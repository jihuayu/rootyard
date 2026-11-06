# Reverse source lease cancellation review — b3838d9

Status: **pass for PostgreSQL lease-loss cancellation of reverse Git work; residual process-containment risk is documented below.**

Reviewed `/workspace/rootyard-workspace-ci` commit `b3838d98baf60c25791e0e6fb7de65ea293d9caf` and native Rust service binary `/workspace/rootyard-workspace/target/debug/rootyard`, SHA-256 `61d0b7e20f7be308a50ad4578d52e65456649da9493cdc1239e5974af470ceeb`.

The reverse import keeps the local read gate and writer mutex around synchronous source work. A scoped watcher checks the shared PG lease every 50 ms, and reverse Git’s watchdog kills the command process group on lease loss, waits for group quiescence, reaps the leader, and only then returns. The child also inherits the data-volume `.rootyard.lock`; this protects ordinary descendants from allowing another Rootyard writer to open the same volume after a server crash. The lease-loss path returns 503 before retry succeeds.

Independent native validation (real Rootyard process, PostgreSQL, and Git) passed:

```sh
source /workspace/shared/rootyard-env.sh
cd /workspace/rootyard-workspace-ci
PYTHONPATH=/workspace/rootyard-workspace-ci/tests:/workspace/rootyard-workspace-ci \
python3 -c 'import os, unittest; from tests.test_namespace_service import NamespaceServiceTest; os.chdir("/workspace/rootyard-workspace"); suite=unittest.defaultTestLoader.loadTestsFromTestCase(NamespaceServiceTest); result=unittest.TextTestRunner(verbosity=2).run(suite); raise SystemExit(not result.wasSuccessful())'
```

Result: `test_pinned_subdir_view_and_git_bundle` passed (1/1, 16.506s). It terminated the real PostgreSQL reader backend while a wrapper and Git child were active, observed the exclusive advisory-lock waiter proceed, got HTTP 503 within the asserted deadline, confirmed both child PIDs quiesced, and then completed a retry and ChangeSet integration. An initial attempt hit a PostgreSQL migration lock timeout before the test entered the case; the successful rerun was clean.

Residual process-death limit: `PR_SET_PDEATHSIG` applies to the immediate Git process. If the Rootyard parent is SIGKILLed, a descendant that deliberately calls `setsid` and closes the inherited volume-lock FD can outlive both the leader and the volume lock. Normal Git descendants inherit the lock FD, and live lease loss is protected by process-group kill/reap; the native test does not prove survival against a malicious, detached helper after parent death. If that helper is in scope, service-level cgroup/systemd process-tree cleanup is needed. The current Git commands disable hooks and system/global configuration, making such helper execution outside this test’s demonstrated path.
