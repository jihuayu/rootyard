# Background operation diagnostics — partial issue #80

Detached webhook, workspace capture, workspace remote GC, durable dispatch and storage maintenance work now carry server-generated operation IDs and fixed worker/phase labels. HTTP request IDs/routes do not flow into worker scopes. Raw external error text is replaced with fixed categories. Persisted attempt/generation values are attached where available.

The [native report](round5-worker-diagnostics-evidence/native.json) passes all ten recorded steps against binary `6795ee27961ce0f0cf510578fb542daefe209de3e313aa967a872a3a7fbb5252`, source `ee80cd16db6806e9648db0843bc1b98e65491745`, compiled inputs `32a8f18b4a4192bfa7d6bc2677d9ed680309e921fafd6da2d04a6e65c56e04d7`; the [fresh build receipt](round5-worker-diagnostics-evidence/build.json) binds those bytes. All-target Clippy passed on this candidate.

A real PostgreSQL statement timeout (57014) is induced in the storage maintenance scheduler; a separate HTTP trigger raises 23503 with synthetic sensitive text. The test verifies operation/request isolation, fixed error response, log redaction and successful HTTP operation after trigger cleanup. No SQL error classification is mocked.

This is not complete worker fault acceptance. Native faults were not injected into the other wrapped workers. Session GC, sharding, startup journal/provisioning reconciliation, metrics and backup workers remain outside this operation scope. No physical disk or machine failure was exercised. Issue #80 remains open.
