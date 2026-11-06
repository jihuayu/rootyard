# Sandbox runner

The sandbox service runs commands in Bubblewrap user, PID, mount and network namespaces. Every job gets an independent native workspace snapshot. Only the job's bounded stdout and stderr files are exposed through authenticated HTTP routes.

`ROOTYARD_SANDBOX_MODE=cgroup` is required for production execution. Set `ROOTYARD_SANDBOX_CGROUP_ROOT` to a delegated cgroup v2 directory with enabled CPU, memory and PIDs controllers. The runner creates a job cgroup, sets `memory.max` to 512 MiB, disables swap, sets `pids.max` to 64 and `cpu.max` to 50,000/100,000. User code waits behind a start gate until the cgroup is attached. The writable workspace is a 256 MiB private tmpfs; `/tmp` is a 64 MiB private tmpfs. The baseline is read-only. A missing controller or denied cgroup write fails closed.

`ROOTYARD_SANDBOX_MODE=dev` runs the same real Bubblewrap isolation, cancellation and timeout flow for local testing. The job workspace is a private host directory. CPU, address-space, individual-file, file-descriptor and per-UID process limits apply, but aggregate process memory and disk usage are not enforced. Do not expose development mode to untrusted production jobs. The current development test runs two jobs, cancellation and timeout through the native HTTP service.

Jobs whose service process crashes are marked failed on startup. Bubblewrap's `--die-with-parent` terminates its namespace when the service exits. Each retry creates a new job ID. CI run claim/report linkage, interactive terminal sessions and artifact export remain to be integrated with the CI runner adapter.
