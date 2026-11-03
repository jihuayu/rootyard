# Rootyard

Phase-one, single-node Git hosting in Rust. PostgreSQL holds users, token digests and repository metadata. **Native bare Git repositories on a durable local volume are authoritative for refs and objects.** Clients create commits locally and use Git Smart HTTP to clone, fetch and push.

This is an early implementation, not a production high-availability service. There is no UI, LFS, virtual filesystem, PostgreSQL refs store, online object-store backend, distributed coordinator, complete push audit/outbox, or automated backup system.

## Requirements

- Linux, Rust stable (edition 2024), Git 2.43 or newer, PostgreSQL 17.
- A durable, private local filesystem for `ROOTYARD_DATA_DIR`; one serving process per directory.
- TLS termination in front of HTTP outside localhost. The app does not terminate TLS.
- PostgreSQL on a trusted private connection or through a local TLS proxy. The driver uses `NoTls`, including when the PostgreSQL URL defaults to `sslmode=prefer`; `sslmode=require` is rejected rather than silently downgraded.

These are baseline requirements, not a claim that every version or storage device has been qualified. See [verification](docs/development.md).

## Local quick start

Start PostgreSQL with a dedicated database and role, then run from this checkout:

```sh
export DATABASE_URL='postgresql://rootyard:YOUR_LOCAL_PASSWORD@127.0.0.1:5432/rootyard'
export ROOTYARD_DATA_DIR="$PWD/data"
export ROOTYARD_BIND='127.0.0.1:8080'
cargo build --locked
./target/debug/rootyard migrate
./target/debug/rootyard create-user alice
./target/debug/rootyard serve
```

`create-user` prints JSON containing a new token and token ID. Save the token in a password manager: it is displayed once and only its digest is stored. Do not paste it into source files, URLs, logs, or shell history. In a second terminal, read it privately and create a repository:

```sh
read -r -s -p 'Token: ' ROOTYARD_TOKEN; echo
export ROOTYARD_TOKEN
# Feed the authorization header via stdin, not a literal shell-history entry.
printf 'header = "Authorization: Bearer %s"\n' "$ROOTYARD_TOKEN" | \
  curl --fail-with-body --config - -H 'Content-Type: application/json' \
  -d '{"name":"demo"}' http://127.0.0.1:8080/api/repos
unset ROOTYARD_TOKEN

git clone http://alice@127.0.0.1:8080/git/alice/demo.git
# Enter the token at Git's password prompt; use a secure credential helper if desired.
cd demo
git switch -c main
printf 'Hello Rootyard\n' > README.md
git add README.md
git -c user.name=Alice -c user.email=alice@example.invalid commit -m 'Initial commit'
git push -u origin main
```

Creating the same repository again is idempotent by owner and name. Names contain 1–63 lowercase ASCII letters, digits, `_` or `-`, beginning with a letter or digit. Do not include `.git` in the API name.

## API and access

- `POST /api/repos`, JSON `{"name":"demo"}`: provision your repository.
- `GET /api/repos`: list up to 1,000 of your repositories, ordered by name; pagination is not implemented.
- `GET /api/repos/alice/demo`: inspect your own repository.
- `/git/alice/demo.git`: authenticated Smart HTTP endpoint, not a browsable directory.
- `GET /health/live`: process liveness; `GET /health/ready`: database reachability and repository-directory presence, not a full integrity scan.

Create returns `201` for a new ready repository, `200` for an existing ready one, or `202` while provisioning remains pending. Startup and a periodic scan resume pending provisioning in batches of at most 64, with persisted attempt counts and a 30-second retry backoff. Inspect the repository state before cloning. `serve` applies migrations automatically before recovery and accepting requests.

Use Bearer tokens for REST, or Basic authentication with username and token as password. Read-only tokens can clone/fetch and read metadata, but cannot create repositories or push. There is no sharing model: users access only their own repositories.

```sh
./target/debug/rootyard create-token alice --read-only
./target/debug/rootyard revoke-token TOKEN_UUID
```

The repository is the security boundary. A reader may obtain historical or unreachable objects; there is no branch-level confidentiality. Non-fast-forward branch pushes are rejected, including force pushes. New repositories use SHA-1 objects and default `HEAD` to `main`. Tags and non-default branch deletion use native Git semantics; deleting the branch named by `HEAD` is denied. Native Git manages ref locking, quarantine and push results. A disconnected push can have an unknown outcome: fetch/check refs before retrying.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | PostgreSQL metadata connection; no built-in TLS |
| `ROOTYARD_DATA_DIR` | `data` | Durable repository volume |
| `ROOTYARD_BIND` | `127.0.0.1:8080` | HTTP listening address |
| `ROOTYARD_GIT` | Git found in `PATH` | Native Git executable |
| `ROOTYARD_MAX_REQUEST_BYTES` | `134217728` | Request stream limit, 128 MiB |
| `ROOTYARD_MAX_OUTPUT_BYTES` | `536870912` | Git output stream limit, 512 MiB |
| `ROOTYARD_MAX_CONCURRENT_GIT` | `8` | Concurrent Git process bound |
| `ROOTYARD_GIT_TIMEOUT_SECONDS` | `120` | Git request deadline |
| `ROOTYARD_GIT_MEMORY_BYTES` | `1073741824` | Per-child address-space resource limit |
| `ROOTYARD_MAX_REPO_BYTES` | `1073741824` | Repository size admission threshold |

Smart HTTP accepts streaming `gzip`/`x-gzip` request bodies; both wire bytes and expanded bytes are bounded by the request limit. Other content encodings are rejected. The Git transfer deadline continues even when a client stops reading. If a timeout, cap or child failure occurs after response headers have been sent, the response stream fails or is truncated; an initial HTTP `200` alone does not mean the Git operation succeeded.

Numeric limits must be positive. Repository size checks are not filesystem quotas; concurrent writes and temporary packs can require extra disk. Use a dedicated filesystem quota and headroom where a hard disk limit is needed. Process limits and stream bounds do not establish a total service RSS bound. See [operations](docs/operations.md).

## Container development

The provided Compose stack is local development only. It publishes HTTP exclusively on `127.0.0.1` and keeps PostgreSQL private to its network. It builds from source using official Rust and Debian images and persists both database and Git data in named volumes.

```sh
# Generate a local hexadecimal password; keep the file outside version control.
umask 077
printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > .env
docker compose up --build -d
docker compose exec rootyard rootyard create-user alice
```

Never run `docker compose down -v` unless you intend to destroy the development data. Do not expose this development stack directly to the internet.

## Further reading

- [Architecture and phase-one decisions](docs/architecture.md)
- [Operations, recovery and coordinated backup/restore](docs/operations.md)
- [Development and verification](docs/development.md)
- [Verification record and remaining limits](docs/verification.md)

Licensed under Apache-2.0.

## Phase-two reliability increment

GitFS writes now retain durable operation evidence and post-receive receipts, with explicit unknown/recovering states. PostgreSQL atomically stores audit evidence and durable events; fenced local consumers maintain audit and ref projections. This does not replace Git refs with PostgreSQL refs or enable HA. See [reliability contract and operations](docs/reliability.md) and [phase-two verification](docs/phase-two-verification.md).

Run the added tests against an isolated test database:

```sh
export ROOTYARD_TEST_DATABASE_URL=postgresql://localhost/rootyard_test
cargo test --test outbox -- --ignored
python3 tests/reliability.py --binary target/debug/rootyard --report test-results/reliability.json
```
