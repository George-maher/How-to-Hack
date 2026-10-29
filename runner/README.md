# Runner

The Runner is the only component that may start a scanner container. It is a
separate service from the Laravel API, with no database, no Redis, and no queue.

```
Laravel API ──(HMAC-signed HTTP, internal network)──▶ Runner ──(docker CLI)──▶ one-shot scanner container
```

## Why a separate service

The API process previously did `shell_exec('docker run --network=host ...')`
inline. That gives the web application root-equivalent power over the host and
puts a shell string on the path between user input and process execution. The
Runner replaces it with a narrow job interface:

* fixed registry of 18 tools, each with a fixed image and a fixed argv template;
* the request selects a tool *by name* — it cannot supply a binary, an image, a
  mount, an environment variable or an extra CLI flag;
* argv arrays only, never a shell string;
* the Runner re-evaluates the target policy independently, immediately before
  execution, so a stale approval cannot be replayed;
* jobs are bounded by timeout, memory, CPUs, PIDs, output size and concurrency.

**Implementation choice:** Node.js. The repository already ships Node for the
frontend, so this adds no new toolchain; `child_process.spawn` takes an argv
array (no shell); and the service has **zero runtime dependencies**. A PHP
implementation was rejected because no PHP runtime was available to verify it.

## Endpoints

All endpoints except `/health` require HMAC authentication.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, version, active job count |
| GET | `/tools` | Tool catalogue with intrusiveness |
| POST | `/jobs` | Run one tool (blocking, bounded) |
| POST | `/jobs/:job_id/cancel` | Stop a running job |

### Authentication

```
x-runner-timestamp: <unix seconds>
x-runner-signature: hex(hmac_sha256(RUNNER_SECRET, `${timestamp}.${rawBody}`))
```

Timestamps outside `RUNNER_CLOCK_SKEW_SECONDS` (default 300) are rejected, so a
captured request cannot be replayed. The signature covers the raw body, so the
target cannot be altered in flight.

### `POST /jobs`

```json
{
  "job_id": "1-nmap-1-a1b2c3d4",
  "scan_id": 1,
  "tool": "nmap",
  "target": { "host": "app.example.com", "url": "https://app.example.com", "scheme": "https", "port": 443 },
  "scope": { "allowlist": [ { "host": "app.example.com", "ports": [443] } ], "lab_exceptions": [] },
  "pinned_ips": ["93.184.216.34"],
  "limits": { "timeout_ms": 120000 },
  "approval": { "fingerprint": "…", "approved_at": null }
}
```

Unknown keys are rejected with `422`. Response:

```json
{
  "job_id": "…", "tool": "nmap",
  "outcome": "completed | failed | timed_out | unavailable | cancelled",
  "exit_code": 0, "duration_ms": 1204,
  "stdout": "[{\"port\":443,…}]",
  "stderr": "", "truncated": false, "diagnostic": null,
  "scope": { "allowed": true, "reason": "allowed", "host": "app.example.com" },
  "runner_version": "1.0.0"
}
```

Status codes: `401` unauthenticated · `403` target refused (`reason` explains) ·
`409` same job already running · `413` body too large · `422` schema · `429`
runner busy · `500` internal.

`outcome` describes the *process*, never the findings. Parsing happens in the
API, which maps an unparseable payload to `invalid_output` rather than to
"no findings".

## Execution hardening

Each job runs:

```
docker run --rm --name hth-<job> \
  --network <dedicated scanner network> --read-only \
  --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit N --memory Nm --cpus N --user 65534:65534 \
  --log-driver none --mount <wordlists>:/wordlists:ro <image> <tool> <args…>
```

There is no `--privileged`, no host network, no Docker socket inside the
scanner container and no host mounts beyond a read-only wordlist directory.

## Failure behaviour

* Docker binary missing → `unavailable` / `docker_binary_missing`.
* Tool missing from the image → `unavailable` / `tool_not_installed` (exit 127).
* Non-zero exit → `failed` with the exit code and a stderr excerpt.
* Timeout → container killed (`docker kill`), outcome `timed_out`.
* Scope refusal → `403`, and the job is *not* executed.
* Duplicate `job_id` → the cached result is replayed; the tool does not run twice.

There is no silent fallback anywhere: every path produces an explicit outcome.

## Configuration

| Variable | Required | Default | Notes |
|---|---|---|---|
| `RUNNER_SECRET` | yes | — | ≥32 chars; startup aborts otherwise |
| `RUNNER_PORT` | no | 8080 | |
| `RUNNER_SCANNER_NETWORK` | no | `scanner-net` | must not be host/bridge/default |
| `RUNNER_CONTAINER_USER` | no | `65534:65534` | must be non-root |
| `RUNNER_IMAGE` | no | `howtohack/scanner:latest` | |
| `RUNNER_MAX_CONCURRENT` | no | 2 | |
| `RUNNER_MAX_TIMEOUT_MS` | no | 600000 | ceiling for a single job |
| `RUNNER_MAX_OUTPUT_BYTES` | no | 262144 | per stream |
| `DOCKER_HOST` | no | — | point at the filtered socket proxy |

## Tests

```bash
cd runner
npm install     # dev dependency: vitest
npm test
```

The suite covers policy evaluation (IPv4 alternate notations, IPv6 including
mapped/NAT64/ULA/link-local, metadata endpoints, CIDR, DNS rebinding, lab
exceptions), authentication (signature, skew, tampering), schema strictness,
argv construction, container isolation flags, timeouts, output caps,
cancellation, idempotency and cross-language registry parity.

Container execution itself is covered with an injected fake `docker` process:
this suite does **not** prove the isolation flags work against a real Docker
daemon, and it does not start any container.
