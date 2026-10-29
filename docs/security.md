# Security model, operations and rollback

This document describes what the toolkit actually enforces, what it does **not**
enforce, and how to undo the Phase 1 changes safely.

Everything marked **UNVERIFIED** was not executed in the environment where this
work was done (no PHP runtime with dependencies, no Docker daemon). Those items
are limitations, not claims.

---

## 1. Trust boundaries

```
browser ──HTTPS──▶ API (Laravel)  ──HMAC-signed job──▶ Runner ──docker API──▶ one-shot scanner container
                      │                                   │                        │
                      │                                   │                        └─ can reach the target
                      └─ PostgreSQL / Redis               └─ no DB, no Redis, no queue,
                         (no published ports)               no shell, no user input in argv
```

| Component | Trusted with | Explicitly *not* trusted with |
|---|---|---|
| Browser | nothing | authorization decisions (all enforced server-side) |
| API | issuing jobs, approvals, audit | starting processes; it has no Docker client at all |
| Runner | starting containers | database, Redis, the API's secrets, arbitrary commands |
| Scanner container | talking to one approved target | network reach to API/DB/Redis, host filesystem, privileges |
| AI provider | ordering tools inside an approved plan | widening scope, approving, adding tools (refused and audited) |

**Trusted code:** the Runner is treated as trusted. It is not a sandbox against
a compromised Runner — see §7.

---

## 2. Target authorization (SEC-02)

Deny by default. A target is scannable only if an operator listed it.

Enforced at **three** boundaries with the same rules:

1. `POST /projects/{id}/scan` → `ProjectService::initiateScan`
2. the queue worker, per scanner → `ScannerExecutor`
3. the Runner, immediately before `docker run` → `runner/src/policy.mjs`

Implementation: `backend/app/Security/Target/` (PHP) and `runner/src/policy.mjs`
(JS). The two are kept in sync by shared test tables.

### What is refused

| Category | Examples | Permittable by lab exception |
|---|---|---|
| Loopback | `127.0.0.1`, `::1`, `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `::ffff:127.0.0.1`, `64:ff9b::7f00:1` | yes, host + port scoped |
| Private | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | yes, host + port scoped |
| Link-local | `169.254/16`, `fe80::/10` | yes (except metadata, below) |
| CGNAT | `100.64/10` | yes |
| Reserved | `192.0.2/24`, `2001:db8::/32`, `2002::/16` | yes |
| Multicast / unspecified | `224/4`, `0.0.0.0`, `::` | **no** |
| Cloud metadata | `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254` | **never** |

Additional rules:

* **Split answers are refused.** A name resolving to both a public and a private
  address is rejected outright rather than half-trusted.
* **Every answer must be acceptable.** One bad address in a DNS answer refuses
  the whole target.
* **DNS pinning.** The addresses seen at approval time are stored on the scan.
  If the name later resolves elsewhere, the scan fails with `address_changed`.
* **Redirects are never followed** by the in-process client, and the Runner
  itself performs no outbound HTTP at all (it only starts containers).
* **Connection pinning.** `SafeHttpClient::guarded()` validates at *send* time
  and then injects `CURLOPT_RESOLVE` so the transport connects to the address it
  just approved, instead of resolving the name a second time.
* **Fail closed.** Any exception inside policy evaluation becomes `policy_error`,
  which is a denial.

### Lab exceptions

Deliberately narrow, enforced at construction (`PolicyConfig::fromArray` throws
otherwise):

* one exact host, no wildcards, no CIDR;
* at least one explicit port; the exception covers **only** those ports;
* mandatory future `expires_at`;
* no subdomain inheritance;
* cannot name a metadata address (checked before exception evaluation);
* every add/remove is audited (`scope.lab_exception_added` /
  `scope.lab_exception_revoked`).

Config form (`SCAN_LAB_EXCEPTIONS`):

```json
[{"host":"127.0.0.1","ports":[8080],"expires_at":"2026-12-31T00:00:00Z","note":"local lab"}]
```

---

## 3. Approval (SEC-03)

An active scan cannot start without a human decision.

* `ScanPlan` derives intrusiveness from the registry, so a tampered plan JSON
  cannot downgrade an active tool to passive.
* Any active tool ⇒ the scan is created in `awaiting_approval` and **nothing is
  queued**.
* Approval is a `ScanApproval` row bound to a fingerprint over
  host + ports + tool set + options.
* Granting requires `ApprovalController::approve` (authenticated, ownership
  checked). `ApprovalService::grant()` has no other caller — the AI planner and
  the worker cannot reach it.
* TTL: `SCAN_APPROVAL_TTL_MINUTES` (default 120) from the moment of grant; the
  *request* expires earlier if never actioned
  (`SCAN_APPROVAL_REQUEST_TTL_MINUTES`, default 1440).
* **Re-verified inside the worker**, not at dispatch time. Expired, mismatched,
  missing or already-consumed approvals fail the scan with `approval_expired`.
* **Single use.** `consume()` is a compare-and-set; the second consumer fails.
  A retry cannot replay a consumed consent.
* Rejecting a request marks the approval rejected and the scan terminal.

---

## 4. Scanner execution and outcomes (REL-02)

The API never builds a command line. It sends a tool **name**; the Runner owns
argv construction from its own registry.

Container flags applied to every job (`runner/src/executor.mjs`):

```
--rm --network <dedicated> --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m
--cap-drop ALL --security-opt no-new-privileges
--pids-limit N --memory Nm --memory-swap Nm --cpus N --user 65534:65534
--log-driver none
```

There is no `--privileged`, no host network, no Docker socket inside the scanner,
and the only bind mount is a read-only wordlist directory chosen by the operator.

### Outcome vocabulary

`completed` · `failed` · `timed_out` · `unavailable` · `cancelled` ·
`invalid_output` · `blocked` · `skipped`

* exit 0 → `completed`
* exit 126/127 → `unavailable` (`tool_not_installed`)
* docker binary missing → `unavailable` (`docker_binary_missing`)
* other non-zero → `failed` (exit code and stderr preserved)
* timeout → container killed, `timed_out`
* explicit cancel → `cancelled`
* unparseable stdout → `invalid_output`

A scan is `Failed` only when **every** scanner was inconclusive; otherwise it is
`Completed` with `degraded = true` and reason `partial`. A silent scanner never
becomes a clean scan.

`ScanResultCollection` holds findings only — it carries no notion of success, so
an empty list cannot be read as "no vulnerabilities".

---

## 5. Infrastructure hardening (SEC-04 / REL-01)

| Item | Enforcement |
|---|---|
| Database | `DB_PASSWORD` required by compose (`:?`); **no published port** |
| Redis | `REDIS_PASSWORD` required; `requirepass` set; **no published port** |
| App | binds `127.0.0.1:8000`; runs as `www-data`; `cap_drop: ALL`; `no-new-privileges`; no Docker CLI |
| Runner | no ports published; reachable only on `internal-network`; `cap_drop: ALL`; no DB/Redis |
| Queue | `--tries=1 --timeout=90`; `retry_after=120` > job timeout, so no double delivery |
| Reaper | `scans:reap` every minute closes scans whose worker died |

Queue timeout relationship (verified by inspection, not execution):

```
RunScanJob::$timeout      = 90 s
config('queue.redis.retry_after') = 120 s   →  retry_after > timeout  ✅
ScanOrchestrator max_duration     = 900 s   →  bounded by the per-scan deadline
heartbeat_stale_seconds           = 300 s   →  reaper threshold
```

The per-scan deadline (900 s) exceeds the job timeout (90 s). That is
intentional: the job timeout is a backstop, and the orchestrator's own deadline
stops a scan cleanly with `scan_timeout` before the worker is killed. A scan that
nonetheless outlives the worker is closed by the reaper as `worker_lost`, never
left `running`.

### Docker socket proxy

`tecnativa/docker-socket-proxy` with `CONTAINERS=1 IMAGES=1 POST=1`, and
`EXEC=0 VOLUMES=0 SECRETS=0 SWARM=0 NODES=0 SERVICES=0 SYSTEM=0`.

Effective capability: create/start/kill/stop containers and read images.
It **cannot** `exec` into a container, mount a volume, read secrets, or touch
swarm objects.

#### What the proxy actually enforces (read from its source)

Taken from `tecnativa/docker-socket-proxy` **v0.2.0**, `haproxy.cfg` — the tag
`0.2` in compose resolves to `0.2.x` (`{{major}}.{{minor}}`).

```haproxy
http-request deny unless METH_GET || { env(POST) -m bool }
http-request allow if { path,url_dec -m reg -i ^(/v[\d\.]+)?/containers } { env(CONTAINERS) -m bool }
...
http-request deny
```

Three consequences, in order of severity:

1. **No request body is ever inspected.** There is no `payload()` fetch in the
   template, so `POST /containers/create` accepts any `HostConfig`: privileged,
   host PID/network namespace, `/` bind-mounted read-write, `CapAdd: [SYS_ADMIN]`,
   or mounting `/var/run/docker.sock`. → **root-equivalent**.
2. **`^/containers` is an unconstrained prefix match**, not just "create". With
   `CONTAINERS=1` + `POST=1` the Runner can also `kill`, `stop`, `restart`,
   `pause` and `update` **any container on the host** — `app`, `db`, `redis`,
   the scheduler, or this proxy. That is a denial-of-service primitive against
   the whole stack, and it is not fixable by path filtering alone because
   container IDs are not prefix-constrained.
3. Everything not listed is denied by the final rule, and a `GET` is still
   subject to the section rules (so `/secrets`, `/volumes`, `/exec` remain
   closed for reads too — `VOLUMES=0` blocks the *volume endpoint*, not a bind
   mount in a create body).

**Verdict: the proxy is a least-privilege boundary for everything except the
Runner. It is not a sandbox against the Runner.** Treat Runner compromise as
host compromise. Real containment needs one of:

| Option | Effect | Cost |
|---|---|---|
| Rootless Docker / userns-remap for the Runner's daemon | Namespaced escapes stop being root | Medium; changes image ownership |
| Docker authorization plugin (e.g. OPA) validating `HostConfig` | Rejects privileged/bind/host-ns bodies | Medium; new component |
| Dedicated dockerd for scanners only (no db/redis/app on it) | Bounds "kill any container" to scanner containers | Low concept, needs a second daemon |
| Accept the risk | Keep the Runner minimal and monitored | Documented above |

The current build takes the last option **and says so**; it does not claim
containment it cannot provide.

### Networks

* `edge-network` — frontend ↔ API (published ports live here).
* `internal-network` — API ↔ PostgreSQL/Redis/Runner (nothing published).
* `scanner-net` — one-shot scanner containers. `enable_icc=false` so scanners
  cannot talk to each other. It is **not** `internal: true`, because an
  authorised public target must be reachable; isolation comes from what is *not*
  on that network (no API, no database, no Redis, no proxy).
* `scanner-control` — Runner ↔ docker-proxy only, `internal: true`.

**Recommendation for hosts that only scan local labs:** make `scanner-net` an
`internal: true` network and attach a validating egress proxy, or apply host
firewall rules restricting the `scanner-net` bridge to the allowlisted
destinations. Without that, a scanner container can reach any host the daemon
host can reach — the *policy* still refuses unauthorized targets before a
container starts, but there is no packet-level guarantee.

---

## 6. Audit trail (AUD-01)

`audit_events` is append-only from the application's perspective. Recorded:
auth success/failure, invalid tokens, authorization denials, scope decisions,
lab-exception changes, approval request/grant/reject/expire/consume/mismatch,
scan create/start/cancel/complete/fail/reap, and report generation/access.

`sanitise()` redacts by key name (`password`, `token`, `secret`,
`authorization`, `api_key`, …), truncates strings to 500 chars and the whole
context to 4000 bytes. Logging failures never break the request they describe,
but they are reported to the application log — a silent audit gap is itself a
finding.

---

## 7. Known limitations (not verified in this environment)

| # | Limitation | Impact |
|---|---|---|
| 1 | No Docker daemon available | Container isolation flags are asserted in argv but **never executed**. UNVERIFIED. |
| 2 | No Composer vendor tree (`composer.lock` is a 0-package stub) | Laravel/PHPUnit suite, migrations and route registration are **unexecuted**. |
| 3 | `CURLOPT_RESOLVE` pinning | **Runtime-verified** against local fixtures (17 assertions, `backend/tests/Standalone/http_pinning_test.php`). Not yet exercised through Laravel's Guzzle transport (no vendor tree). |
| 4 | Docker socket proxy | Filters paths only; no body inspection, and `^/containers` is unconstrained. A compromised Runner is root-equivalent and can kill any container. See §5. |
| 5 | Scanner image not built | Tool presence (`unavailable` behaviour) is simulated in tests, not observed. |
| 6 | Replay window, not replay-proof | A request captured inside the 300 s window can be replayed. Mitigation is transport confidentiality on the internal network. |
| 7 | No nonce store | Deliberate: a shared clock window is simpler than distributed nonce state. |
| 8 | Secret rotation | Rotating `RUNNER_SECRET` requires restarting both sides; there is no dual-secret window. |
| 9 | In-process active scanners | `SqlInjectionAssessmentScanner` / `XssAssessmentScanner` send fixed payloads from the API process (behind approval). Pre-existing, unchanged, not extended. |
| 10 | Parser behaviour | Untested against real tool output for most tools; unparseable output is reported as `invalid_output`, not as clean. |

---

## 8. Recommended operator hardening (not implemented)

1. **Rootless Docker** or user-namespace remapping for the Runner's daemon.
2. Egress firewall on `scanner-net` limited to approved destinations.
3. TLS between the API and the Runner (the HMAC protects integrity, not
   confidentiality).
4. A committed `composer.lock` and `npm ci` in the frontend image.
5. `APP_DEBUG=false`, `APP_ENV=production`, and a real `APP_KEY` on day one.
6. Ship audit events to append-only external storage (uncomment `retention_days`
   only if you are allowed to delete).

---

## 8a. Verification harnesses

```bash
# Policy, lifecycle, approvals and the Runner contract (no dependencies).
php backend/tests/Standalone/target_policy_test.php
php backend/tests/Standalone/scan_lifecycle_test.php
php backend/tests/Standalone/approval_test.php
php backend/tests/Standalone/runner_contract_test.php

# Routes, imports and constructor dependency resolution (static analysis).
php backend/tests/Standalone/container_wiring_test.php

# Real TCP: proves CURLOPT_RESOLVE pinning against local fixtures.
node backend/tests/Standalone/http_pinning.mjs

# Runner (Node, no dependencies).
cd runner && npx vitest run
```

`container_wiring_test.php` is static analysis, not a Laravel boot: it proves
that every route points at a defined public method, every `use App\...` import
resolves, and every constructor argument is either a real class or a bound
interface. It cannot prove middleware ordering or runtime binding behaviour.

`http_pinning_test.php` skips cleanly (exit 0) when it is run without its
fixtures, so `run_all.sh` stays usable.

## 9. Rollback

Nothing here has been committed. Roll back in this order.

### 9.1 Code

```bash
# See what changed
git status --porcelain
git diff --stat

# Discard everything (only if you have no other work in the tree)
git checkout -- .
git clean -fd backend/app backend/tests backend/database runner docs
```

Targeted rollback of one objective, without touching the rest:

```bash
git checkout -- backend/app/Security/Http/SafeHttpClient.php   # undo pinning change
git checkout -- backend/app/Http/Requests/StoreProjectRequest.php
rm -f backend/app/Security/Scan/JobId.php                       # → restore the
#   inline jobId() in RunnerClient if you also revert that file
```

### 9.2 Configuration

* `docker-compose.yml` and `Dockerfile` at `HEAD` had a published Postgres/Redis
  port and a `--network=host` scanner. **Do not restore them**; they are the
  vulnerability this phase removes.
* Compare with the previous `.env`:

```bash
diff <(git show HEAD:.env.example) .env.example
```

* New required variables: `DB_PASSWORD`, `REDIS_PASSWORD`, `RUNNER_SECRET`
  (32+ chars). Compose refuses to start without them — that is intentional.

### 9.3 Migrations

Four migrations were added:

```
2026_01_01_000010_harden_scans_table
2026_01_01_000020_create_scan_approvals_table
2026_01_01_000030_create_scan_scanner_runs_table
2026_01_01_000040_create_audit_events_table
```

`000010` is **destructive on rollback** in one direction: it rewrites
`scans.status` values (`pending` → `queued`). Its `down()` maps them back.

```bash
php artisan migrate:rollback --step=4   # only on a database you own
```

**Before rolling back, dump the audit and approvals tables.** Losing
`audit_events` destroys the evidence trail:

```bash
pg_dump -t audit_events -t scan_approvals -t scan_scanner_runs "$DB_DATABASE" > audit_backup.sql
```

Never roll back by reintroducing `shell_exec('docker run --network=host')`.

### 9.4 Disabling the Runner without reverting code

Set `RUNNER_ENABLED=false` (or clear `RUNNER_SECRET`). Docker-backed scanners
then report `unavailable` and scans fail honestly instead of silently returning
nothing. The API keeps working for in-process scanners.

---

## 10. Operator checklist before first use

- [ ] `APP_ENV=production`, `APP_DEBUG=false`, `APP_KEY` generated
- [ ] `ALLOW_REGISTRATION=false` unless you intend open signup
- [ ] `SCAN_ALLOWLIST` names the hosts you are authorised to test
- [ ] Lab exceptions are host+port scoped and expire
- [ ] `RUNNER_SECRET` is 32+ random chars (`openssl rand -hex 32`)
- [ ] `DB_PASSWORD` / `REDIS_PASSWORD` set, no default credentials
- [ ] Postgres and Redis have **no published ports**
- [ ] `php artisan migrate` run, `scans:reap` scheduled
- [ ] Backups configured for `audit_events`
- [ ] You have written authorization for every allowlisted target
