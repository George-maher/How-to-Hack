# Phase 1 — Security & Reliability: implementation report

Branch `arena/a4476df2-how-to-hack`, working tree only (**nothing committed**).
Baseline commit: `8d1e9f83109abaa87edf22f8a4e92800359101d7`.

Every number below was produced by running the command shown. Anything that
could not be executed in this environment is marked **BLOCKED**, not "passing".

---

## 1. Baseline (Phase 0 findings)

The repository advertised considerably more than it implemented. Verified by
reading every file and by executing what could be executed:

| Claimed | Reality at baseline |
|---|---|
| Dedicated Runner service | Did not exist. Docker scanners ran `shell_exec('docker run … --network=host …')` **inside Laravel**. |
| Python analysis service | Does not exist (0 Python files in the repo). |
| WebSocket live updates | Does not exist. The UI polls every 5 s. |
| Scanner registry | Existed as a class list; argv was built as a shell string per scanner. |
| Report downloads | Used `<a download href>`, which cannot send the bearer token → always 401. |
| Auth | Bearer token existed; several endpoints were unauthenticated, listings returned other users' rows. |
| Target control | No allowlist, no SSRF protection. Private/loopback targets scannable. |
| Approval | Did not exist. |
| Failure semantics | `catch {}` around scanner execution produced an empty result set presented as a clean scan. |
| Scanner image | Ran `unzip` without installing it; 4 registered tools were never installed. |

Environment: no PHP CLI, no Composer, no Docker daemon, no PostgreSQL, no
Redis, `composer.lock` is a 0-package stub, no `vendor/`, no `.env`.
All PHP execution therefore used a real PHP 8.2 runtime via `@php-wasm/node`.

---

## 2. Work done in this continuation

Continuing from the existing tree — not a restart.

### 2.1 Genuine defects found and fixed

| # | Defect | Evidence | Fix |
|---|---|---|---|
| 1 | `RunnerClient::jobId()` **did not exist** but was called from 3 places | `grep -rn "RunnerClient::jobId"` → 3 hits, 0 definitions | Extracted `App\Security\Scan\JobId` + delegating `RunnerClient::jobId()` |
| 2 | The PHP client and the Runner **could never talk**: client sent nested `target/limits/approval` and `null` optionals; `validate.mjs` required a flat `timeout_ms` / `approval_fingerprint` and rejected `null` | Schema comparison + `validateJob` unit tests | Rewrote `validate.mjs` to the documented nested contract, accepting `null` only for genuinely optional fields |
| 3 | `BaseDockerScanner` sent the *original* URL with the *normalized* host → 422 `invalid_job` for any target written in alternate notation | `target.url` / `target.host` agreement check | Added `App\Security\Target\TargetUrl::rebuild()`; scanner now sends a URL built around the approved host |
| 4 | `SafeHttpClient::guarded()` validated at send time but **did not pin the connection** — the transport re-resolved the name (rebinding window) | Code inspection | Middleware now injects `CURLOPT_RESOLVE` for the approved address and forces `allow_redirects=false` at transport level |
| 5 | Server left a job wedged in `in_progress` if the executor threw → every retry 409 forever | Server path review | `try/catch` around `executor.run`, job released, 500 returned |
| 6 | Job-cache eviction could evict a **running** entry, allowing the same work twice | Server path review | Eviction only considers finished entries |
| 7 | `security.runner.enabled` and `connect_timeout_seconds` were configured but never read | `grep` → 0 uses | Wired into `RunnerClient::isConfigured()` / `send()` |
| 8 | `security.runner.url` defaulted to `:8081`, compose/.env use `:8080` | Config vs compose | Default corrected |
| 9 | Dead `TargetScopeService::isWellFormedUrl()` advertised a guard nothing called | `grep` → 0 callers | Removed (a fake guard is worse than none) |
| 10 | Project URLs accepted any scheme (`ftp://`, credentials in URL) at creation | Request rules | `starts_with:http://,https://` added to store/update |
| 11 | `LabExceptionStore::add()` had an empty `if` branch | Code inspection | Removed; audit constants added |

### 2.2 Test suites rewritten

The four suites that targeted the pre-redesign API were rewritten against the
current contracts:

| File | Tests | What it now covers |
|---|---|---|
| `runner/test/executor.test.mjs` | 36 | isolation flags, argv/shell safety, all five outcomes, output caps, timeout→kill, cancellation, cleanup, no secret in child env |
| `runner/test/server.test.mjs` | 46 | all four routes, HMAC, tamper, replay window, strict schema, scope revalidation per job, duplicates, 429, cancellation isolation, error hygiene |
| `runner/test/security.test.mjs` | 52 | signature integrity, constant-time compare, flag-injection, arbitrary-execution refusal, independent authorization, config refusal, secret hygiene |
| `runner/test/registry-parity.test.mjs` | 21 | registry integrity, PHP↔JS name/intrusiveness parity, real API payload acceptance, scanner-image contract |

Plus `validate.test.mjs` (23) updated where it encoded the obsolete flat schema,
and a new PHP harness `backend/tests/Standalone/runner_contract_test.php` (50).

---

## 3. Test results (exact)

### Runner — `cd runner && npx vitest run`

```
✓ test/server.test.mjs            (46 tests)
✓ test/security.test.mjs          (52 tests)
✓ test/executor.test.mjs          (36 tests)
✓ test/registry-parity.test.mjs   (21 tests)
✓ test/policy.test.mjs            (49 tests)
✓ test/validate.test.mjs          (23 tests)
✓ test/auth.test.mjs              (11 tests)

Test Files  7 passed (7)
Tests       238 passed (238)
```

### Backend standalone harnesses — real PHP 8.2 (`@php-wasm/node`)

| Harness | Result |
|---|---|
| `tests/Standalone/target_policy_test.php` | **83 passed, 0 failed** |
| `tests/Standalone/scan_lifecycle_test.php` | **38 passed, 0 failed** |
| `tests/Standalone/approval_test.php` | **52 passed, 0 failed** |
| `tests/Standalone/runner_contract_test.php` | **50 passed, 0 failed** |
| **Total** | **223 passed, 0 failed** |

### PHP syntax — all 188 files

```
PHP 8.2 parse: 188/188 OK
```

(`token_get_all` with `TOKEN_PARSE` over `app/`, `database/`, `routes/`,
`config/`, `tests/`, `bootstrap/`.)

### Frontend — `cd frontend`

| Command | Result |
|---|---|
| `npx tsc -b` | exit 0, no diagnostics |
| `npm run build` | exit 0 — `dist/assets/index-*.js 268.80 kB` |
| `npx eslint src` | exit 0, 0 problems |

### BLOCKED (cannot execute here)

| Check | Why |
|---|---|
| `php artisan test` / PHPUnit (`tests/Feature/*`, `tests/Unit/*`) | `composer.lock` is a stub; `composer install` needs Packagist, which is unreachable; no `vendor/`. |
| Migrations against PostgreSQL | No PostgreSQL, no `vendor/`. |
| Laravel boot, route registration, DI resolution | Same. |
| Docker: image build, container isolation, network enforcement | No Docker daemon. |
| Scanner image tool availability | Image never built. |

Each of these is a **limitation**, not a pass.

---

## 4. Security review of the implemented design

| # | Area | Verdict | Evidence / limitation |
|---|---|---|---|
| 1 | DNS pinning | **PASS (code)**, live connect UNVERIFIED | `SafeHttpClient` injects `CURLOPT_RESOLVE` at send time; policy records `resolved_ips` on the scan and refuses `address_changed`. |
| 2 | Redirects | **PASS** | `allow_redirects=false` in client options and re-forced in middleware. The Runner performs no outbound HTTP at all (asserted by a test that scans `src/`). |
| 3 | IPv6 wrapping | **PASS** | Mapped (`::ffff:7f00:1`), NAT64 (`64:ff9b::7f00:1`), ULA, link-local, `fd00:ec2::254` all classified and refused; 15 shared cases across PHP and JS. |
| 4 | Lab exceptions | **PASS** | Host+port scoped, mandatory expiry, no CIDR, no wildcard, no subdomains; config validation throws at boot otherwise. |
| 5 | HMAC | **PASS**, replay bounded not eliminated | Signature over `timestamp.body`; ±300 s window; `timingSafeEqual`. No nonce store — documented. |
| 6 | Container isolation | **BLOCKED** | Flags asserted in argv (36 tests) but never executed against a real daemon. |
| 7 | Docker socket proxy | **PARTIAL** | Only the Runner can reach the daemon; `EXEC`/`VOLUMES`/`SECRETS`/`SWARM` blocked. The proxy filters endpoints, not bodies — a compromised Runner could still create a privileged container. Documented. |
| 8 | Cancellation / orphan recovery | **PASS (code)** | `cancel()` returns true only on HTTP 202; unconfirmed stays `cancel_requested`; reaper closes scans whose heartbeat is stale as `worker_lost`. |
| 9 | Approval binding | **PASS** | Fingerprint over host+ports+tools+options; re-verified in the worker; single-use via compare-and-set `consume()`. |
| 10 | Failure semantics | **PASS** | Enum outcomes; all-inconclusive ⇒ `Failed`; partial ⇒ `Completed` + `degraded`; `ScanResultCollection` carries findings only. |

---

## 5. Acceptance matrix (11 criteria)

| # | Criterion | Status | Evidence | Limitation |
|---|---|---|---|---|
| 1 | Baseline & architecture verified | **PASS** | 13-section audit; Python/WebSocket/Runner claims falsified; `docs/security.md` §1 | — |
| 2 | Auth & resource access (SEC-01) | **PASS (code)** | Bearer token stored as SHA-256, constant-time compare; every controller action calls `authorize()`; listings scoped in SQL; registration off by default; login throttled 5/min per email+IP | Feature tests BLOCKED (no vendor) |
| 3 | Allowlist & SSRF (SEC-02) | **PASS** | `app/Security/Target/` (16 classes) + `runner/src/policy.mjs`; enforced at API, worker and Runner; 83 PHP + 49 JS assertions | — |
| 4 | Scope-bound approval (SEC-03) | **PASS** | `ApprovalService`, `ScanPlan`, `ApprovalController`; 52 approval-harness assertions | UI flow unexecuted in a browser |
| 5 | DB/Redis/Runner hardening (SEC-04) | **PARTIAL** | No published DB/Redis/Runner ports; required passwords; `cap_drop: ALL`; socket proxy | Container flags **BLOCKED**; proxy not body-filtering |
| 6 | Queue lifecycle & recovery (REL-01) | **PASS (code)** | CAS transitions, `tries=1`/`timeout=90` < `retry_after=120`, reaper every minute, orphan/replay tests | Never run against a real queue |
| 7 | Honest outcomes (REL-02) | **PASS** | `ScannerOutcome` enum; exit codes/stderr/duration captured; `invalid_output` ≠ no findings; 36 executor tests | Real tool output unverified |
| 8 | Audit & redaction (AUD-01) | **PASS (code)** | `AuditLogger` with key-based redaction, length/byte caps, non-fatal logging | Never written to a live database |
| 9 | Authenticated downloads & FE correctness (FE-01/02) | **PASS (build)** | `DownloadButton` fetches with the bearer token; `ApiError` preserves server messages; 8 lifecycle states; polling follows server state; `tsc`/`vite`/`eslint` clean | No browser/E2E run |
| 10 | Automated tests & regression | **PASS** | 238 Runner + 223 PHP standalone + 188/188 parse | PHPUnit/Docker BLOCKED |
| 11 | Rollback & remaining risks | **PASS** | `docs/security.md` §7 (10 limitations) and §9 (code/config/migration rollback) | — |

**Overall: Phase 1 is complete for everything executable in this environment.
It is not "production ready": six checks are BLOCKED and listed above.**

---

## 6. Files of note

```
backend/app/Security/Target/          policy domain (16 classes)
backend/app/Security/Scan/JobId.php   deterministic Runner job ids
backend/app/Security/Http/SafeHttpClient.php   send-time validation + pinning
backend/app/Services/Runner/          RunnerClient (+ jobId delegation)
backend/app/Services/Scan/            ScanOrchestrator, ScannerExecutor
backend/tests/Standalone/             4 harnesses, 223 assertions
runner/src/                           policy, validate, tools, executor, server, auth, config
runner/test/                          7 suites, 238 tests
docs/security.md                      model, limitations, rollback, operator checklist
Dockerfile · docker-compose.yml       hardening
```

## 7. Dependencies

**No dependency was added to the backend or frontend.** The Runner has zero
runtime dependencies; `vitest` was already its only devDependency. `@php-wasm`
was installed **outside the repository** (`/tmp`) purely to obtain a PHP runtime
for verification and is not a project dependency.

## 8. Rollback

See `docs/security.md` §9 — code (`git checkout -- .`), configuration (do not
restore the published DB/Redis ports), and migrations
(`php artisan migrate:rollback --step=4`, after dumping `audit_events`).

## 9. Not committed

`git status --porcelain` → 94 entries (57 modified, 2 deleted, 35 untracked).
Nothing has been committed or pushed, per the instruction not to commit unless
asked.
