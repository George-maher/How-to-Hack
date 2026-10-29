# Phase 1 — Verification Closure

Branch `arena/a4476df2-how-to-hack`. Working tree only; **nothing committed or
pushed**. Baseline commit `8d1e9f8`.

Every number below came from running the command next to it in this environment.
Anything unexecutable is marked **BLOCKED**, and no environmental blocker is
presented as a pass.

---

## 2. Environment (measured, not assumed)

| Item | Result |
|---|---|
| OS / shell | Debian 12 (bookworm), kernel 6.1, `/bin/bash` |
| PHP CLI | **absent** — verification used a real PHP **8.2.33** runtime via `@php-wasm/node` (installed under `/tmp`, not a project dependency) |
| PHP extensions available in that runtime | curl ✅, openssl, mbstring, zlib, phar, zip, dom, sqlite3, PDO(sqlite,mysql) |
| PHP extensions **missing** | `pdo_pgsql`, `pgsql`, `sockets`, `pcntl`, `posix`, `intl` |
| Composer | **absent**, and unobtainable: `repo.packagist.org` and `getcomposer.org` both return `000` (proxy-blocked); no Composer phar on npm/PyPI |
| `composer.lock` | **stub**: 959 bytes, `packages: 0`, `packages-dev: 0`, `content-hash: 000…0` |
| `vendor/` | absent; no local Composer cache |
| Node / npm | v22.22.3 / 10.9.8 |
| PostgreSQL client/server | absent |
| Redis | absent |
| Docker CLI / daemon | absent; no `/var/run/docker.sock` |
| Tests present | **both** styles: Laravel/PHPUnit (`tests/Feature`, `tests/Unit`) *and* dependency-free PHP harnesses (`tests/Standalone`) |

Two consequences worth stating plainly: the missing `pdo_pgsql`/`sockets`/
`pcntl` extensions mean this WASM runtime could not host Laravel or its queue
even **if** the vendor tree existed, and the stub lockfile means dependency
resolution is impossible regardless of network.

---

## A. Changes made

### Verification added (new files)

| File | Purpose |
|---|---|
| `backend/tests/Standalone/http_pinning_test.php` | 18 runtime assertions over **real TCP**: proves `CURLOPT_RESOLVE` sends the connection to the approved literal, not a re-resolved answer |
| `backend/tests/Standalone/http_pinning.mjs` | Fixture runner: two servers on the *same* port on `127.0.0.1` and `127.0.0.2`, a redirect target, and optional `::1`; spawns `php`/`$PHP_BIN` |
| `backend/tests/Standalone/container_wiring_test.php` | 11 static-wiring assertions: route → public method, every `use App\…` resolves, every constructor argument resolves, injected contracts are bound, security services are singletons |

### Defects fixed

| # | Defect | Evidence | Fix |
|---|---|---|---|
| 1 | `.env.example` documented **`ANTHROPIC_API_KEY`** but the code reads **`CLAUDE_API_KEY`** | `config/ai-agent.php:15` vs `.env.example` | Template corrected; an operator following it would have silently disabled the Claude provider |
| 2 | `AI_AGENT_MODEL` documented but read by nothing | `grep` across `config/` | Removed; per-provider `*_MODEL` keys documented instead |
| 3 | Dead `scanners.docker` config block with **`network => 'host'`** default | no `config('scanners.docker…')` call anywhere | Block removed; comment records why |
| 4 | Compose header claimed `scanner-net` is `internal: true` — it is not | compose vs its own comment | Comment corrected |
| 5 | Compose claimed the proxy prevents "host config changes" | proxy source (§ below) | Comment corrected to the verified truth |
| 6 | `.env.example` omitted `RUNNER_ENABLED`, timeouts, `SCAN_MAX_*`, `AUDIT_RETENTION_DAYS` | env-key cross-check | Added |

Config/env consistency is now clean: the only key documented without a `config()`
reader is `VITE_API_URL`, which is read by Vite in the frontend.

*(Harness bugs found and fixed during development — off-by-one alias extraction,
`enum`/`interface` not indexed, string-interpolation braces breaking the depth
counter, `null` treated as a type — were in my own new code and are noted here
only for reproducibility.)*

---

## B. Verification evidence

### New results (this session)

| Command | Result |
|---|---|
| `node backend/tests/Standalone/http_pinning.mjs` | **17 passed, 0 failed, 1 skipped** — exit 0 |
| `php …/container_wiring_test.php` | **11 passed, 0 failed** |
| `npx vitest run` (runner) | **238 passed / 238** (7 files) |
| 5 standalone harnesses | **234 passed, 0 failed** (83 + 38 + 52 + 50 + 11) |
| PHP parse, all files | **190/190 OK** |
| `docker-compose.yml` YAML parse + invariants | parses; only `app`/`frontend` publish ports (both `127.0.0.1`) |
| `npx tsc -b` / `npx eslint src` / `vite build` | exit 0 / 0 problems / 268.80 kB (82.58 kB gzip) |

### What the pinning test actually proves

Fixtures bind `127.0.0.1:P` and `127.0.0.2:P` — same port, different address,
and the hostname `pinned.test` does not exist in DNS.

1. No pin → **fails to resolve** (`ADDRESS-A`/`B` unreachable). So DNS supplies
   nothing and any success must come from the pin.
2. Pin `127.0.0.1` → `ADDRESS-A`; pin `127.0.0.2` → `ADDRESS-B`. **The pin, not
   DNS, chose the destination.**
3. `302` is returned, not followed, and the redirect target is not fetched —
   with a **control** case proving the target *is* reachable when following is
   enabled (so test 3 is not a false pass).
4. The **real** `TargetPolicy` (lab exception, injected resolver) produces
   `resolvedIps = ['127.0.0.1']`; the **real** `SafeHttpClient::pickAddress`/
   `resolveEntry` (via reflection) turn it into `pinned.test:P:127.0.0.1`; that
   entry is then fed to a live curl request which reaches `ADDRESS-A`.
5. A changed DNS answer with a stored pin → `AddressChanged`; a split answer
   (private + public) → denied whole; an allowed decision with no address and a
   denied decision both yield **no pin** (the client turns that into a denial).

Skipped: pin to `[::1]` — this runtime cannot resolve IPv6 (`Couldn't resolve
host '::1'`, while Node's own IPv6 works), confirmed to be emscripten
networking, not the code. The bracketed entry format (`host:8443:[::1]`) is
asserted separately.

### Proxy review — read from source, not from memory

`tecnativa/docker-socket-proxy` **v0.2.0** `haproxy.cfg` (tag `0.2` =
`{{major}}.{{minor}}`, confirmed from its CI `tag-semver` config):

```haproxy
http-request deny unless METH_GET || { env(POST) -m bool }
http-request allow if { path,url_dec -m reg -i ^(/v[\d\.]+)?/containers } { env(CONTAINERS) -m bool }
http-request deny
```

* **No `payload()` anywhere** → request bodies are never inspected.
* **`^/containers` is an unconstrained prefix** → not just create, but `kill`,
  `stop`, `restart`, `pause`, `update` on **any** container on the host.
* `GET` is method-permitted but still subject to section rules, so `/exec`,
  `/volumes`, `/secrets` stay closed (verified from the rule order).

### Regression (re-run, not carried over)

The previously reported figures were re-executed and reproduced exactly:
238 Runner tests, 234+17 PHP assertions, 190/190 parse, clean frontend build.

---

## C. Acceptance matrix

| # | Criterion | Status | Evidence | Verified how |
|---|---|---|---|---|
| 1 | Target policy & IP normalization | **PASS** | 83 PHP + 49 JS assertions incl. alternate IPv4/IPv6 forms, split answers, metadata, lab-exception scoping | Unit/behavioural, deterministic injected DNS |
| 2 | Runner API contract compatibility | **PASS** | `validate` 23, `registry-parity` 21, `runner_contract` 50, `server` 46 — includes real API payload acceptance, nested/null/unknown-key handling, job-id rules | Unit + in-process HTTP to the real server |
| 3 | Approval binding & single-use | **PASS** | `approval_test` 52: fingerprint over host/ports/tools/options, invalidation, expiry, mismatch, single-use CAS | Harness |
| 4 | Scan lifecycle & recovery | **PARTIAL** | State machine + reaper + CAS transitions covered by `scan_lifecycle` 38 and code review; `tries=1`/`timeout=90` < `retry_after=120` | Harness only — **no worker/Redis ever ran** |
| 5 | Docker isolation & socket-proxy | **PARTIAL** | Isolation flags asserted in 36 argv tests; proxy audited from source; compose invariants parsed | **No daemon** → no container ever started. Proxy has a **confirmed HIGH** exposure (below) |
| 6 | Laravel boot, DI & routes | **PARTIAL** | `container_wiring` 11/11, mutation-tested (route→missing method, dangling import, unbound interface all caught) | **Static analysis** — Laravel never booted |
| 7 | PostgreSQL migrations | **BLOCKED** | `composer.lock` stub, Packagist `000`, no `pdo_pgsql`, no server | Nothing executed |
| 8 | Auth & report download authorization | **PARTIAL** | Controllers authorize per object; downloads use bearer `fetch`→Blob; frontend builds/lints clean | Code + static; **PHPUnit Feature tests unexecutable** |
| 9 | Safe HTTP client & DNS pinning | **PARTIAL** | 17 runtime assertions incl. pin-beats-DNS and redirect control | **Real TCP** for the curl mechanism + real policy/client logic; Guzzle plumbing unexecuted |
| 10 | Truthful scanner outcomes | **PASS** | `executor` 36: exit 126/127→`unavailable`, timeout→`timed_out`, non-zero→`failed`, bad stdout→`invalid_output`, cancel→`cancelled`, zero-findings≠clean | Fake children — no real binaries |
| 11 | Frontend lifecycle & downloads | **PARTIAL** | `tsc`, `eslint`, `vite build` clean; 8 states, `ApiError.code` branching, auth'd downloads | Build/lint only — **no browser E2E** |

**Not marked PASS:** criterion 5 (no container ran) and 7 (nothing ran). Per the
rules, argv inspection is not isolation evidence and harnesses are not Laravel
integration.

---

## D. Remaining blockers

| # | Blocked | Why | Cause | To unblock |
|---|---|---|---|---|
| 1 | Composer / vendor tree | `composer.lock` is a stub; Packagist & getcomposer.org return 000; no phar on npm/PyPI | **Environmental** (network allowlist) + repo ships a stub lock | `cd backend; composer install` on a networked machine, then commit the real lock |
| 2 | Laravel boot, PHPUnit, migrations | Requires (1); this WASM runtime also lacks `pdo_pgsql`/`sockets`/`pcntl` | Environmental | With (1): `php artisan test` |
| 3 | PostgreSQL verification | No server **and** no PDO driver anywhere available | Environmental | Disposable PG 16 + `php artisan migrate --database=pgsql` |
| 4 | Docker isolation, proxy behaviour | No CLI, no daemon, no socket | Environmental (sandbox) | Runbook §F |
| 5 | Socket-proxy privilege | **Not** environmental — architectural | Proxy filters paths, not bodies | §F step 7 reproduces the exposure; fix needs rootless Docker / authz plugin |
| 6 | Browser E2E | No browser/harness set-up in repo | Environmental | Add Playwright when a browser is available |

---

## E. Security assessment

**Phase 1 is partially verified.** The security *controls* are implemented and
well covered by executable tests; the *deployment* claims are not, because
nothing ran under Docker or Laravel.

Unresolved issues, by severity:

- **HIGH — Runner compromise is host compromise.** `CONTAINERS=1` + `POST=1`
  with a prefix-matched `^/containers` lets a compromised Runner (a) create a
  privileged container, bind-mount `/`, or mount the Docker socket, and (b)
  kill/stop/restart *any* container, including `db`, `redis` and the API. Not
  fixable by path filtering. Documented in `docs/security.md` §5 with four
  remediation options; the docs no longer claim containment.
- **MEDIUM — non-reproducible API image.** `Dockerfile` runs
  `rm -f composer.lock && composer install`, so every build resolves whatever
  is current. Deliberate while the lock is a stub, but it must not ship.
- **MEDIUM — unverified runtime isolation.** Read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`, pids/memory/CPU limits and the dedicated network are
  asserted in argv only. No container has ever started.
- **LOW — floating image tags** (`redis:7-alpine`, `postgres:16-alpine`,
  `docker-socket-proxy:0.2`). Digest pinning would be better; `0.2` is a valid
  tag (`{{major}}.{{minor}}`), verified from the project's CI config.
- **LOW — `db`/`redis` have no `cap_drop: ALL`.** Adding it may break their
  entrypoints (they need `CHOWN`/`SETUID` during init) and cannot be tested
  here, so it was left alone rather than guessed at.

No production-readiness claim is made. Criteria 5, 6, 7, 8, 9 and 11 remain
partial or blocked.

---

## F. Owner runbook (PowerShell, Docker Desktop)

```powershell
cd C:\path\to\HowToHack

# 1. Secrets (32+ chars). Never commit .env.
Copy-Item .env.example .env
$hex = -join ((48..57)+(97..102) | Get-Random -Count 64 | ForEach-Object { [char]$_ })
(Get-Content .env) -replace '^RUNNER_SECRET=.*', "RUNNER_SECRET=$hex" | Set-Content .env
# repeat for DB_PASSWORD and REDIS_PASSWORD; set APP_KEY afterwards

# 2. Confirm the pinned proxy tag exists before building
docker manifest inspect tecnativa/docker-socket-proxy:0.2

# 3. Build and start
docker compose build
docker compose up -d
docker compose ps

# 4. Dependencies + tests (closes blockers 1-3)
docker compose exec app composer install
docker compose exec app php artisan migrate --force
docker compose exec app php artisan test
docker compose run --rm runner npx vitest run

# 5. Isolation evidence for one scanner container
docker compose --profile build build scanner-builder
docker run --rm --network scanner-net --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m `
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 512m `
  --user 65534:65534 --entrypoint id howtohack/scanner:latest
# expect: uid=65534 gid=65534, and no root

# 6. Confirm no host integration on a live scan container
docker ps --filter "name=howtohack-scan" --format "{{.ID}}" | ForEach-Object {
  docker inspect $_ --format 'Priv={{.HostConfig.Privileged}} CapAdd={{.HostConfig.CapAdd}} Net={{.HostConfig.NetworkMode}} PID={{.HostConfig.PidMode}} Binds={{.HostConfig.Binds}}'
}

# 7. Reproduce the documented proxy exposure (expected: 201 — this PROVES risk E-1)
docker run --rm --network scanner-control curlimages/curl -s -o NUL -w "%{http_code}`n" `
  -X POST http://docker-proxy:2375/containers/create `
  -H "Content-Type: application/json" -d '{\"Image\":\"alpine\",\"HostConfig\":{\"Privileged\":true}}'

# 8. Confirm blocked paths stay blocked (expected: 403 each)
docker run --rm --network scanner-control curlimages/curl -s -o NUL -w "%{http_code}`n" `
  -X POST http://docker-proxy:2375/exec/abc/start -d '{}'
```

Step 7 returning `201` is the expected result and is the evidence for the HIGH
risk in §E — it is not a test failure. Fixing it requires rootless Docker or a
Docker authorization plugin, which is an architectural change outside this
phase's scope.

---

## Files changed this session

```
backend/tests/Standalone/http_pinning_test.php    new — 18 runtime assertions
backend/tests/Standalone/http_pinning.mjs         new — local fixtures
backend/tests/Standalone/container_wiring_test.php new — 11 static assertions
backend/config/scanners.php                       dead 'docker' block removed
.env.example                                      CLAUDE_API_KEY fix, dead key removed
docker-compose.yml                                two misleading comments corrected
docs/security.md                                  proxy section rewritten; §8a added
```
