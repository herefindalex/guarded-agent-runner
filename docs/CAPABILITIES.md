# Guarded Agent Runner Capability Matrix

Guarded Agent Runner now has two explicitly separated layers: the GAR-PCS-001
M1 core with M2 read-only components, and the earlier Python
fixed-process sandbox used only as a legacy trust-boundary demonstration. The
matrix records what exists, how it was verified, and what must not be inferred.

## GAR-PCS-001 M1 core and M2 read-only alpha

| Capability | Current behavior | Validation |
|---|---|---|
| Agent authority | Immutable principal/session/enrollment scope with full SHA-256 digest and revocation epoch | Go unit tests |
| Change proposal | Catalog IDs compile to an immutable Paper A→B `ChangeIntent`; no path, URL or executable DSL input | Go unit tests |
| Idempotency | Same principal/enrollment/key and bytes return the frozen intent; changed bytes conflict | AT-005/006 tests |
| Independent approval | Agent tool catalog has no approve tool; owner-local service/CLI requires exact ID and digest | AT-001–004 tests |
| Writer ownership | One unreleased operation per enrollment; UNKNOWN blocks later approval | AT-034/060 tests |
| Durable journal | File-backed SQLite WAL + FULL readback; transactional authority and step preparation | Go unit tests |
| Shadow revalidation | Known drift is `INTENT_STALE`; missing evidence is `PRECONDITION_UNAVAILABLE`; zero dispatch | Unit/fake-target analogs of AT-013/014/018/026; formal M4 `LOCAL_PAPER` acceptance remains `NOT_RUN` |
| Live mutation | Hard-disabled; G-01/G-02 `PASS`, G-03/G-04 `FAIL`, and G-05/G-06/G-07 `NOT_RUN` | Historical read-only evidence, exact enrolled G-02 HOST_RECOVERY and failed-closed G-03 evidence; no mutation acceptance |
| MCP transport | Official Go SDK Streamable HTTP; literal loopback binding, exact Origin check, hashed bearer-to-session mapping, per-session 10 req/s burst-20 limit, strict ten-tool schemas, 64 KiB requests and 256 KiB responses | SDK interoperability and boundary tests |
| MCP approval | No approval/rejection/revocation tool is registered | Exact tool-list test |
| Paper runtime observations | GARGuard publishes bounded atomic snapshots; Go adapter validates pairing, freshness, duplicate/unknown fields, bounds, and symlink safety | Java/Go tests plus exact `LOCAL_PAPER_READ_ONLY` fixture |
| Paper login admission | GARGuard reads the paired lease fail-closed, rejects pre-login during maintenance, and publishes `MAINTENANCE` or `OPEN_READ_ONLY_ALPHA` | Java tests plus isolated Paper fixture |
| Admission TCP barrier | Fixed listener/upstream, maximum 30-second lease, paired runtime acknowledgment, existing-connection drop on close, restart defaults closed | Go race tests plus IPv4/IPv6 fixture checks |
| Host/container/artifact observations | Separate `gar-host` process uses a fixed full container ID and Docker Unix socket from owner-only config; rejects stopped/unhealthy targets, restart policy drift, competing startup writers, data mount/identity drift, unknown JARs and symlinks; validates gate image/namespace/rootfs/capabilities/socket mounts and exact loopback bindings; publishes atomic bounded evidence | Fake Unix-Docker tests plus exact local fixture with real Docker API and artifact hashes |
| Composite observations | Host supplies container/bootstrap/inventory/artifact evidence; GARGuard supplies boot/readiness/player/TPS/MSPT/heap evidence; proposal preconditions fail closed on stale, skewed, mismatched, or unready evidence | Go unit tests and live paired snapshots across a normal Paper restart |
| GAR change history | SQLite returns bounded principal/enrollment-scoped intent summaries with cursors; no pre-enrollment history is fabricated | Go unit tests |
| Graceful-stop oracle | Requires lifecycle, terminal runtime, graceful-exit and operation/step attribution; uncertain dispatch blocks backup and retry | UNIT/FAKE_TARGET plus a fixed-target `LOCAL_PAPER` run; the run stopped Paper but remained UNKNOWN when log evidence failed |
| Offline backup foundation | Fixed enrolled roots and artifact path, explicit RESERVED→WRITING→FINALIZING→VERIFYING→VALID lifecycle, source hash checks, bounded tar, fsync, no-clobber rename, digest reread, durable metadata and S05 completion | UNIT/FAKE_TARGET with real temporary files and SQLite reopen; the failed G-03 campaign never reached S05 |
| Backup observations | Owner-local `garctl backup show` inspects durable metadata; owner-side `Engine.Inspect` rechecks archive digest; live MCP backup evidence remains unavailable | Unit/store/filesystem tests; metadata alone is not a current integrity check |

Admission topology validation also attests the enrolled host gate binary digest,
its read-only bind, fixed command, `no-new-privileges`, and read-only mirrored
config, state, and runtime mounts.

## Planner and request boundary

| Capability | Current behavior | Validation |
|---|---|---|
| Request generation | UI generates read-only text from selected target and intent | Browser verified |
| Free-form interpretation | Not implemented; no LLM is connected | Explicit UI and README disclosure |
| Typed planning | Four presets generate typed `ToolCall` objects | Unit tested |
| Planner authority | None; planner cannot approve or execute | Architecture and injected-plan tests |
| Credentials in planner | None | Code inspection |

## Capability scope and policy

| Capability | Current behavior | Validation |
|---|---|---|
| Resource scope | Exactly one selected service per run | API and planner tests |
| Action scope | `service_status`, `read_log`, `restart_service` | Policy tests |
| Scope integrity | Canonical payload protected by SHA-256 hash | Unit tested |
| Monotonic scope | Persisted scope may remain equal or shrink, never expand | Repository tests |
| Approval monotonicity | Required approval cannot become automatic | Repository tests |
| Unknown actions | Denied | Policy and fail-closed tests |
| Malformed arguments | Denied | Policy tests |
| Policy exception | Converted to `DENY_INTERNAL_ERROR` | Fail-closed test |

## Service scenarios

| Service | Diagnostics | Restart authorization | Deterministic result |
|---|---|---|---|
| Service A | Real child-process status, PID, generation, and supervisor logs | Exact human approval | Compose sandbox replaces the process and verifies a new healthy generation |
| NGINX | Status and last 100 log lines | Automatic | Initially stopped; restarted; verified running |
| PostgreSQL | Status and last 100 log lines | Exact human approval | Initially degraded; pauses; resumes after revalidation; verified running |
| MySQL | Status and last 100 log lines | Required only if remediation is needed | Initially healthy; restart skipped; verified running |
| Redis | Status and last 100 log lines | Required only if remediation is needed | Initially healthy; restart skipped; verified running |

## Conditional remediation

| Capability | Current behavior | Validation |
|---|---|---|
| Health decision | Restart when status is not `running` or logs contain defined failure terms | Runner tests |
| Healthy outcome | Records `NO_RESTART_NEEDED` and `TOOL_SKIPPED` | Runner and audit tests |
| Recovery verification | Executes a new `service_status` after restart or skip | Runner and browser tests |
| Outcome summary | UI distinguishes healthy, approval-required, approved-not-executed, and recovered states | Browser verified |

## Human approval

| Capability | Current behavior | Validation |
|---|---|---|
| Approval granularity | Bound to run, action, arguments, resource, scope hash, and expiry | Unit tested |
| Approval side effect | Approval changes state only; it does not execute | API/browser verified |
| Resume revalidation | Rechecks binding, expiry, policy, authorization, resource, scope, and live service precondition | Unit and Docker integration tested |
| Stale approval | Changed status, PID, or generation yields terminal `STALE_PRECONDITION` without restart | Unit and Docker integration tested |
| Rejection | Terminal; executor receives no restart | Unit tested |
| Approval expiry | Fails closed | Unit tested |
| Cryptographic signature | Not implemented; binding is an integrity hash, not an authenticated signature | Explicit non-capability |

## Execution and audit

| Capability | Current behavior | Validation |
|---|---|---|
| Executor surface | Three typed methods through one dispatcher | Code inspection and tests |
| Fixed sandbox adapter | Internal HTTP adapter can operate only `service-a`; no Docker socket or arbitrary URL | Unit and Docker integration tested |
| Real process replacement | Supervisor terminates the old child and starts a new generation | Unit and Docker integration tested |
| Shell or arbitrary command | Not implemented | Explicit non-capability |
| Execution token | Short-lived and bound to run, action, and resource | Unit tested through executor paths |
| Timeout | `asyncio.wait_for` with terminal failure | Unit tested |
| Cleanup | Idempotent and executed from `finally` | Unit tested |
| Run persistence | SQLite through SQLAlchemy repository | API and runner tests |
| Audit ordering | Timestamp plus insertion ID | Exact event-sequence tests |
| Tamper-proof external audit | Not implemented | Production requirement |

## Delivery

| Capability | Current behavior | Validation |
|---|---|---|
| Local Conda setup | Python 3.12 environment definition | Locally verified |
| React production build | TypeScript and Vite | Locally verified |
| Container build | Multi-stage Dockerfile, non-root runtime | Defined; CI job included |
| CI | Python, frontend, and container checks | Defined; hosted run pending |
| Secret scan | Full-history Gitleaks workflow | Defined; hosted run pending |
| CD artifact | Tagged/manual GHCR publication with SBOM and provenance | Defined; hosted run pending |
| Automatic server deployment | Not implemented | Explicit operator boundary |

## Explicit non-capabilities

- Real systemd, Kubernetes, cloud, database, or SSH execution beyond the fixed local process sandbox
- Real infrastructure credentials
- LLM inference or natural-language authorization
- Multi-user authentication and RBAC
- Mainline policy administration UI
- Signed approval attestations
- Cross-worker locking and idempotency
- Remote append-only audit storage
- Unattended deployment to any environment

Related: [README](../README.md), [architecture](../ARCHITECTURE.md), [status](STATUS.md), and [security](SECURITY.md).
