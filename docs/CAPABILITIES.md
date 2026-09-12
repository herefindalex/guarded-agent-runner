# Guarded Agent Runner Capability Matrix

Guarded Agent Runner validates a secure execution-control pattern with deterministic fake infrastructure. The matrix records what exists, how it was verified, and what must not be inferred from the demo.

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
| Resume revalidation | Rechecks binding, expiry, policy, authorization, resource, and scope | Unit tested |
| Rejection | Terminal; executor receives no restart | Unit tested |
| Approval expiry | Fails closed | Unit tested |
| Cryptographic signature | Not implemented; binding is an integrity hash, not an authenticated signature | Explicit non-capability |

## Execution and audit

| Capability | Current behavior | Validation |
|---|---|---|
| Executor surface | Three typed methods through one dispatcher | Code inspection and tests |
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

- Real systemd, Kubernetes, cloud, database, or SSH execution
- Real infrastructure credentials
- LLM inference or natural-language authorization
- Multi-user authentication and RBAC
- Mainline policy administration UI
- Signed approval attestations
- Cross-worker locking and idempotency
- Remote append-only audit storage
- Unattended deployment to any environment

Related: [README](../README.md), [architecture](../ARCHITECTURE.md), [status](STATUS.md), and [security](SECURITY.md).
