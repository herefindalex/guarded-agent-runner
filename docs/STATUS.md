# Guarded Agent Runner Status

Updated: 2026-09-17

This document separates implemented behavior from locally verified evidence and from work that still depends on GitHub or a production environment. A workflow file existing in the repository is not the same as a hosted workflow run passing.

## Status vocabulary

| Label | Meaning |
|---|---|
| `IMPLEMENTED` | The behavior exists in source code |
| `LOCAL_VERIFIED` | A local automated or browser check passed |
| `HOSTED_NOT_RUN` | GitHub-hosted evidence does not yet exist |
| `NOT_IMPLEMENTED` | The capability is intentionally absent |

## GAR-PCS-001 M1 core and M2 read-only alpha

G-03 continuation: the S00–S05 coordinator, fixed-target Paper stop adapter,
offline readiness contract, bounded archive engine and durable backup metadata
now pass UNIT/FAKE_TARGET tests, including six crash/reopen boundaries. The
owner-local `gar-g03-verify` route was exercised against the enrolled isolated
Paper target. S00–S02 passed and Paper exited cleanly, but Docker rejected the
RFC3339Nano logs query, so S03 became UNKNOWN, retained writer ownership and
blocked S04/S05. No backup record or archive exists. The query bug is fixed and
covered by regression tests, but this campaign cannot be retried or promoted;
G-03 is `FAIL`. G-02 changed
FAIL → PASS after verification of the existing reboot at 2026-09-17T08:41:43Z.
The kernel boot ID changed and the original fixture containers recovered with
fresh CLOSED/MAINTENANCE, zero-player and dual-stack fail-closed observations.
No additional workstation reboot was performed or is authorized. Current gates:
G-01 PASS, G-02 PASS, G-03 FAIL, G-04 FAIL, G-05/G-06/G-07 NOT_RUN.

The current baseline commit `744922f8ba87f6e51b4130f50a62785c0e4fd70c` has
successful hosted [CI](https://github.com/herefindalex/guarded-agent-runner/actions/runs/35190266318)
and [Secret scan](https://github.com/herefindalex/guarded-agent-runner/actions/runs/35190266263).
The G-03 continuation has local verification. Hosted results must be checked
for the exact published commit; baseline results alone do not validate later
changes, and CI cannot establish real Paper G-03 acceptance.

| Check | Result |
|---|---|
| Go domain/store/workflow/MCP tests | PASS, including race detector |
| `go vet ./...` | PASS |
| Agent tool count | PASS, exactly 10 and no approval tool |
| Fake-target mutation dispatch | PASS, zero; mutation entry point returns `UNSUPPORTED_ENVIRONMENT` |
| `compatibility.lock` | Historical `LOCAL_PAPER_READ_ONLY` tuple, G-02 `HOST_RECOVERY`, and the exact failed G-03 `LOCAL_PAPER` campaign; G-01/G-02 `PASS`, G-03/G-04 `FAIL`, G-05/G-06/G-07 `NOT_RUN`; mutation disabled |
| MCP Streamable HTTP transport | `LOCAL_VERIFIED`; official SDK client plus real authenticated loopback MCP against the isolated Paper fixture |
| Paper guard and runtime snapshot adapter | `LOCAL_VERIFIED`; Paper 26.2 build 124 loaded GARGuard 0.1.0 and published fresh bounded snapshots across a normal restart |
| Paper admission guard | `LOCAL_VERIFIED`; maintenance rejects pre-login, a fresh matching lease reports `OPEN_READ_ONLY_ALPHA`, and missing/stale/cross-generation state fails closed |
| Fixed-target host observer and composite adapter | `LOCAL_VERIFIED`; exact container/image/data-root identity, lifecycle, artifact hashes, freshness, boot pairing, gate topology, and loopback binding policy observed against the isolated fixture |
| Admission TCP gate | `LOCAL_VERIFIED`; IPv4/IPv6 closed/open checks, bounded lease, runtime acknowledgment, in-flight TCP drop, and gate/Paper restart-to-closed behavior passed |
| Minecraft in-flight login-close | `LOCAL_PAPER`; protocol 776 Login Start remained in flight before close, connection terminated in 13 ms, players stayed zero |
| Read-only MCP tools | `LOCAL_VERIFIED`; exactly 10 tools, no approval tool, live health/player/performance/plugin/error/change reads; backup honestly unavailable |
| Host recovery, stop/backup, real plugin transition | G-02 `HOST_RECOVERY` PASS; G-03 failed closed at S03 with no backup; G-04 source attribution fails and G-05/G-06/G-07 remain incomplete |

Detailed mapping: [GAR v0.1 implementation status](GAR_V01_IMPLEMENTATION.md).

The implementation status below is retained legacy Python service-sandbox evidence. It is not GAR-PCS-001 Paper mutation evidence.

## Legacy implementation status

| Area | Status | Evidence |
|---|---|---|
| Deterministic typed planner | `LOCAL_VERIFIED` | Planner tests cover all four presets and every service selection |
| Immutable capability scope | `LOCAL_VERIFIED` | Scope-expansion and approval-weakening tests reject persisted changes |
| Fail-closed policy | `LOCAL_VERIFIED` | Unknown, malformed, out-of-scope, missing-scope, and internal-failure tests pass |
| Automatic NGINX remediation | `LOCAL_VERIFIED` | Browser flow and runner tests show restart plus independent verification |
| PostgreSQL approval gate | `LOCAL_VERIFIED` | Browser flow proves approval does not execute; resume revalidates and completes |
| Service A process sandbox | `LOCAL_VERIFIED` | Compose flow replaced PID 96 with PID 104, advanced generation 2 to 3, and verified healthy |
| Live sandbox panel | `LOCAL_VERIFIED` | Browser shows live health, PID, generation, bounded supervisor logs, and audit events |
| Stale precondition | `LOCAL_VERIFIED` | Changed PID/generation produced terminal `STALE_PRECONDITION` with no extra restart |
| Healthy MySQL/Redis skip | `LOCAL_VERIFIED` | Browser and runner tests show `TOOL_SKIPPED` and verified `RUNNING` state |
| Exact approval binding | `LOCAL_VERIFIED` | Tampered action arguments, resource, scope, expiry, policy, and authorization fail |
| Guarded execution timeout | `LOCAL_VERIFIED` | Timeout fails the run and cleanup remains idempotent |
| Ordered audit trail | `LOCAL_VERIFIED` | Tests assert the full event sequence for approval and skip flows |
| React production build | `LOCAL_VERIFIED` | TypeScript and Vite production build pass |
| Responsive UI | `LOCAL_VERIFIED` | 390px browser check reports no horizontal overflow |
| Container image | `LOCAL_VERIFIED` | Multi-stage non-root Python 3.12 image built and returned HTTP 200 from `/health` |
| GitHub CI | Hosted PASS for baseline `744922f` | CI run 35190266318 succeeded; verify each later commit's hosted run separately |
| Secret scanning workflow | Hosted PASS for baseline `744922f` | Secret scan run 35190266263 succeeded; verify each later commit's hosted scan separately |
| GHCR publication | `IMPLEMENTED`, `HOSTED_NOT_RUN` | Tagged/manual publication workflow includes SBOM and provenance |

## Local validation baseline

| Check | Result |
|---|---|
| Python | 3.12 in Conda environment `guarded-agent-runner` |
| `python -m pytest -q` | PASS, 39 tests |
| `ruff check guarded_agent_runner tests` | PASS |
| `npm --prefix frontend run build` | PASS |
| `docker build -t guarded-agent-runner:verify .` | PASS |
| Container `/health` smoke test | PASS |
| GitHub workflow YAML parse | PASS, three workflows |
| Markdown relative-link check | PASS |
| Browser scenarios | PASS, Service A approval/restart, stale approval, NGINX, PostgreSQL, MySQL, Redis |
| Browser console | PASS, no warning or error observed |
| 390px horizontal overflow | PASS |
| LAN health endpoint | PASS at the locally observed demo address |

The LAN address is environment-specific and is intentionally not committed as a stable endpoint.

## Evidence boundaries

- The fixed Compose sandbox proves real local child-process replacement, not operating-system or production service control.
- Legacy direct-run targets still use fake infrastructure for deterministic policy demonstrations.
- Local browser checks are not a hosted end-to-end environment.
- Branch baseline `744922f` passed hosted CI and Secret scan; each published G-03 commit requires its own hosted checks, independently of the real Paper release gates.
- GHCR publication remains `HOSTED_NOT_RUN` until a tagged or manual run publishes an image.
- No production credentials, external infrastructure, LLM, or identity provider were used.

## Current non-capabilities

The MVP does not implement production service adapters beyond the fixed local sandbox, real credentials, authenticated operator identity, multi-user RBAC, signed approvals, a remote immutable audit ledger, distributed locking, an LLM, or automatic server deployment.

See the [capability matrix](CAPABILITIES.md) for control-by-control detail and [architecture](../ARCHITECTURE.md) for the production evolution path.
