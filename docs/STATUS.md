# Guarded Agent Runner Status

Updated: 2026-09-16

This document separates implemented behavior from locally verified evidence and from work that still depends on GitHub or a production environment. A workflow file existing in the repository is not the same as a hosted workflow run passing.

## Status vocabulary

| Label | Meaning |
|---|---|
| `IMPLEMENTED` | The behavior exists in source code |
| `LOCAL_VERIFIED` | A local automated or browser check passed |
| `HOSTED_NOT_RUN` | GitHub-hosted evidence does not yet exist |
| `NOT_IMPLEMENTED` | The capability is intentionally absent |

## GAR-PCS-001 M1 core and M2 read-only alpha

| Check | Result |
|---|---|
| Go domain/store/workflow/MCP tests | PASS, including race detector |
| `go vet ./...` | PASS |
| Agent tool count | PASS, exactly 10 and no approval tool |
| Fake-target mutation dispatch | PASS, zero; mutation entry point returns `UNSUPPORTED_ENVIRONMENT` |
| `compatibility.lock` | One exact `LOCAL_PAPER_READ_ONLY` tuple; G-01 `PASS`, G-02/G-04 `FAIL`, G-03/G-05/G-06/G-07 `NOT_RUN`; mutation disabled |
| MCP Streamable HTTP transport | `LOCAL_VERIFIED`; official SDK client plus real authenticated loopback MCP against the isolated Paper fixture |
| Paper guard and runtime snapshot adapter | `LOCAL_VERIFIED`; Paper 26.2 build 124 loaded GARGuard 0.1.0 and published fresh bounded snapshots across a normal restart |
| Paper admission guard | `LOCAL_VERIFIED`; maintenance rejects pre-login, a fresh matching lease reports `OPEN_READ_ONLY_ALPHA`, and missing/stale/cross-generation state fails closed |
| Fixed-target host observer and composite adapter | `LOCAL_VERIFIED`; exact container/image/data-root identity, lifecycle, artifact hashes, freshness, boot pairing, gate topology, and loopback binding policy observed against the isolated fixture |
| Admission TCP gate | `LOCAL_VERIFIED`; IPv4/IPv6 closed/open checks, bounded lease, runtime acknowledgment, in-flight TCP drop, and gate/Paper restart-to-closed behavior passed |
| Read-only MCP tools | `LOCAL_VERIFIED`; exactly 10 tools, no approval tool, live health/player/performance/plugin/error/change reads; backup honestly unavailable |
| Host recovery, real plugin transition, mutation beta | `NOT_RUN`; G-02 remains failed pending host reboot and real in-flight Minecraft login checks; G-04 source attribution and G-03/G-05/G-06/G-07 remain incomplete |

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
| GitHub CI | `IMPLEMENTED`, `HOSTED_NOT_RUN` | Backend, frontend, and container jobs are defined in `ci.yml` |
| Secret scanning workflow | `IMPLEMENTED`, `HOSTED_NOT_RUN` | Full-history Gitleaks workflow is defined |
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
- The upstream baseline CI and secret scan passed on commit `a04aa36`; the current sandbox changes still require a new hosted run.
- GHCR publication remains `HOSTED_NOT_RUN` until a tagged or manual run publishes an image.
- No production credentials, external infrastructure, LLM, or identity provider were used.

## Current non-capabilities

The MVP does not implement production service adapters beyond the fixed local sandbox, real credentials, authenticated operator identity, multi-user RBAC, signed approvals, a remote immutable audit ledger, distributed locking, an LLM, or automatic server deployment.

See the [capability matrix](CAPABILITIES.md) for control-by-control detail and [architecture](../ARCHITECTURE.md) for the production evolution path.
