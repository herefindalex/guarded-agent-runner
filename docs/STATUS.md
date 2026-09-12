# Guarded Agent Runner Status

Updated: 2026-09-12

This document separates implemented behavior from locally verified evidence and from work that still depends on GitHub or a production environment. A workflow file existing in the repository is not the same as a hosted workflow run passing.

## Status vocabulary

| Label | Meaning |
|---|---|
| `IMPLEMENTED` | The behavior exists in source code |
| `LOCAL_VERIFIED` | A local automated or browser check passed |
| `HOSTED_NOT_RUN` | GitHub-hosted evidence does not yet exist |
| `NOT_IMPLEMENTED` | The capability is intentionally absent |

## Implementation status

| Area | Status | Evidence |
|---|---|---|
| Deterministic typed planner | `LOCAL_VERIFIED` | Planner tests cover all four presets and every service selection |
| Immutable capability scope | `LOCAL_VERIFIED` | Scope-expansion and approval-weakening tests reject persisted changes |
| Fail-closed policy | `LOCAL_VERIFIED` | Unknown, malformed, out-of-scope, missing-scope, and internal-failure tests pass |
| Automatic NGINX remediation | `LOCAL_VERIFIED` | Browser flow and runner tests show restart plus independent verification |
| PostgreSQL approval gate | `LOCAL_VERIFIED` | Browser flow proves approval does not execute; resume revalidates and completes |
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
| `python -m pytest -q` | PASS, 35 tests |
| `ruff check guarded_agent_runner tests` | PASS |
| `npm --prefix frontend run build` | PASS |
| `docker build -t guarded-agent-runner:verify .` | PASS |
| Container `/health` smoke test | PASS |
| GitHub workflow YAML parse | PASS, three workflows |
| Markdown relative-link check | PASS |
| Browser scenarios | PASS, NGINX, PostgreSQL, MySQL, Redis |
| Browser console | PASS, no warning or error observed |
| 390px horizontal overflow | PASS |
| LAN health endpoint | PASS at the locally observed demo address |

The LAN address is environment-specific and is intentionally not committed as a stable endpoint.

## Evidence boundaries

- Fake infrastructure proves orchestration and authorization behavior, not operating-system service control.
- A successful fake restart does not establish production reliability.
- Local browser checks are not a hosted end-to-end environment.
- Workflow definitions remain `HOSTED_NOT_RUN` until their GitHub Actions runs are inspected.
- GHCR publication remains `HOSTED_NOT_RUN` until a tagged or manual run publishes an image.
- No production credentials, external infrastructure, LLM, or identity provider were used.

## Current non-capabilities

The MVP does not implement real service adapters, real credentials, authenticated operator identity, multi-user RBAC, signed approvals, a remote immutable audit ledger, distributed locking, an LLM, or automatic server deployment.

See the [capability matrix](CAPABILITIES.md) for control-by-control detail and [architecture](../ARCHITECTURE.md) for the production evolution path.
