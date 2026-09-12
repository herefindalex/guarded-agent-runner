# Guarded Agent Runner Architecture

Guarded Agent Runner separates proposal generation from authorization and execution. The design assumes request text and planner output may be malicious. It gives those components influence over a typed proposal, but never gives them credentials, approval objects, execution tokens, or a general-purpose execution interface.

## System goals

The MVP answers four engineering questions:

1. Can an untrusted planner propose useful infrastructure work without receiving authority?
2. Can every action be constrained to one service and a small typed action set?
3. Can privileged approval be exact, time-bound, and revalidated immediately before execution?
4. Can the system prove both what it decided and whether remediation achieved the desired result?

It intentionally does not answer infrastructure integration, identity-provider, distributed-locking, or immutable-ledger questions. Those production gaps are explicit rather than simulated.

## Topology and trust boundaries

```mermaid
flowchart TB
    subgraph Untrusted[Untrusted influence]
        Request[Operator request text]
        Planner[Deterministic planner]
    end

    subgraph Control[Trusted control plane]
        API[FastAPI API]
        Compiler[Capability compiler]
        Policy[Fail-closed policy engine]
        State[Run state machine]
        Approval[Approval binding]
        Revalidation[Resume revalidation]
    end

    subgraph Execution[Trusted execution boundary]
        Executor[Guarded typed executor]
        Token[Short-lived execution token]
    end

    subgraph Data[Persistence]
        Repository[(SQLite repository)]
        Audit[(Ordered audit events)]
    end

    Request --> API
    API --> Planner
    API --> Compiler
    Planner --> Policy
    Compiler --> Policy
    Policy --> State
    Policy -->|automatic| Token
    Policy -->|privileged| Approval
    Approval --> Revalidation
    Revalidation --> Token
    Token --> Executor
    Executor --> Fake[Fake infrastructure]
    State --> Repository
    Approval --> Repository
    Policy --> Audit
    Executor --> Audit
```

### Untrusted boundary

The request and planner may select only values accepted by the API and planner preset. The planner never receives credentials or authorization objects. Tests can inject arbitrary planner output to prove that unknown actions, malformed arguments, and out-of-scope resources fail before execution.

### Trusted control plane

The capability compiler, policy engine, state-transition rules, approval binding, resume revalidation, and repository integrity checks form the control-plane portion of the trusted computing base.

### Execution boundary

The executor exposes exactly `service_status`, `read_log`, and `restart_service`. It checks a short-lived token bound to the run, action, and resource before dispatch. There is no escape hatch for shell commands or arbitrary plugins.

## Request-to-outcome data flow

```mermaid
sequenceDiagram
    actor Operator
    participant API
    participant Planner
    participant Policy
    participant Approval
    participant Executor
    participant Store

    Operator->>API: target + preset intent + generated request
    API->>Store: create run and immutable scope
    API->>Planner: request, preset, selected service
    Planner-->>API: typed ToolCall plan

    loop each automatic diagnostic action
        API->>Policy: evaluate ToolCall against scope
        Policy-->>API: ALLOW_AUTO or deny
        API->>Executor: bound short-lived token + ToolCall
        Executor-->>API: typed result
        API->>Store: action result + audit events
    end

    alt service healthy
        API->>Store: restart_service = SKIPPED
    else NGINX remediation needed
        Policy-->>API: ALLOW_AUTO
        API->>Executor: restart_service
    else database/cache remediation needed
        Policy-->>API: REQUIRE_APPROVAL
        API->>Approval: create exact approval binding
        Operator->>Approval: approve exact action
        Note over Approval,Executor: Approval alone does not execute
        Operator->>API: resume
        API->>Policy: revalidate approval and current policy
        API->>Executor: restart_service
    end

    API->>Executor: service_status verification
    Executor-->>API: resulting service state
    API->>Store: terminal outcome + audit events
```

The API has two advancement modes. `POST /runs/{id}/step` advances one automatic step. `POST /runs/{id}/run` continues until the run reaches a terminal state or an approval gate. After an approved restart is resumed, the service performs remaining automatic verification steps before completing.

## Capability model

A `CapabilityScope` contains:

- one or more allowed service names; compiled MVP runs contain exactly one;
- a fixed allowed-action set;
- an approval mode for each action;
- a version and SHA-256 hash over a canonical representation.

The repository checks every persisted update against the previous scope:

```text
scope(t+1) ⊆ scope(t)
```

In the current MVP the scope normally remains equal throughout a run. Equality satisfies the invariant. A production runner could reduce the remaining action set after each step, but it still could not add another service or change `required` approval to `auto`.

Example: a PostgreSQL run may read PostgreSQL status and logs and may propose a PostgreSQL restart. It cannot pivot to NGINX, invoke `run_shell`, or turn its required restart approval into automatic authorization.

## Typed planning

`DeterministicPlanner` maps four presets to reproducible plans:

| Preset | Tool calls |
|---|---|
| `status_only` | `service_status` |
| `logs_only` | `read_log` |
| `status_and_logs` | `service_status`, `read_log` |
| `diagnose_and_restart` | diagnostic status, logs, conditional restart, verification status |

Each `ToolCall` records a purpose such as `diagnose_current_state`, `remediate_if_needed`, or `verify_outcome`. Purpose is explanatory metadata; authorization still depends on the action, exact arguments, and compiled scope.

No LLM is connected. Determinism keeps policy, lifecycle, and audit behavior reproducible while the trust boundary is being validated.

## Conditional remediation

Before evaluating a `restart_service` call whose purpose is `remediate_if_needed`, `RunnerService` inspects the earlier typed results. Restart is required when:

- observed status is not `running`; or
- recent logs contain `failed`, `error`, `degraded`, `restarting`, or `unavailable`.

When neither condition is true, the action becomes `SKIPPED` with:

```json
{
  "executed": false,
  "decision": "NO_RESTART_NEEDED",
  "observed_status": "running",
  "reason": "Service is healthy; remediation was skipped."
}
```

The skip is an explicit audited decision, not an absent event. Verification still runs afterward.

## Policy decisions

The policy engine validates in this order:

1. scope exists and its hash is valid;
2. action is known;
3. action belongs to the scope;
4. arguments exactly match the action schema;
5. resource belongs to the scope;
6. approval mode is present.

It returns `ALLOW_AUTO`, `REQUIRE_APPROVAL`, or a specific deny result. `safe_evaluate` converts internal policy exceptions to `DENY_INTERNAL_ERROR`, so uncertainty fails closed.

## Approval binding and resume revalidation

An approval binds these fields:

- run ID;
- exact action;
- exact arguments;
- exact resource;
- current scope hash;
- expiry time.

The binding hash detects mutation. Approval changes the run to `APPROVED`; it deliberately does not call the executor. A separate resume request rechecks the approval status, expiry, binding, run and action match, resource, scope, current user authorization, and current policy result. Any mismatch emits `RESUME_REVALIDATION_FAILED` and executes nothing.

## Run state machine

```mermaid
stateDiagram-v2
    [*] --> CREATED
    CREATED --> PLANNED
    PLANNED --> RUNNING
    RUNNING --> WAITING_APPROVAL
    WAITING_APPROVAL --> APPROVED
    APPROVED --> RUNNING: resume + revalidation
    RUNNING --> COMPLETED
    WAITING_APPROVAL --> REJECTED
    CREATED --> FAILED
    PLANNED --> FAILED
    RUNNING --> FAILED
    APPROVED --> FAILED
    PLANNED --> EXPIRED
    RUNNING --> EXPIRED
    WAITING_APPROVAL --> EXPIRED
    APPROVED --> EXPIRED
```

`REJECTED`, `COMPLETED`, `FAILED`, `EXPIRED`, and `CANCELLED` are terminal. Undefined transitions raise `InvalidRunTransition`.

## Persistence and audit

SQLAlchemy stores serialized Pydantic models in three SQLite tables:

| Table | Content |
|---|---|
| `runs` | Current run, scope, plan, action results, lifecycle state |
| `approvals` | Approval request, decision, exact binding, expiry |
| `audit_events` | Ordered decision and execution events |

Audit retrieval orders by timestamp and insertion ID. The repository enforces scope monotonicity when an existing run is saved.

SQLite and process-local locks are acceptable for a single-process concept-validation deployment. They do not provide a tamper-proof ledger or cross-worker concurrency guarantees.

## Failure handling

- Policy exceptions become deny decisions.
- Executor calls run through `asyncio.wait_for`.
- Timed-out or failed calls transition the run to `FAILED`.
- Execution-token cleanup runs in `finally` and is idempotent.
- Expired runs and approvals cannot resume.
- Rejected approval is terminal.
- A malformed execution call never reaches fake infrastructure.

## Deployment topology

```text
Browser
   |
HTTP :8000
   |
FastAPI process (React static assets + API)
   |
SQLite volume + in-memory fake infrastructure
```

The Docker image uses a Node build stage and a non-root Python 3.12 runtime. GitHub Actions verifies backend, frontend, and container builds. Tagged or manually requested releases publish a container to GHCR; no workflow deploys it to a server.

## Production evolution

Moving beyond concept validation requires deliberate replacements:

| MVP component | Production requirement |
|---|---|
| Deterministic preset planner | LLM gateway with schema-constrained output; keep it outside the trusted computing base |
| String operator identity | Authenticated identity and RBAC from an identity provider |
| SHA-256 approval integrity | Signed or MAC-protected approvals with managed rotating keys |
| Fake infrastructure | Per-action adapters using narrowly scoped, short-lived credentials |
| SQLite audit | Remote append-only audit sink with independent retention and access control |
| Process-local locks | Database-backed concurrency, idempotency keys, and worker leases |
| Code-configured policy | Reviewed, versioned policy bundles with controlled rollout |
| One process | Health checks, metrics, tracing, rate limits, and horizontal deployment |

The key constraint remains unchanged: adding a smarter planner must not increase its authority.

## Related documents

- [README](README.md)
- [Capability matrix](docs/CAPABILITIES.md)
- [Current status](docs/STATUS.md)
- [Security guidance](docs/SECURITY.md)
