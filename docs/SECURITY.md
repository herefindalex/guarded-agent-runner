# Guarded Agent Runner Security Guidance

Guarded Agent Runner is a concept-validation MVP. Its controls demonstrate how an untrusted planner can be separated from infrastructure authority, but they do not make the current fake-infrastructure implementation a production operations platform.

## Security objective

The primary objective is to prevent proposal text or planner output from becoming authority. A request may influence a typed plan. It cannot add credentials, create an approval, mint an execution token, weaken policy, or invoke an unexposed action.

## Threat model

Assume an attacker can:

- control the operator request text;
- fully compromise planner output;
- request an unknown tool or malformed arguments;
- target a service outside the compiled scope;
- modify or replay approval data;
- race or delay a resume request;
- cause the policy service or executor to fail;
- revoke current user authorization before resume;
- attempt to expand a persisted capability scope.

The MVP trusts:

- the capability compiler and canonical scope hash implementation;
- the policy engine and action schemas;
- approval creation and resume revalidation;
- execution-token creation and the guarded executor;
- state-transition rules;
- the application process and SQLite host.

An attacker with direct process memory or database write access can damage availability and audit integrity. That threat is outside the current boundary.

## Implemented controls

### Narrow capability scope

Each run contains one selected service and three possible typed actions. Repository updates must preserve `scope(t+1) ⊆ scope(t)`. A run cannot add another service or weaken required approval to automatic.

### Fail-closed policy

Missing or invalid scope, unknown actions, malformed arguments, out-of-scope resources, and policy exceptions all deny execution. A policy error does not fall back to automatic authorization.

### Exact approval

Approval binds the run ID, action, arguments, resource, scope hash, and expiry. Approval changes workflow state only. Resume independently revalidates current policy and authorization before the executor receives a token.

### Bounded executor

The executor recognizes only `service_status`, `read_log`, and `restart_service`. It validates a short-lived token bound to the current run, action, and resource. It has no subprocess, shell, SSH, filesystem, Kubernetes, Terraform, or cloud SDK interface.

### Timeout and cleanup

Execution is time-bounded. Cleanup occurs in a `finally` block and is idempotent. Timeout or execution failure transitions the run to a terminal failure.

### Observable decisions

Policy decisions, approval state, resume revalidation, skips, executor start/success/failure, and terminal state are recorded as ordered audit events.

## Credential boundary

The MVP needs no infrastructure credentials. Do not add credentials to request text, planner prompts, fake service logs, tests, screenshots, issues, or repository files.

A production adapter should:

1. retrieve a narrowly scoped credential only after successful authorization;
2. mint it for one action and one resource;
3. enforce a short expiry;
4. keep it out of the planner, UI response, audit metadata, and persistent run model;
5. revoke or allow it to expire after execution.

GitHub Actions should remain credential-free except for GitHub's job-scoped token used to publish an image. No workflow should receive infrastructure secrets unless a separately reviewed deployment design requires them.

## Approval limitations

The current binding uses deterministic SHA-256 to detect mutation. It is not a signature and does not establish who approved the action. Production requires authenticated operator identity, authorization checks, signed or MAC-protected approvals, protected keys, rotation, and replay prevention across workers.

## Persistence limitations

SQLite stores application state and audit events on one host. It does not provide:

- immutable or independently retained audit evidence;
- protection against a database administrator rewriting records;
- distributed transactions or worker leases;
- high availability;
- cross-region retention.

Production should send audit events to a separately controlled append-only sink and use database-backed concurrency plus idempotency keys.

## UI and API limitations

- `user_id` and approval `actor` are strings supplied by the caller, not authenticated identities.
- The app has no session management, RBAC, CSRF protection, rate limiting, or tenant isolation.
- Local-network binding exposes plain HTTP unless a separate trusted proxy provides TLS.
- OpenAPI is enabled by default.

Keep the MVP on a trusted development network. Do not expose it directly to the public Internet.

## Repository protections

- Local databases, Python caches, frontend dependencies, and build output are ignored.
- CI runs lint, tests, frontend build, and container build without infrastructure credentials.
- `secret-scan.yml` checks out full available history and runs Gitleaks.
- Container publication uses only the GitHub job token and grants `packages: write` only in the release workflow.

Workflow presence is not proof that repository-level secret scanning, push protection, branch protection, or hosted runs are enabled. Track those separately in [GITHUB_SETTINGS.md](GITHUB_SETTINGS.md).

## Production readiness checklist

- [ ] Authenticate operators through a trusted identity provider.
- [ ] Enforce RBAC and separation of requester and approver where required.
- [ ] Sign approval attestations and prevent replay.
- [ ] Replace fake infrastructure with reviewed per-action adapters.
- [ ] Use short-lived, resource-scoped credentials.
- [ ] Move policy to reviewed and versioned bundles.
- [ ] Add database-backed concurrency and idempotency.
- [ ] Export audit events to an independent append-only system.
- [ ] Add TLS, Origin/CSRF controls, rate limiting, and secure sessions.
- [ ] Add metrics, tracing, alerts, backup, and recovery procedures.
- [ ] Threat-model each new action before adding it to the executor.

## Vulnerability reporting

Do not open a public issue containing credentials, private infrastructure details, or an actionable exploit. Enable GitHub private vulnerability reporting before publishing the repository, then use it for sensitive reports.

Related: [architecture](../ARCHITECTURE.md), [capability matrix](CAPABILITIES.md), and [current status](STATUS.md).
