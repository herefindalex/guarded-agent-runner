# Guarded Agent Runner Security Guidance

Guarded Agent Runner is a concept-validation MVP. Its controls demonstrate how an untrusted planner can be separated from infrastructure authority, but the fixed local process sandbox is not a production operations platform.

## GAR-PCS-001 M1 and M2 read-only boundary

The MCP alpha uses the official Go SDK in stateless mode so every HTTP request
must reauthenticate. Bearer digests map to immutable SQLite scopes; the server
requires a literal loopback listener, checks browser Origin against one exact
configured origin, rejects unknown tool fields, and bounds request and response
sizes. Credential and SQLite files must be regular owner-only non-symlinks
owned by the current OS user. Loopback is not treated as authentication.

GARGuard writes a bounded atomic runtime snapshot and never exposes player
names or UUIDs. The Go adapter treats that file as untrusted: it rejects
symlinks, oversized input, unknown or duplicate fields, pairing mismatch,
future timestamps, stale evidence, invalid numeric ranges, and conflicting
plugin names. This is not proof against a malicious plugin that already owns
the Paper JVM, and it is not host/container or artifact attribution evidence.

Host/container/artifact evidence comes from a separate fixed-target `gar-host`
process. It rejects lifecycle and startup-writer drift, hashes only enrolled
plugin slots, and publishes an atomic snapshot. The MCP frontend never receives
its Docker socket or data-root path.

The admission profile moves Paper to unexposed port 25566 and gives published
loopback port 25565 exclusively to `gar-gate`. The gate accepts only a fixed
loopback upstream and a maximum 30-second owner-local lease. It also requires a
fresh matching GARGuard runtime acknowledgment, so the lease file alone cannot
open admission. Missing, malformed, stale, expired, or cross-generation state
is closed; closing terminates existing proxied TCP connections. GARGuard also
rejects player pre-login while its paired admission state is closed or invalid.
The host observer validates the gate container/image, shared Paper network
namespace, exact IPv4/IPv6 loopback bindings, read-only rootfs, dropped
capabilities, restart policy, `no-new-privileges`, absence of a Docker socket
mount, the enrolled gate binary digest and read-only bind, the fixed command,
and read-only mirrored config/state/runtime mounts.

The Paper product direction currently includes the M1 fake-target Go core and M2 read-only components. The agent catalog has ten read/propose/query tools and no approval tool. Approval, rejection, and revocation are owner-local `garctl` operations bound to the exact full intent digest. The SQLite journal requires a regular owner-only non-symlink file and reads back WAL/FULL settings; it rejects unsafe permissions instead of silently changing them.

Live Paper mutation is not available. `compatibility.lock` records one exact
`LOCAL_PAPER_READ_ONLY` tuple with G-01 PASS, plus G-02 HOST_RECOVERY PASS.
The existing host reboot was verified after explicitly starting only the
original enrolled fixture containers, with admission still CLOSED. Fresh
MAINTENANCE, zero-player, exact-topology and IPv4/IPv6 gate-close observations
passed. No further workstation reboot is authorized. The rebuilt guard artifact
digest is recorded separately from the historical G-01 artifact; this does not
prove artifact attribution or unattended startup. G-04 fails because runtime source attribution
is unavailable. G-03/G-05/G-06/G-07 remain `NOT_RUN`, and the mutation entry point returns
`UNSUPPORTED_ENVIRONMENT` even when a test constructs synthetic PASS gates.
The offline backup foundation has UNIT/FAKE_TARGET coverage and does not expose
a live dispatch route. Stop confirmation requires independently observed lifecycle
and terminal runtime evidence with operation/step attribution. Possible dispatch
with unknown outcome retains writer ownership and blocks forward execution.
Backup partials and orphan archives remain invalid; VALID metadata and S05
completion commit atomically only after fsync, finalization and digest reread.
Source/destination paths come from owner configuration, never an agent request.
S06–S10 preparation is explicitly disabled. Real stop/backup acceptance, artifact
replacement, recovery, and independent-admin onboarding remain later milestones.

The FastAPI/React approval UI described below is legacy service-sandbox code. It is not an operator approval channel for GAR-PCS-001 and must not be exposed to an agent as proof of the Paper security model.

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

Approval binds the run ID, action, arguments, resource, scope hash, expiry, and the last authoritative service status, PID, and generation when available. Approval changes workflow state only. Resume independently revalidates current policy, authorization, and live service preconditions before the executor receives a token. A changed precondition produces terminal `STALE` with `STALE_PRECONDITION`; no restart is issued.

### Bounded executor

The executor recognizes only `service_status`, `read_log`, and `restart_service`. It validates a short-lived token bound to the current run, action, and resource. It has no arbitrary subprocess, shell, SSH, filesystem, Kubernetes, Terraform, cloud SDK, Docker socket, or caller-selected URL interface.

### Fixed Docker sandbox

The Compose demo runs `sandbox-service-a` on the internal Compose network. Its supervisor manages one real child HTTP process and exposes four narrow endpoints:

- `GET /status` returns health, PID, and generation;
- `GET /logs` returns bounded supervisor and child logs;
- `POST /restart` replaces the child process and starts the new generation healthy;
- `POST /reset` replaces the child process and starts the new generation unhealthy.

The runner adapter is fixed to `service-a` and the configured internal sandbox base URL. It cannot select an arbitrary host, path, method, or action. The browser does not access the sandbox container directly; it polls the runner's `/sandbox` proxy. The runner exposes the reset proxy only when `DEMO_MODE=true`. Reset is a demonstration control for repeating the scenario, not an agent capability and not part of the guarded executor action set.

Neither Compose service mounts the Docker socket. The sandbox does not expose a shell or general-purpose command endpoint. These constraints keep the demo meaningful, but they do not make the child process or internal HTTP protocol suitable for production workloads.

### Timeout and cleanup

Execution is time-bounded. Cleanup occurs in a `finally` block and is idempotent. Timeout or execution failure transitions the run to a terminal failure.

### Observable decisions

Policy decisions, approval state, resume revalidation, skips, executor start/success/failure, and terminal state are recorded as ordered audit events.

## Credential boundary

The MVP needs no infrastructure credentials. Do not add credentials to request text, planner prompts, sandbox logs, tests, screenshots, issues, or repository files.

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
- With `DEMO_MODE=true`, any caller that can reach the runner API can reset the sandbox target through `/sandbox/reset`.
- Local-network binding exposes plain HTTP unless a separate trusted proxy provides TLS.
- OpenAPI is enabled by default.

Keep the MVP and its Compose ports on a trusted local development machine or network. Do not expose either service directly to the public Internet.

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
- [ ] Replace the fixed local sandbox and test fake with reviewed production per-action adapters.
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
