# Guarded Agent Runner

Guarded Agent Runner (GAR) is a local-first control plane for letting an
untrusted agent inspect a Minecraft Paper server and propose a narrowly scoped
plugin change without giving that agent approval authority, Docker access, a
shell, arbitrary file access, or a live mutation endpoint.

The repository currently contains two deliberately separate products:

1. **GAR v0.1 for Paper**: a Go/MCP read-only and proposal workflow with
   immutable agent scope, owner-local approval, durable SQLite ownership,
   independently sourced runtime evidence, and a fail-closed admission gate.
2. **Legacy service sandbox**: a Python/FastAPI/React demonstration that runs a
   fixed local child process and visualizes approval, revalidation, PID,
   generation, health, and logs in a browser.

The legacy web UI is not the Paper mutation UI, and its approval endpoint is
not an approval channel for GAR v0.1. Evidence from the two modes must not be
combined.

> **Current release boundary:** one exact Paper/itzg tuple has locally verified
> read-only interoperability and admission-barrier evidence. Live plugin
> mutation remains programmatically disabled. `compatibility.lock` records G-02
> `PASS`: real IPv4/IPv6 in-flight login-close and post-reboot fail-closed checks
> passed for the enrolled fixture. Recovery used explicit startup of the existing
> containers; the separate recovered GARGuard build digest is recorded in the lock.
> No further workstation reboot is authorized. G-03 now has an owner-local,
> fixed-target S00–S05 executor in addition to UNIT/FAKE_TARGET coverage. Its
> first `LOCAL_PAPER` run stopped Paper cleanly but failed closed at S03 when
> Docker rejected the shutdown-log query; no backup was created, so G-03 is
> `FAIL`, not `PASS`. This is not production or beta readiness.

## Why GAR exists

Natural-language requests are useful input, but they are not authority. GAR
keeps the following boundary explicit:

```text
request or planner output -> typed proposal -> policy and evidence checks
                                           -> owner-local decision
                                           -> no live mutation in v0.1
```

An agent may influence a registered proposal. It cannot create an approval,
expand its immutable scope, select a filesystem path or container, obtain the
Docker socket, or turn uncertain evidence into permission.

The central capability rule is:

```text
scope(t+1) ⊆ scope(t)
```

A later step may retain or reduce authority. It cannot add another target,
plugin, action, or weaker approval requirement.

## Two request modes are retained

| Mode | Input | Translation | Authority boundary |
|---|---|---|---|
| Human / legacy web flow | A target, one deterministic preset, and generated request text | The legacy deterministic planner converts the preset to three typed service actions | Web approval applies only to the disposable service sandbox |
| Agent / MCP flow | Strict JSON arguments for one of ten registered tools | No second LLM translation is required; the request is already a typed tool call | The agent can read or propose only within its stored immutable session scope |

An LLM may exist outside GAR and choose which MCP tool to call. GAR never treats
that model's prose, reasoning, or tool selection as approval. Unknown fields,
unknown tools, caller-selected authority fields, and malformed arguments fail
closed.

## GAR v0.1 agent contract

The MCP server exposes exactly ten agent-facing tools:

| Tool | Purpose | Side effect |
|---|---|---|
| `inspect_server_identity` | Return the fixed enrollment, support profile, and mutation limitations | Read only |
| `get_health` | Return bounded process, ping, guard, boot, readiness, and maintenance observations | Read only |
| `get_players` | Return player count without names or UUIDs | Read only |
| `get_performance` | Return bounded TPS, MSPT, CPU, memory, and disk observations when available | Read only |
| `get_recent_errors` | Return a bounded page of recent error evidence | Read only |
| `list_plugins` | Return the attributed plugin inventory | Read only |
| `get_recent_changes` | Return principal- and enrollment-scoped intent history | Read only |
| `get_backup_status` | Report live backup evidence unavailable; the S05 foundation is not connected to MCP | Read only |
| `propose_plugin_change` | Compile registered plugin and artifact IDs into an immutable `ChangeIntent` | Proposal only; no dispatch |
| `get_operation` | Return the caller's own intent, operation, or step record | Read only |

There is intentionally no approve, reject, revoke, open-gate, stop-server,
replace-file, restart-container, or shell tool. Owner decisions are local CLI
operations bound to the exact intent ID and full digest:

```bash
go run ./cmd/garctl intent show --db /path/to/gar.db --id <intent-id>
go run ./cmd/garctl intent approve --db /path/to/gar.db \
  --id <intent-id> --digest <full-intent-digest>
go run ./cmd/garctl intent reject --db /path/to/gar.db \
  --id <intent-id> --digest <full-intent-digest>
go run ./cmd/garctl intent revoke --db /path/to/gar.db \
  --id <intent-id> --digest <full-intent-digest>
```

Approval changes durable state only. It does not execute a mutation. The fixed
S00-S10 change workflow is present in the immutable intent and journal. The
S00–S05 coordinator and offline archive engine have UNIT/FAKE_TARGET coverage
and an owner-local fixed-target Paper acceptance command. The first real run
stopped at an honest S03 `UNKNOWN`; it did not execute S04/S05. Artifact
replacement and recovery remain absent. `StartMutation` therefore returns
`UNSUPPORTED_ENVIRONMENT` even if synthetic tests construct passing gates.

## Paper evidence architecture

GAR separates evidence by privilege instead of asking one process to attest to
everything:

```text
Agent
  |
  | loopback MCP + exact Origin + bearer digest
  v
gar serve --------------------------------------------------+
  | reads snapshots only                                   |
  +--> composite adapter <--- GARGuard runtime snapshot     |
  |                         boot/readiness/players/TPS      |
  |                                                        |
  +---------------------- host snapshot <--- gar-host ------+
                              container/image/data/artifacts
                              admission topology/state

Owner CLI -> exact approval / admission lease

Host 127.0.0.1:25565 and [::1]:25565
  -> gar-gate in Paper network namespace
  -> Paper 127.0.0.1:25566
```

### GARGuard

The Paper plugin publishes a bounded atomic runtime snapshot. It reports boot
identity, readiness, player count, performance data, and the runtime admission
state. It does not mutate plugins. Its `AsyncPlayerPreLoginEvent` handler
rejects logins while the admission lease is closed or invalid.

The Go reader treats the snapshot as untrusted data. It rejects symlinks,
oversized input, duplicate or unknown fields, stale or future timestamps,
pairing and generation mismatch, invalid numeric ranges, and conflicting
plugin names.

### Fixed-target host observer

`gar-host` receives one owner-only enrollment file containing a full container
ID, image ID, data-root identity, bootstrap fingerprint, managed plugin slots,
and snapshot path. It observes that target through the Docker Unix API and has
no inbound action API.

For the admission profile it also verifies the gate container's full ID and
image, `network_mode=container:<paper-id>`, read-only root filesystem,
`cap_drop: ALL`, absence of a Docker socket mount, restart policy `no`, and
the exact IPv4/IPv6 loopback port bindings. It also hashes the enrolled host
gate binary and verifies its read-only bind, the fixed entrypoint and
arguments, `no-new-privileges`, and the read-only mirrored config, state, and
runtime mounts. The MCP-serving process receives only the resulting snapshot
and never receives the Docker socket or Paper data-root path.

### Fail-closed admission gate

`gar-gate` is an owner-controlled fixed TCP proxy. Its listener, upstream,
state file, runtime snapshot, pairing ID, and deployment generation all come
from an owner-only config; none can be selected by an agent request.

- Paper listens on port `25566` inside its network namespace and is not
  published directly.
- The gate shares that namespace, listens on `25565`, and is the only service
  published to host `127.0.0.1:25565` and `[::1]:25565`.
- The default is `CLOSED`.
- `OPEN` is an owner-local lease with a hard maximum of 30 seconds.
- Missing, malformed, stale, expired, or cross-generation state is closed.
- The gate also requires GARGuard's fresh runtime snapshot to acknowledge
  `OPEN_READ_ONLY_ALPHA`; writing a lease alone is insufficient.
- Closing the lease terminates existing proxied TCP connections within the
  configured polling interval.
- Restarting either the gate or Paper does not recreate an open lease.

This barrier restricts admission; it does not enable mutation.

## Exact local evidence

`compatibility.lock` records evidence for one tuple only:

| Component | Pinned observation |
|---|---|
| Paper | Minecraft/Paper 26.2, build 124 |
| Java | Eclipse Temurin 25 |
| Container | Digest-pinned `itzg/minecraft-server:java25` |
| Guard | GARGuard 0.1.0 with recorded JAR hash and size |
| Platform | Linux x86_64, Docker Engine/API and Compose versions recorded in the lock |
| Evidence level | `LOCAL_PAPER_READ_ONLY` |
| Mutation | `false` |

The local run verified:

- repeated Paper startup and graceful stop observation;
- paired, fresh GARGuard and host snapshots across restart;
- all ten authenticated MCP tools and absence of an approval tool;
- IPv4 and IPv6 loopback closed/open behavior;
- a maximum 30-second lease plus runtime-guard acknowledgment;
- active TCP connection termination on close;
- real Paper Login Start closure on every enrolled IPv4 and IPv6 binding, with
  the ignored acceptance artifact SHA-256 and live enrollment identity bound in
  `compatibility.lock` to the committed verifier source;
- gate and Paper container restart defaulting closed;
- Docker topology, binding, namespace, rootfs, capability, and mount checks.
- gate binary digest, fixed command, and evidence-mount attribution.

The lock intentionally does not claim that another Paper, Java, image, host,
filesystem, plugin, or configuration tuple is supported.

## Release gates and remaining work

| Gate | Status | What the status means |
|---|---|---|
| G-01 | `PASS` | Exact tuple has reproducible local read-only startup evidence |
| G-02 | `PASS` | Changed kernel boot ID and fresh post-reboot CLOSED/MAINTENANCE, zero-player, exact-topology and dual-stack fail-closed evidence; explicit recovery of existing fixture containers |
| G-03 | `FAIL` | A real approved `LOCAL_PAPER` run passed S00–S02 and cleanly stopped Paper, but shutdown-log evidence returned UNKNOWN at S03; S04/S05 were blocked and no backup was created |
| G-04 | `FAIL` | Runtime artifact source attribution remains unavailable |
| G-05 | `NOT_RUN` | No verified real plugin A-to-B transition |
| G-06 | `NOT_RUN` | No crash-recovery and ambiguous-outcome campaign |
| G-07 | `NOT_RUN` | No independent administrator onboarding and permission validation |

Mutation remains disabled until the required mutation gates pass with real
`LOCAL_PAPER` and `HOST_RECOVERY` evidence. Passing unit tests or editing the
lock file cannot enable it.

## Quick start: verification

Prerequisites:

- Go matching `go.mod`
- Docker Engine with Compose and Buildx
- Anaconda or Miniconda with the `guarded-agent-runner` environment
- Node.js 24 and npm
- `make`

Run the complete repository verification:

```bash
make verify
```

It runs Go tests and vet, race-enabled admission tests, the GARGuard Java tests
and JAR verification in a pinned Gradle container, Python lint and tests, and
the frontend type check and production build.

Useful focused checks:

```bash
go test -race ./...
make admission-verify
make paper-guard-verify
npm --prefix frontend run build
```

## Quick start: synthetic MCP transport

This checks authentication and transport only. The example contains synthetic
enrollment values and therefore cannot provide live Paper evidence.

```bash
install -m 600 examples/mcp-alpha/server-config.example.json /tmp/gar-server.json
go run ./cmd/garctl agent issue --db /tmp/gar.db --config /tmp/gar-server.json \
  --principal local-agent --credentials-out /tmp/gar-credentials.json \
  --token-out /tmp/gar-token
go run ./cmd/garctl doctor --db /tmp/gar.db --config /tmp/gar-server.json \
  --credentials /tmp/gar-credentials.json \
  --allowed-origin http://127.0.0.1:4173
go run ./cmd/gar serve --db /tmp/gar.db --config /tmp/gar-server.json \
  --credentials /tmp/gar-credentials.json --listen 127.0.0.1:8787 \
  --allowed-origin http://127.0.0.1:4173
```

The bearer value is written once to `/tmp/gar-token`; only its SHA-256 digest
is stored in the owner-only credentials mapping. Do not commit either file.

## Quick start: isolated Paper fixture

The fixture is disposable and must not be pointed at an existing server or
player environment. It stores generated state only under
`examples/itzg-paper/data/` and evidence under ignored fixture directories.

Accepting the Minecraft EULA is an owner decision. Set the environment variable
only after acceptance:

```bash
export MINECRAFT_EULA=TRUE
docker compose -f examples/itzg-paper/compose.yaml up -d
docker compose -f examples/itzg-paper/compose.yaml ps
```

The base profile publishes no game or management port. Follow
[`examples/itzg-paper/README.md`](examples/itzg-paper/README.md) to replace all
example enrollment placeholders with independently observed values before
starting `gar-host` or `gar serve` against the real fixture.

### Admission development profile

Prepare owner-only ignored copies of the admission config and gate binary.
The config's state and runtime paths must be clean absolute paths derived from
your checkout. Compose mounts the config directory at that same absolute path:

```bash
FIXTURE_DIR="$(pwd)/examples/itzg-paper"
mkdir -p "$FIXTURE_DIR/evidence/admission"
install -m 600 "$FIXTURE_DIR/admission-config.example.json" \
  "$FIXTURE_DIR/evidence/admission/config.json"
go build -o "$FIXTURE_DIR/evidence/gar-gate" ./cmd/gar-gate

export GAR_ADMISSION_CONFIG="$FIXTURE_DIR/evidence/admission/config.json"
export GAR_ADMISSION_DIRECTORY="$FIXTURE_DIR/evidence/admission"
export GAR_PAPER_RUNTIME_DIRECTORY="$FIXTURE_DIR/data/plugins/GARGuard"
export MINECRAFT_EULA=TRUE

docker compose -f examples/itzg-paper/compose.yaml \
  -f examples/itzg-paper/compose.admission.yaml config
docker compose -f examples/itzg-paper/compose.yaml \
  -f examples/itzg-paper/compose.admission.yaml up -d
```

Before `up`, edit only the ignored owner copy and replace every
`/REPLACE/ABSOLUTE/PATH` placeholder. Do not commit generated config, tokens,
container IDs, runtime snapshots, logs, or evidence.

Operate the lease from the host with the host-visible config path:

```bash
HOST_ADMISSION_CONFIG="$FIXTURE_DIR/evidence/admission/config.json"

go run ./cmd/gar-gate status --config "$HOST_ADMISSION_CONFIG"
go run ./cmd/gar-gate open --config "$HOST_ADMISSION_CONFIG" \
  --lease 30s --reason "owner-local read-only test"
go run ./cmd/gar-gate close --config "$HOST_ADMISSION_CONFIG" \
  --reason "test complete"
```

Keep the lease short, confirm GARGuard has acknowledged the same generation,
and close it immediately after the test. The admission profile is development
evidence, not a public server configuration.

## Legacy browser sandbox

The browser UI demonstrates the earlier human-input flow with a fixed local
process. It displays the real child PID, generation, health, supervisor logs,
approval state, revalidation result, and ordered audit trail.

```bash
conda env create -f environment.yml
conda activate guarded-agent-runner
make install
docker compose up --build
```

Open <http://127.0.0.1:8000>. The Compose services are:

- `runner`: FastAPI, policy, approval, executor, audit API, SQLite, and React UI;
- `sandbox-service-a`: a narrow supervisor for one disposable child process.

The runner does not receive the Docker socket. The sandbox exposes only
status, bounded logs, restart, and demo reset on the internal Compose network.
Reset is a UI demonstration control, not an agent capability.

Legacy typed actions are limited to:

| Action | Arguments | Effect |
|---|---|---|
| `service_status` | `service: string` | Read current state |
| `read_log` | `service: string`, `lines: 1..1000` | Read bounded logs |
| `restart_service` | `service: string` | Replace the fixed child process after policy and any required approval |

Four in-memory NGINX, PostgreSQL, MySQL, and Redis scenarios remain available
when the app is started without the Compose sandbox. They are deterministic
policy demonstrations, not real infrastructure adapters.

## Security properties

- MCP binds to a literal loopback address, uses stateless official-SDK
  Streamable HTTP, validates one exact Origin, reauthenticates every request,
  rate-limits each session, rejects unknown JSON fields, and bounds requests
  and responses.
- Bearer files, SQLite databases, observer configs, and admission configs must
  be regular owner-only non-symlink files owned by the current OS user.
- SQLite uses WAL, `synchronous=FULL`, foreign keys, one unreleased writer per
  enrollment, principal/target-scoped idempotency, and durable UNKNOWN state.
- Missing or conflicting evidence is `UNKNOWN`/unavailable and blocks progress;
  it is never converted to success.
- Approval is bound to the full canonical RFC 8785 intent digest. Resume and
  shadow checks revalidate evidence instead of trusting an earlier decision.
- No component accepts an agent-provided shell command, executable, URL,
  container ID, Docker socket, filesystem path, listener, or upstream.

See [Security](docs/SECURITY.md) for the full threat model and limitations.

## Intentional non-capabilities

- No live Paper plugin mutation, artifact replacement, rollback, or recovery
- No arbitrary shell, subprocess, SSH, Kubernetes, Terraform, cloud, or
  caller-selected filesystem interface
- No agent-visible approval or admission-control tool
- No successful real stop-to-backup acceptance evidence; the owner-local route
  failed closed at S03 and is not exposed through MCP
- No runtime artifact source attribution
- No authenticated multi-user operator UI, RBAC, signed approval, or remote
  immutable audit sink
- No unattended deployment or public-server operating mode
- No claim of compatibility outside the exact tuple in `compatibility.lock`

## Repository map

| Path | Responsibility |
|---|---|
| `cmd/gar/` | Status and authenticated loopback MCP serving |
| `cmd/garctl/` | Owner-local doctor, credential issuance, intent decisions, and operation inspection |
| `cmd/gar-host/` | Fixed-target Docker/data-root observer with no inbound action API |
| `cmd/gar-gate/` | Fixed-target, leased, fail-closed TCP admission proxy |
| `internal/domain/` | Authority-bearing schemas, state axes, canonical digests, and stable errors |
| `internal/policy/` | Release mode and G-01-G-07 gate evaluation |
| `internal/store/` | SQLite sessions, frozen intents, approval, ownership, journal, and audit |
| `internal/workflow/` | Ten-tool service, registry, proposal compiler, and shadow revalidation |
| `internal/admission/` | Admission config, state lease, runtime acknowledgment, and TCP gate |
| `internal/adapters/paper/` | Strict GARGuard runtime snapshot reader |
| `internal/adapters/host/` | Docker, data-root, artifact, and admission topology observer |
| `internal/adapters/composite/` | Fail-closed merge of independent Paper and host evidence |
| `plugins/paper-guard/` | Paper runtime snapshot and pre-login admission guard |
| `examples/itzg-paper/` | Disposable, digest-pinned Paper fixture and admission overlay |
| `compatibility.lock` | Exact tuple, evidence level, gate status, and mutation-disabled record |
| `guarded_agent_runner/` | Legacy FastAPI policy, approval, executor, audit, and sandbox adapter |
| `frontend/` | Legacy React sandbox UI and live process evidence panel |
| `tests/` | Legacy Python security, lifecycle, API, and sandbox tests |
| `.github/workflows/` | CI, secret scanning, and tagged container publication |

## Documentation

| Document | Purpose |
|---|---|
| [Architecture](ARCHITECTURE.md) | Trust boundaries, evidence sources, state machines, and data flow |
| [GAR v0.1 implementation](docs/GAR_V01_IMPLEMENTATION.md) | Invariant and acceptance mapping |
| [Current status](docs/STATUS.md) | Evidence-backed implementation and validation status |
| [Capability matrix](docs/CAPABILITIES.md) | Implemented controls and explicit non-capabilities |
| [Security](docs/SECURITY.md) | Threat model, assumptions, credential boundary, and production gaps |
| [Paper fixture](examples/itzg-paper/README.md) | Safe isolated fixture enrollment and operation |
| [GitHub settings](docs/GITHUB_SETTINGS.md) | Repository protection and delivery checklist |

## CI and delivery

GitHub Actions validates Python, Go, GARGuard, the frontend build, and the
container. A separate workflow runs full-history Gitleaks. Tagged or manually
dispatched releases publish an SBOM- and provenance-enabled image to GHCR.

No workflow deploys to a server, opens the admission lease, or touches a
Minecraft environment. Publishing an artifact is separate from an operator's
decision to deploy it.
