# GAR v0.1 Implementation Status

Normative baseline: `GAR-PCS-001@v0.1-r1`, supplied 2026-09-16.

## Implemented milestone

This repository implements the M1 deterministic core on a fake target plus M2
read-only components. The Paper guard, fixed-target host observer, composite
reader, MCP transport, and doctor are compile/unit/fake verified and have been
exercised against one authorized isolated Paper/itzg read-only fixture. This
does not establish complete M0 feasibility, G-07 independent-admin onboarding,
M3 live shadow acceptance, M4 isolated mutation, or mutation beta.

| Path | Responsibility |
|---|---|
| `internal/domain/` | Authority-bearing schemas, canonical digests, stable errors, state axes |
| `internal/policy/` | Release mode and G-01–G-07 mutation gate |
| `internal/store/` | SQLite sessions, frozen intents, approvals, writer ownership, step journal, audit |
| `internal/workflow/` | Fixed ten-tool catalog, fake target, proposal compiler, shadow revalidation, operator service |
| `internal/mcpserver/` | Official SDK Streamable HTTP, bearer-to-scope authentication, Origin and output boundary |
| `internal/runtimeconfig/` | Strict owner-controlled enrollment/artifact/profile configuration |
| `internal/adapters/paper/` | Strict read-only parser for paired GARGuard atomic runtime snapshots |
| `internal/adapters/host/` | Fixed-container Docker/data-root/admission-topology observer and strict atomic snapshot reader |
| `internal/adapters/composite/` | Fail-closed merge of independently sourced host and Paper observations |
| `internal/admission/` | Owner-only fixed config, bounded lease state, runtime acknowledgment, and fail-closed TCP gate |
| `plugins/paper-guard/` | Java/Paper runtime snapshot producer and fail-closed pre-login admission guard; no mutation |
| `cmd/gar/` | Honest status and loopback MCP serving; no mutation listener |
| `cmd/gar-host/` | Separately privileged fixed-target observer; no inbound action API or shell |
| `cmd/gar-gate/` | Fixed-target TCP admission proxy with owner-local open/close/status commands |
| `cmd/garctl/` | Owner-local doctor, agent credential issuance, intent decisions, operation inspection |
| `compatibility.lock` | Exact `LOCAL_PAPER_READ_ONLY` tuple and explicit mutation-blocking gate evidence |

## Invariant enforcement

| Contract | Enforcement evidence |
|---|---|
| INV-01/03/04 | Operation binds exact sealed intent digest, enrollment, and fixed scope; digest mismatch is rejected |
| INV-02 | Ten-tool agent catalog contains no approval operation; approval exists only in `OperatorService` and `garctl` |
| INV-05 | Missing, stale, conflicting, or cross-boot evidence never becomes PASS |
| INV-07 | SQLite ownership query permits one unreleased operation; UNKNOWN blocks subsequent work |
| INV-08 | Step attempts record durable dispatch/effect axes; UNKNOWN cannot silently advance |
| INV-09/12 | Verification is a separate axis; success requires PASS and confirmed maintenance release |
| INV-13 | WAL/FULL settings are read back; authority and step/audit writes are transactional |
| INV-14 | Expiry and revocation epochs are checked at request/use time; mutation defaults closed |
| INV-15 | Proposal schema accepts registry IDs only; MCP rejects unknown authority/path/URL/container fields |
| INV-16 | Status separates the observed read-only success from `NOT_RUN`, failed gates, and unavailable mutation evidence |

INV-06, INV-10, and INV-11 are represented in the fixed S00–S10 intent state
model, but require the M4 host executor and real Paper evidence before they can
be claimed as operationally enforced.

## Local acceptance evidence

The Go tests cover M1 authority, idempotency, journal, UNKNOWN and shadow
cases plus M2 transport checks: missing/wrong credentials, revoked session
epochs, hostile Origin, literal-loopback binding, exactly ten tools with no
approval, strict unknown-field rejection, bounded sensitive output, official
SDK interoperability, reconnect idempotency, and disconnect durability.

The core acceptance suite remains UNIT/FAKE_TARGET, but an additional
`LOCAL_PAPER_READ_ONLY` run verified Paper 26.2 build 124, Java 25, the pinned
itzg image, GARGuard loading, fresh host/runtime snapshots, restart pairing,
all ten authenticated MCP read/propose/query tools, the leased IPv4/IPv6 TCP
gate, Paper runtime acknowledgment, pre-login maintenance state, connection
drop on close, restart-to-closed behavior, Docker admission topology, and gate
binary/command/evidence-mount attribution. A real Paper protocol 776 Login
Start was observed in flight and terminated 13 milliseconds after
owner-local close with zero players before and after. The host-reboot
checkpoint is prepared but has not crossed a real kernel boot, so G-02 remains
`FAIL`. `HOST_RECOVERY`, real plugin transition, mutation, and `BETA` cases
remain `NOT_RUN`. The MCP server is stateless so authority is resolved again
for every HTTP request.

## Deliberately blocked

- Paper and host observation paths passed an authorized isolated read-only run; no independent administrator has completed G-07 onboarding.
- The fail-closed admission gate, Paper login guard, Docker binding observer,
  and real in-flight Minecraft login-close probe exist, but G-02 remains failed
  until the prepared checkpoint is verified across a real host reboot.
- No Docker lifecycle controller, artifact importer, backup engine, or
  filesystem replacer exists.
- No live mutation entry point exists. `StartMutation` returns
  `UNSUPPORTED_ENVIRONMENT` even if tests construct synthetic PASS gates,
  because the M4 executor is absent.
- The Python/React service sandbox is legacy concept-validation code and is not
  evidence for the Paper workflow.

## Next executable milestone

M0 still needs the remaining G-02 host-reboot evidence, a
backup-ready graceful-stop oracle, loader/source attribution, and a real
supported plugin transition for G-03 through G-05. The remainder of M2 is G-07
permission/onboarding evidence from an independent administrator. Mutation
remains blocked until every required M4 gate and `LOCAL_PAPER`/`HOST_RECOVERY`
test passes.
