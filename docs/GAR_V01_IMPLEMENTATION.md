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
owner-local close with zero players before and after. G-02 subsequently passed
HOST_RECOVERY verification using the existing real reboot and explicit startup
of the original fixture containers. Real plugin transition, mutation and BETA
remain NOT_RUN. The MCP server is stateless so authority is resolved again
for every HTTP request.

## G-03 foundation: implemented, real acceptance NOT_RUN

The continuation starts from `744922f8ba87f6e51b4130f50a62785c0e4fd70c` on
`feat/gar-v0.1`. M1/M2, immutable scope and intent, owner-only approval,
SQLite ownership/journal, shadow validation, ten authenticated MCP tools and
the read-only Paper/admission adapters were already present.

The owner prohibited further workstation reboots. The existing reboot was
verified without issuing another reboot: the original checkpoint at
`2026-09-17T07:56:22.394854243Z` crossed from kernel boot ID
`a47de622-856c-45e8-8907-1d395e3244fa` to
`b87e66b7-3e35-40cd-9233-3c810b4deed4`. The unmodified VerifyHostReboot harness,
built from a detached clean tracked checkout of `744922f`, returned PASS at
`2026-09-17T08:41:43.075074519Z`. G-02 therefore changed FAIL → PASS. The
original container identities were started explicitly, consistent with their
restart policy `no`; fresh host/Paper observations proved CLOSED admission,
matching enrollment/generation/data-root/topology, MAINTENANCE, zero players,
and gate-driven close on both IPv4 and IPv6. This is owner-assisted recovery,
not proof of unattended container startup.

The preceding real IPv4/IPv6 Login Start probes passed with protocol 776,
zero players and 11 ms close latency. The combined ignored evidence SHA-256 is
`6fcaf31080d8caf7446f6b3f8ecce72c6431347e7812e687818ee819fec9bb89`.
The lock binds it to enrollment, generation, container, data root, Paper tuple,
pairing, the complete endpoint set and source commit. The required Java test
build had rebuilt GARGuard from unchanged source, producing SHA-256
`021372d926a2e9ff703f188db2cd6598766617f3215e10a8acdef74fc9dfadac`.
That recovered artifact is recorded separately from the historical G-01 guard
artifact; the artifact registry is unchanged. G-02 does not establish G-04
source attribution or validate a plugin replacement transition.

`internal/domain/backup.go`, `internal/workflow/foundation.go`,
`internal/backup/` and `internal/store/backup.go` implement the offline
foundation. `FoundationTarget` is an owner-installed contract, currently
exercised only by deterministic FAKE_TARGET tests. There is no production
implementation of this stop/maintenance dispatch interface, and no live
execution command, HTTP route or MCP tool is connected to it. The existing
read-only host observer rejects stopped containers and cannot supply the
offline evidence contract. Real G-03 remains NOT_RUN; these tests cannot
establish that a real Paper process stopped safely.

The stop oracle distinguishes NOT_REQUESTED, DISPATCH_POSSIBLE in the durable
journal, STOPPING, STOPPED_CONFIRMED, FAILED and UNKNOWN. Confirmation requires
fresh lifecycle evidence, a zero exit without OOM kill, terminal runtime and
graceful termination evidence, the exact container/runtime boot, and a receipt
correlated to the operation, step and dispatch time. A successful dispatch
response alone is insufficient. Observation polls use deadlines, not a fixed
sleep. Timeouts after possible dispatch become UNKNOWN. Observed stopped state
without attribution remains EXPECTED_STATE_OBSERVED + UNATTRIBUTED and blocks.

| Step | Dispatch and effect | Durable evidence and reconciliation | Failure behavior |
|---|---|---|---|
| S00 claim | Local acknowledgement of the independently approved writer | Exact intent digest, operation and execution epoch; reuse the existing claim | Missing/revoked approval or expired start blocks; no new claim |
| S01 revalidate | Read-only observation, journaled as a correlated local check | Target/generation/policy, source artifact/hash, inventory/config and boot | Missing/stale observation → PRECONDITION_UNAVAILABLE; changed state → INTENT_STALE |
| S02 maintenance | Prepare and mark dispatch possible before closing admission | Correlated close receipt plus fresh MAINTENANCE and zero-player acknowledgement | Lost response/acknowledgement → UNKNOWN; retain ownership |
| S03 graceful stop | Prepare and mark dispatch possible before exactly one stop request | Correlated lifecycle/runtime/termination evidence and the fresh pre-stop zero-player snapshot | Ambiguous dispatch/timeout → UNKNOWN, no retry; abnormal exit → NEEDS_INTERVENTION |
| S04 offline revalidate | Read-only proof after confirmed stop | BackupReadyEvidence checks exact target/source/root, closed admission, stopped process, filesystem root and absence of a conflicting writer | Unknown facts block as PRECONDITION_UNAVAILABLE; changed target/source blocks as INTENT_STALE; known competing writer → TARGET_BUSY |
| S05 backup | Prepare and mark dispatch possible before reserving/writing an archive | CREATING record, file/directory sync, SHA-256 reread; VALID metadata and correlated S05 completion commit in one transaction | Partial/orphan stays CREATING; unresolved dispatch → UNKNOWN; never silently adopt or overwrite artifacts |

Every step begins as NOT_DISPATCHED / PROVEN_NOT_APPLIED. Revocation is checked
again in the dispatch transaction. The execution budget is bounded by the
approved intent and the first durable step time. After S05 the operation stays
EXECUTING with ownership retained and verification NOT_STARTED. The coordinator
ends there, and the store explicitly rejects S06–S10 preparation. StartMutation
continues to reject even synthetic all-PASS profiles.

BackupReadyEvidence preserves the historical zero-player observation, which
must have been fresh at stop dispatch. On recovery, offline observations must
be fresh again and agree with the exact approved state. The engine reads only
owner-enrolled roots and the fixed source artifact path; operation inputs contain
IDs, never filesystem paths. It independently checks root identity and source
artifact bytes before writing, and revalidates the offline target and source
after writing. The v1 tar recipe excludes top-level logs, cache and
temporary-sockets. It bounds bytes and entries, rejects symlinks, hardlinked
files and special files, confines reads with os.Root, and uses no-clobber atomic
rename on Linux. It implements no extraction, restore or online snapshot.

A backup becomes VALID only after archive completion, file sync, atomic
finalization and directory sync, known size, SHA-256 calculation and matching
reread, and durable metadata commit. This foundation persists explicit
FAKE_TARGET evidence levels and rejects live-evidence reservations. The record binds backup/schema/target,
enrollment/generation/container/data-root/Paper tuple, runtime boot, exact
intent/digest/operation/step, source inventory/config/artifact identities,
recipe, timestamps, OFFLINE mode, size/hash and readiness evidence.
`Engine.Inspect` rechecks the stored target binding and current artifact digest.
`garctl backup show --db <owner-db> --id <backup-id>` exposes durable metadata
after reopen, explicitly labeling current artifact integrity NOT_CHECKED.

| Injected boundary | Verified result |
|---|---|
| Prepared S03, before dispatch | Store reopen retains NOT_DISPATCHED / PROVEN_NOT_APPLIED; safe continuation dispatches once |
| S03 dispatch possible, before acknowledgement | Store reopen yields UNKNOWN on recovery; no second stop |
| S03 proven complete, before backup | Reopen resumes only after fresh offline validation; source drift blocks and no archive starts |
| Backup temp file creation | Partial artifact and CREATING record remain invalid after reopen |
| Archive rename, before metadata commit | Orphan final file remains CREATING; no adoption or overwrite |
| Completed backup metadata commit | VALID record, S05 acknowledgement and reread integrity survive reopen |
| Stop response loss / timeout | UNKNOWN holds ownership; backup never begins |
| Unattributed stop / abnormal exit | Blocking unattributed evidence / NEEDS_INTERVENTION respectively |
| Archive tamper, resource limit, unsafe links, source/target drift | No valid backup; digest tamper after completion also fails inspection |

These are UNIT/FAKE_TARGET tests using temporary real files and SQLite,
not LOCAL_PAPER or HOST_RECOVERY acceptance. The next smallest milestone is
reviewing this S05 foundation, then implementing a fixed-target owner-side
stop/offline observer and demonstrating it against an independently approved
isolated Paper target with every required source predicate available. Source
attribution G-04, transition G-05, real ambiguous mutation G-06, external-admin
G-07, and S06–S10 remain outside this run.

## Deliberately blocked

- Paper and host observation paths passed an authorized isolated read-only run; no independent administrator has completed G-07 onboarding.
- G-02 passed for the enrolled owner-recovered fixture only. No unattended
  recovery, other host tuple, or further workstation reboot is implied.
- No live Docker lifecycle controller, artifact importer, or
  filesystem replacer exists.
- No live mutation entry point exists. `StartMutation` returns
  `UNSUPPORTED_ENVIRONMENT` even if tests construct synthetic PASS gates,
  because the M4 executor is absent.
- The Python/React service sandbox is legacy concept-validation code and is not
  evidence for the Paper workflow.

## Next executable milestone

M0 still needs real G-03 stop/backup evidence, loader/source attribution,
and a real supported plugin transition for G-04 through G-05. The remainder of M2 is G-07
permission/onboarding evidence from an independent administrator. Mutation
remains blocked until every required M4 gate and `LOCAL_PAPER`/`HOST_RECOVERY`
test passes.
