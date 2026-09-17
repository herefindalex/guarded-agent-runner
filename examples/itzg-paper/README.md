# Isolated Paper/itzg read-only fixture

This is the disposable fixture used for the repository's exact
`LOCAL_PAPER_READ_ONLY` evidence. It pins the inspected multi-platform itzg
`java25` image digest and Paper 26.2 build 124. The observed tuple is recorded
in `compatibility.lock`: G-01 passes for reproducible read-only startup, G-02
and G-04 fail closed, and the remaining mutation gates are `NOT_RUN`.

This evidence proves only the listed local read-only interoperability. It does
not establish mutation compatibility, backup/recovery correctness, a verified
plugin transition, external-admin onboarding, or support for other Paper,
Java, image, host, or filesystem tuples.

The fixture publishes no game or management ports and has `restart: "no"`.
Starting it downloads and runs third-party server software and requires the
owner to accept the Minecraft EULA. Do not set `MINECRAFT_EULA=TRUE` unless the
owner has explicitly accepted the EULA and authorized this disposable test.

Build the guard without starting Paper:

```bash
make paper-guard-verify
```

After an authorized start, enrollment values must be replaced with independently
observed full container/image/data-root identities and an absolute snapshot
path. Copy the resulting config to an owner-only file; do not edit the example
in place and treat it as authoritative.

The host-side observer is a separate process because only it may read the
fixed Docker socket and Paper data root. First copy
`host-enrollment.example.json` to an owner-only file, fill its fixed container
ID and paths, create the snapshot output directory, and derive the remaining
pins without exposing Docker inspect environment values:

```bash
go run ./cmd/gar-host enrollment-facts --config /absolute/owner-only/host-enrollment.json
```

Copy `host-observer.example.json` to a separate owner-only file and replace
every placeholder with those independently inspected values. Ensure its
snapshot path stays outside `data/`. The MCP-serving
`gar` process receives only that snapshot path and must run as an identity that
cannot access the Docker socket.

Both publishers replace snapshots with an atomic rename. If GAR runs in a
container, bind-mount the containing observation directories read-only, not the
individual JSON files; a single-file bind remains attached to the old inode and
will become stale. Keep the host snapshot in the dedicated
`evidence/observation/` directory so no credentials or enrollment config are
included in that mount. The Paper-side `plugins/GARGuard/` directory may be
mounted read-only; GAR itself still opens only the fixed snapshot path.

Once enrolled, the fixed target can be observed with either:

```bash
go run ./cmd/gar-host once --config /absolute/owner-only/host-observer.json
go run ./cmd/gar-host serve --config /absolute/owner-only/host-observer.json
```

Neither command accepts a container, path, URL, shell command, or action from
an agent. All authority-bearing values come from the owner-only config.

## Admission barrier development profile

`compose.admission.yaml` adds the owner-controlled `gar-gate` TCP barrier
without enabling plugin mutation. Paper moves to unexposed port 25566 in its
network namespace; the gate exclusively owns published port 25565. Both IPv4
and IPv6 host mappings are loopback-only. The gate accepts only a fixed
loopback upstream from owner-only configuration.

The gate defaults closed. An open state is a maximum 30-second owner-local
lease. A missing, malformed, stale, expired, or cross-generation state closes
new connections, and a transition to closed terminates existing proxied
connections within the configured polling interval. Restarting without a
fresh lease therefore remains closed.

Keep `deployment_generation` identical in the owner copies of the Paper guard,
admission, host observer, and GAR server configs. Increment it deliberately
when reenrolling a replacement deployment; never mix evidence across values.

GARGuard reads the same state independently, rejects player pre-login while it
is closed, and publishes `OPEN_READ_ONLY_ALPHA` only for a fresh matching
lease. The gate requires that runtime acknowledgment before proxying. The
fixed-target host observer verifies the gate's container/image identity,
shared Paper network namespace, exact loopback bindings, read-only rootfs,
dropped capabilities, restart policy, and absence of a Docker socket mount.

The profile locally passed IPv4/IPv6 closed/open checks, bounded lease and
runtime acknowledgment, active TCP connection drop on close, gate/Paper
restart-to-closed checks, and a real Paper protocol Login Start connection
terminated on close with zero players. Host-reboot verification remains
pending, so G-02 must remain `FAIL` until that complete path is demonstrated.

## G-02 acceptance harness

Copy `g02-acceptance.example.json` into an ignored owner-only directory and
replace every placeholder from the owner-controlled admission and GAR server
configs. The harness rejects endpoints that do not match the fixed admission
listener and rejects identities that do not match the GAR enrollment.

```bash
chmod 700 /absolute/owner-only/g02-directory
chmod 600 /absolute/owner-only/g02-directory/config.json
go run ./cmd/gar-g02-verify minecraft-login-close \
  --config /absolute/owner-only/g02-directory/config.json
go run ./cmd/gar-g02-verify host-reboot-prepare \
  --config /absolute/owner-only/g02-directory/config.json
```

The first command requires a fresh owner-controlled host observation whose
container, generation, gate identity, and complete published-binding set match
the enrollment. It then discovers the exact Paper protocol through every
configured IPv4 and IPv6 gate binding, sends a real Login Start on each one,
closes admission, requires every in-flight connection to terminate, and
requires a fresh zero-player `MAINTENANCE` runtime snapshot. The second command
records the current kernel boot ID only after the same live topology and closed
gate checks pass. It does not reboot the host. After an explicitly authorized
real reboot, run:

```bash
go run ./cmd/gar-g02-verify host-reboot-verify \
  --config /absolute/owner-only/g02-directory/config.json
```

Only a changed kernel boot ID plus post-checkpoint host and Paper observations,
the exact enrolled gate topology, and an immediate gate-driven close on every
published binding can produce `HOST_RECOVERY` PASS evidence. Connection refusal,
timeout, a stale snapshot, or a container restart cannot replace this real
host-reboot observation.
