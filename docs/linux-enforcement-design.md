# Linux Enforcement Design (pre-release)

## Status

This document defines the next implementation boundary for JICloud AI Antiva.
It is a design and test contract, not a claim that network traffic is blocked
in the current release.

**Current release:** observe and audit selected AI processes and established
external IPv4 TCP connections.

**Target release:** enforce an egress policy only for explicitly supervised AI
runtimes, with a tested rollback path. Unsupervised host traffic must not be
modified.

## Security objective

Prevent an AI runtime under Antiva supervision from making an unapproved
outbound connection or transferring data to an unapproved destination, while
avoiding accidental disruption to Ollama, Nightshift, Bonsai, TTS, SSH, DNS,
package updates, and unrelated user applications.

This is narrower than a general-purpose firewall. It does not promise to stop:

- malicious behavior inside a compromised kernel or privileged process;
- traffic that bypasses the supported enforcement hook;
- covert channels over unsupported protocols until those protocols are covered;
- data already exposed to a trusted destination;
- a user who deliberately disables the guard with sufficient privileges.

## Supported first slice

The first enforcement slice will cover only:

- Linux hosts using cgroup v2;
- processes launched through an Antiva-managed service or scope;
- outbound TCP `connect()` for IPv4 and IPv6;
- destination IP and port policy;
- default-deny mode only when the supervised runtime has an explicit policy;
- audit events for policy load, connection decision, enforcement action, and
  rollback.

The first slice will **not** claim to cover UDP, DNS, raw sockets, forwarded
traffic, inbound server traffic, containers outside the managed cgroup, or
arbitrary already-running PIDs. Those are separate milestones.

## Why cgroups, not PID polling

A PID list is an observation aid, not a reliable enforcement identity. PIDs are
reused, children may fork, and a process can open a socket between polls. The
enforcement identity must be a dedicated cgroup owned by the Antiva service
launcher. The policy attaches to that cgroup and follows descendants without
trying to race process creation.

The existing `/proc` monitor remains useful for visibility and diagnostics, but
it must not be presented as the enforcement mechanism.

## Enforcement architecture

### 1. Managed runtime launcher

Introduce an opt-in launcher for supported runtimes:

```text
antiva-run --profile qwen-local -- ollama ...
antiva-run --profile nightshift -- /path/to/nightshift_server ...
```

The launcher will:

1. validate the profile and policy before starting the child;
2. create or enter a dedicated cgroup v2 scope;
3. load the policy in preview mode first;
4. start the child only after the policy is valid;
5. keep the child in the supervised cgroup, including descendants;
6. emit a start/stop and policy-version audit event.

Existing services must not be silently moved into a cgroup. Migration is an
explicit operator action with a dry-run and rollback command.

### 2. Kernel enforcement hook

The implementation should use a cgroup-scoped Linux hook for outbound
connection attempts (eBPF cgroup `connect4`/`connect6` is the preferred
candidate). The hook must make a decision before the connection is established.
A userspace polling loop may report state, but it must not be the only blocker.

The hook must be a small, auditable component with:

- an immutable policy generation number;
- atomic policy replacement;
- bounded maps and bounded rule sizes;
- explicit IPv4 and IPv6 handling;
- a fail-safe behavior when a policy is missing or corrupt;
- a health signal that distinguishes loaded, stale, and unavailable.

If the required kernel capability is unavailable, enforcement mode must refuse
to start. It must not silently fall back to observe-only while displaying a
"protected" status.

### 3. Policy model

Policies are per supervised profile, not global by default:

```yaml
profile: nightshift
mode: enforce
cgroup: /sys/fs/cgroup/ai-antiva/nightshift
allow:
  - direction: egress
    protocol: tcp
    family: ipv4
    cidr: 127.0.0.0/8
    ports: [8086]
  - direction: egress
    protocol: tcp
    family: ipv4
    cidr: 10.0.0.0/8
    ports: [443]
```

The actual schema must reject ambiguous hostnames in the kernel policy. DNS
names may be resolved by a separate policy compiler with an expiry and audited
resolved addresses; the kernel hook receives IP/CIDR rules only.

Policy defaults:

- no profile: no enforcement and no claim of protection;
- preview: record allow/deny decisions without altering traffic;
- enforce: deny unmatched supported connection attempts;
- invalid or expired policy: refuse to launch a new supervised runtime;
- emergency disable: remove enforcement for the selected profile only and emit
  a high-severity audit event.

Loopback allowances must be explicit per profile. For example, a local model
server that does not need external access should receive loopback-only policy,
not a broad `0.0.0.0/0` allow rule.

### 4. Decision and audit contract

Every enforcement decision must carry:

- profile and cgroup identity;
- process identity available at hook/launcher level;
- policy generation and policy hash;
- address family, destination IP, destination port, and protocol;
- action: `allow`, `deny`, `preview_allow`, or `preview_deny`;
- reason code;
- monotonic event sequence plus wall-clock timestamp;
- enforcement health state.

Raw payloads and secrets must never be copied into the audit record. The
existing hash-chained audit log is useful tamper evidence, but it is not an
independent trust anchor. Release mode should additionally support signed
checkpoints and remote or removable-media anchoring.

### 5. Safe rollback

Rollback is a first-class feature, not a shell command hidden in documentation.

Required paths:

- `antiva status --profile NAME` shows whether enforcement is actually loaded;
- `antiva policy check FILE` validates without changing the host;
- `antiva policy apply FILE --preview` records expected decisions only;
- `antiva policy apply FILE --enforce` atomically installs a generation;
- `antiva disable --profile NAME` disables only that profile;
- a local emergency disable token or documented console path works when the
  web/API process is unhealthy;
- the previous valid policy can be restored atomically;
- a failed policy load leaves the previous valid policy active.

The emergency path must be tested with the model runtime running. A failed
rollback is a release blocker.

## Threat and failure cases to test

Before claiming enforcement, automated and manual tests must cover:

1. allowed loopback connection succeeds;
2. disallowed external IPv4 connection fails before connect;
3. disallowed IPv6 connection fails before connect;
4. child process inherits the supervised restriction;
5. an unrelated process remains unaffected;
6. PID reuse does not inherit a stale allow decision;
7. policy replacement is atomic under concurrent connect attempts;
8. malformed, expired, or missing policy cannot produce an accidental allow in
   enforce mode;
9. hook unload or capability loss changes status to `unprotected` and follows
   the documented fail-safe behavior;
10. emergency disable restores the selected profile without changing unrelated
    profiles;
11. audit tampering is detected;
12. restart preserves the last known policy generation and does not claim
    protection before the hook health check passes.

Tests must run in a disposable VM or network namespace. Never begin by applying
rules to the production host's default cgroup or global firewall.

## Staged implementation

### Stage A — design and simulator (implemented)

- freeze the profile and policy schema;
- add a pure-Python decision simulator (`ai_antivirus.enforcement`);
- add policy validation and canonical hashing;
- distinguish `preview_allow`/`preview_deny` from enforce actions;
- reject ambiguous CIDRs, unsupported protocols, invalid ports, and relative
  cgroup paths;
- document operator and rollback flows.

The simulator is side-effect-free: it does not install rules, change cgroups,
open sockets, or alter host networking. Its decisions are the contract for the
future privileged enforcer.

### Stage B — isolated lab enforcement (next)

- implement the managed launcher;
- create a disposable cgroup/network-namespace integration harness;
- implement the hook for TCP connect4/connect6;
- test allow/deny and rollback without touching production services.

### Stage C — opt-in host pilot

- protect one disposable test service only;
- default to preview mode;
- expose truthful health status;
- collect false positives and CPU overhead;
- require explicit confirmation before enforce mode.

### Stage D — product release gate

- signed reproducible binaries and SBOM;
- authenticated local IPC;
- service installer and uninstall rollback;
- independent security review;
- documented support matrix and incident response.

## Quantum-resistant roadmap

SHA-256 remains suitable for the current artifact fingerprint and hash-chain
correlation, subject to normal collision-resistance assumptions. It is not a
quantum-resistant signature scheme. Before long-lived signed feeds or audit
checkpoints are released, use a vetted post-quantum signature design such as
ML-DSA, with a migration plan and key rotation. For confidential long-lived
control-plane data, evaluate hybrid classical/PQ key establishment such as
ML-KEM through a maintained TLS/library stack. Do not implement cryptography
inside Antiva ad hoc.

## Product wording until Stage D

Use:

> AI model artifact scanner and opt-in local runtime monitor with quarantine.

Do not use:

> full antivirus, firewall, guaranteed leak prevention, or quantum-proof
> security.
