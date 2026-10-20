# Product Status And Release Plan

## Product Boundary

JICloud AI Antiva is currently a pre-release model-artifact triage and local
observation prototype. It is not an antivirus product, a network firewall, or a
guarantee that a model cannot leak information.

## Implemented Flow

1. A model artifact is scanned without executing or deserializing it.
2. The scanner calculates SHA-256, validates selected file headers, checks ZIP
   metadata for unsafe paths, scripts, native binaries, and symbolic links, and
   blocks any SHA-256 listed in the configured local threat feed.
2a. Threat feed: a local JSONL/JSON file of blocked SHA-256 indicators with an
   optional reason and source. Feed loading is manual; automatic, signed feed
   updates are a release-gate item below.
3. A watched directory scans files only after they remain stable for one poll.
   Blocked artifacts may be atomically moved to a same-filesystem quarantine.
4. Linux can observe selected AI server processes and their established external
   IPv4 TCP connections.
5. Decisions and scan summaries are stored in a local hash-chained audit log.

The local audit log detects ordinary in-place edits. It is not independent proof
against a privileged attacker, deletion, or a complete rewrite. Do not call it
an immutable or externally tamper-proof audit trail.

## Platform Status

| Platform | Distribution | Current capability | Not yet provided |
| --- | --- | --- | --- |
| Linux (x64) | `dist/linux/` zipapp (CI-built) | Static scanning, directory watch/quarantine, local API, AI-process and IPv4 TCP observation | Traffic blocking, IPv6/UDP/DNS observation, service installer, signed release |
| Windows (x64) | `dist/windows/` EXE (CI-built, unsigned) | Shared scanner/watch source, EXE build scripts, login-start installer scripts | Built/test EXE validated on hardware, native runtime observation, traffic enforcement, signed installer |
| Android | `dist/android/` debug APK (CI-built) | Selected-file SHA-256 and extension warning prototype | Scanner-equivalent validation, server connection, alerts, VPN, release APK |
| macOS | Not started (postponed) | — | Static scanner, all product functions |
| iOS | Not started (postponed) | — | All product functions |

Each build only works for its named platform; consume the artifact under the matching `dist/<platform>/` directory and verify it with that directory's `SHA-256SUMS`.

## Release Gates

1. Implement an explicit network-enforcement architecture before claiming
   egress blocking. It must cover process attribution, allowlist policy, safe
   rollback, and a tested emergency disable path.
2. Add a signed threat-intelligence feed containing revoked model hashes,
   malicious archive indicators, and known destination indicators.
3. Add authenticated local IPC, strict event schemas, bounded audit retention,
   and externally anchored or signed audit checkpoints.
4. Create reproducible, signed Linux/Windows/Android releases with checksums,
   SBOMs, update policy, and vulnerability-response ownership.
5. Add platform integration tests, adversarial artifact fixtures, and an
   independent security review before public distribution.

Gate 3 is partially implemented: the local API accepts an optional bearer token
(`--auth-token` or `AI_ANTIVA_AUTH_TOKEN`) and rejects non-loopback `Host` and
`Origin` headers, event payloads are size-bounded, and `/v1/status` reports
truthful component health. Bounded audit retention and externally anchored or
signed audit checkpoints are still missing.

## Next Development Phase

The next engineering target is a Linux enforcement design, not an immediate
firewall toggle. The design is documented in `docs/linux-enforcement-design.md`.
It defines cgroup-scoped opt-in supervision, IPv4/IPv6 TCP connect enforcement,
preview mode, truthful health status, atomic policy replacement, and a tested
emergency rollback path. Until that design reaches the isolated-lab stage, the
runtime monitor remains observation-only and must not be marketed as traffic
blocking.
