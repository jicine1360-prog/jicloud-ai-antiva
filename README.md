# JICloud AI Antiva

An AI model and host security guard by JICloud.

![JICloud AI Antiva](assets/jicloud-ai-antiva-logo.svg)

This is a pre-release local model-artifact triage tool. It never deserializes or
executes model files. It computes an integrity hash, validates selected format
headers, inspects ZIP metadata, and emits a machine-readable risk report. A
`clean` result only means the implemented checks found no signal; it is not a
malware certification or a guarantee of safe model behavior.

## Run

```bash
PYTHONPATH=src python -m ai_antivirus.cli path/to/model.safetensors
PYTHONPATH=src python -m ai_antivirus.cli path/to/model.pt --json
```

## Distribution

Artifacts are staged per platform under `dist/`. The Linux ZIP executables
require Python 3.10 or newer:

```bash
./dist/linux/ai-model-scan path/to/model.safetensors --json
./dist/linux/ai-model-scan /mnt/usb4tb --recursive --json --threat-feed threats.jsonl
./dist/linux/ai-model-guard --flag-unknown-hosts --allowed-host 127.0.0.1
./dist/linux/ai-model-guard --watch-path ~/models --quarantine-dir ~/.local/share/ai-antivirus/quarantine --threat-feed threats.jsonl
./dist/linux/ai-model-guard --watch-runtime --runtime-interval 5
```

To inspect a model directory recursively, emit one JSON report per artifact so
that long-running scans can be monitored from their saved output:

```bash
./dist/linux/ai-model-scan /mnt/usb4tb --recursive --json > usb4tb-scan.jsonl
```

Rebuild the Linux ZIP applications after a source change with:

```bash
./scripts/build-linux.sh
```

### Per-platform layout

Each platform has its own distribution directory with a `SHA-256SUMS` file:

| Directory | Contents |
| --- | --- |
| `dist/linux/` | `ai-model-scan`, `ai-model-guard` (zipapp) |
| `dist/windows/` | `ai-model-scan.exe`, `ai-model-guard.exe` (PyInstaller onefile) |
| `dist/android/` | `jicloud-ai-antiva-debug.apk` |

Rebuild the checksums and a release manifest after any build:

```bash
./scripts/make-checksums.sh dist/linux
python3 scripts/make-manifest.py dist 0.1.0   # writes dist/release-manifest.json
```

### CI builds

`.github/workflows/build.yml` builds every platform on GitHub Actions (Linux
on Ubuntu, Windows EXE on Windows, Android APK on Ubuntu) and uploads each
platform directory with checksums. Tagging `v*` triggers `.github/workflows/
release.yml`, which assembles a GitHub release from all three platforms.
Windows and Android binaries are unsigned for now; macOS and iOS packaging is
not started.

## Windows 11 build and use

On the Windows PC, install Python 3.10 or later from python.org with the
Python launcher (`py`) enabled. From PowerShell in this project directory,
build the executables with:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\build-windows.ps1
```

This creates `dist\windows\ai-model-scan.exe` and
`dist\windows\ai-model-guard.exe`. Start the local guard with a model folder
and a quarantine folder that is outside that model folder:

```powershell
.\dist\windows\ai-model-guard.exe `
  --watch-path "$HOME\models" `
  --quarantine-dir "$HOME\AI-Antiva-Quarantine"
```

It exposes status only on `http://127.0.0.1:8765/v1/status`; it is not
reachable from another computer. Keep the PowerShell window open while the
guard is running. Use `Ctrl+C` to stop it.

### Windows background protection

After the executables are built, register the guard to start at your Windows
login. This is a per-user Task Scheduler entry and does not require an
administrator account:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\install-windows.ps1 -WatchPath "$HOME\models"
```

The installer creates the model folder when needed, stores the tamper-evident
audit log under `%LOCALAPPDATA%\JICloud\AI Antiva\audit.jsonl`, and starts the
guard immediately. To inspect it, open `http://127.0.0.1:8765/v1/status` or
run:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/v1/status
```

Remove the automatic startup without deleting audit evidence or quarantined
files with:

```powershell
.\scripts\uninstall-windows.ps1
```

## Local guard API

The guard listens on `127.0.0.1` only and answers three routes:

| Route | Method | Notes |
| --- | --- | --- |
| `/health` | GET | liveness check; never requires a token |
| `/v1/status` | GET | counters, component health, and audit chain state |
| `/v1/events` | POST | one JSON event, `Content-Type: application/json`, at most 1 MiB |

Requests must carry a loopback `Host` header, and a browser `Origin` header is
accepted only when it is also loopback, so a page on another site cannot drive
the API. Rejected requests are counted in `rejections` and recorded in the audit
log.

`/v1/status` reports `audit_integrity`, `audit_degraded`, and `audit_entries`.
The log is hash-chained and numbered, and `audit.jsonl.anchor` checkpoints its
tail, so entries removed from the end are reported as degraded instead of
passing silently. The guard verifies the whole chain when it starts and prints a
warning to stderr when that check fails.

To require a bearer token on the `/v1` routes:

```bash
ai-model-guard --auth-token "$(openssl rand -hex 24)"
```

`AI_ANTIVA_AUTH_TOKEN` is used when the flag is omitted. Send the token as
`Authorization: Bearer <token>`.

`/v1/status` reports `enforcement_mode: "none"` and
`enforcement_health: "unavailable"` on purpose: this build records decisions and
quarantines files, it does not block network traffic or processes.

## Egress policy simulator

Stage A includes a side-effect-free policy simulator. It validates an explicit
JSON policy and evaluates IPv4/IPv6 TCP destinations without installing firewall
or eBPF rules:

```python
from ai_antivirus.enforcement import decide, load_policy

policy = load_policy("policy.json")
result = decide(policy, "127.0.0.1", 8080)
print(result.as_dict())
```

This is preview/design functionality, not network enforcement. The simulator
never changes host networking.

## Current scope

- SHA-256 integrity fingerprint
- SafeTensors, GGUF, and TFLite header validation
- SHA-256 threat-intelligence block list (`--threat-feed`; JSONL or JSON array
  of `{"sha256": "...", "reason": "..."}` records). Listed artifacts are
  blocked and quarantined even if the static checks are otherwise clean.
- Unsafe serialization warning
- ZIP archive validity, path traversal, and Windows-path detection
- Script and native binary detection inside ZIP archives
- JSON and human-readable reports

The optional watcher scans a new or changed model only after it remains unchanged
for one polling interval. Artifacts with a `blocked` result can be moved to an
explicit quarantine directory on the same filesystem. Quarantined files are renamed
with a hash-derived identifier and have mode `0600`; if quarantine fails, the blocked
result is still emitted and the failure is recorded instead of being silently discarded.
This works on Windows and Linux without opening, deserializing, or executing the model.
On Linux,
`--watch-runtime` records known AI server processes and their external,
established IPv4 TCP connections. It is read-only monitoring: policy decisions
are audited but traffic is not blocked. It does not observe IPv6, UDP, DNS, or
short-lived connections. See `docs/product-status.md` for the platform boundary
and release plan.

## Android

The Android code in `android/` is a local selected-file SHA-256 prototype. It
does not provide model-structure validation, device protection, guard-server
connection, notification, VPN monitoring, or a release-signed APK. Build the
debug-only APK with:

```bash
cd android
JAVA_HOME=/path/to/full-jdk ./gradlew assembleDebug
```

The debug APK is staged at `dist/android/jicloud-ai-antiva-debug.apk`; do not
distribute it as a security product release.
