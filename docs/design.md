# Initial Design

## Security boundary

The scanner treats every model artifact as untrusted input. It must not import,
deserialize, or execute an artifact during static scanning.

## Scan pipeline

1. Validate that the target is a regular file.
2. Stream the file through SHA-256 without loading it into memory.
3. Infer a format from the extension and file signature where possible.
4. Flag formats that commonly require unsafe deserialization.
5. If the artifact is a ZIP container, inspect names and metadata only.
6. Produce findings with severity, code, and evidence.
7. Derive a status: `clean`, `review`, or `blocked`.

## Initial severity policy

- `high`: archive path traversal or executable/native payload
- `medium`: pickle-like serialization or suspicious archive content
- `low`: unknown model format

This is a triage scanner, not a malware-proof guarantee. A clean result means
that this scanner found no known signal; it does not certify model behavior.

## Planned components

- Static artifact scanner
- Isolated dynamic behavior runner
- Host agent for file, process, and network events
- Egress/DLP policy gateway (see `linux-enforcement-design.md`; opt-in and
  cgroup-scoped before any enforcement claim)
- Signed model registry and append-only audit log
- Encryption and key management

## Report contract

The JSON report is intended to remain stable enough for a future policy engine:

```json
{
  "schema_version": 1,
  "path": "model.safetensors",
  "sha256": "...",
  "status": "clean",
  "findings": []
}
```
