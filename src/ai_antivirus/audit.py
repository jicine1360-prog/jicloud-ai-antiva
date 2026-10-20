"""Append-only, hash-chained audit logging.

This provides tamper evidence, not confidentiality. Encryption is a separate
layer to be added with a vetted cryptographic library and key manager.
"""

from __future__ import annotations

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os
from threading import Lock


def _load_entry(line: str) -> dict | None:
    """Parse one audit line, returning None when it is not a JSON object."""

    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None
    return entry if isinstance(entry, dict) else None


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._last_hash_value, self.degraded = self._last_hash()

    def _last_hash(self) -> tuple[str | None, bool]:
        """Return the last usable entry hash and whether the log is damaged.

        A truncated or malformed final line must not stop the guard from
        starting.  The damage is reported through ``degraded`` and ``verify()``
        so the operator still gets scanning and a truthful health status.
        """

        if not self.path.exists():
            return None, False
        last_hash: str | None = None
        damaged = False
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    entry = _load_entry(line)
                    if entry is None:
                        damaged = True
                        continue
                    candidate = entry.get("entry_hash")
                    if isinstance(candidate, str):
                        last_hash = candidate
                    else:
                        damaged = True
        except OSError:
            return None, True
        return last_hash, damaged

    def append(self, event: dict, decision: dict) -> dict:
        with self._lock:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "previous_hash": self._last_hash_value,
                "event": event,
                "decision": decision,
            }
            canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
            entry["entry_hash"] = hashlib.sha256(canonical).hexdigest()
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._last_hash_value = entry["entry_hash"]
        return entry

    def verify(self) -> bool:
        with self._lock:
            if self.degraded:
                return False
            previous_hash: str | None = None
            if not self.path.exists():
                return True
            try:
                with self.path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        if not line.strip():
                            continue
                        entry = _load_entry(line)
                        if entry is None:
                            return False
                        if entry.get("previous_hash") != previous_hash:
                            return False
                        recorded_hash = entry.pop("entry_hash", None)
                        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        if recorded_hash != hashlib.sha256(canonical).hexdigest():
                            return False
                        previous_hash = recorded_hash
            except (OSError, TypeError):
                return False
            return True
