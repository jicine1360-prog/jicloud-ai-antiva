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


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._last_hash_value = self._last_hash()

    def _last_hash(self) -> str | None:
        if not self.path.exists():
            return None
        last: dict | None = None
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    last = json.loads(line)
        return last.get("entry_hash") if last else None

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
            previous_hash: str | None = None
            if not self.path.exists():
                return True
            try:
                with self.path.open("r", encoding="utf-8") as stream:
                    for line in stream:
                        if not line.strip():
                            continue
                        entry = json.loads(line)
                        if entry.get("previous_hash") != previous_hash:
                            return False
                        recorded_hash = entry.pop("entry_hash", None)
                        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
                        if recorded_hash != hashlib.sha256(canonical).hexdigest():
                            return False
                        previous_hash = recorded_hash
            except (OSError, json.JSONDecodeError, TypeError):
                return False
            return True
