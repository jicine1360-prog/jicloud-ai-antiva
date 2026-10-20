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


def _canonical(entry: dict) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


# The anchor is a checkpoint, not evidence: writing it on every append doubles
# the fsync cost of the log, so it is refreshed in batches and on shutdown.  A
# lagging anchor only narrows the truncation detection window, it never causes a
# false alarm.
ANCHOR_INTERVAL = 20


class AuditLog:
    """Append-only JSONL audit log with a hash chain and a tail anchor.

    The ``<log path>.anchor`` sidecar records the last sequence number and
    entry hash.  Removing the tail of the log therefore leaves the log and the
    anchor disagreeing, which is reported as ``degraded``.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.anchor_path = self.path.with_name(self.path.name + ".anchor")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._last_hash_value, self.degraded, self.entries, self._last_seq, _ = self._scan()
        # Nothing has been verified yet: the first verify() walks the whole
        # chain, later calls only read what was appended since.
        self._verified_offset = 0
        self._verified_hash: str | None = None
        self._verified_seq = 0
        self._verified_mtime: int | None = None
        self._anchor_pending = 0
        if not self.degraded:
            self._check_anchor()
            # A log that already looks tampered with keeps its old anchor: over-
            # writing it would erase the evidence of the removal on next start.
            if not self.degraded:
                self._write_anchor()

    def _scan(self) -> tuple[str | None, bool, int, int, int]:
        """Read the log once.

        Returns the true hash of the last entry, whether the log is damaged, the
        entry count, the last sequence number, and the byte offset.  A truncated
        or malformed final line must not stop the guard from starting: the
        damage is reported through ``degraded`` and ``verify()`` so the operator
        still gets scanning and a truthful health status.

        The tail hash is recomputed instead of read from the file, so editing an
        entry while leaving its recorded hash untouched is visible to the
        anchor check.
        """

        if not self.path.exists():
            return None, False, 0, 0, 0
        tail_entry: dict | None = None
        damaged = False
        entries = 0
        last_seq = 0
        offset = 0
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    offset += len(line.encode("utf-8"))
                    if not line.strip():
                        continue
                    entries += 1
                    entry = _load_entry(line)
                    if entry is None:
                        damaged = True
                        continue
                    if not isinstance(entry.get("entry_hash"), str):
                        damaged = True
                    seq = entry.get("seq")
                    if isinstance(seq, int) and not isinstance(seq, bool):
                        last_seq = seq
                    entry.pop("entry_hash", None)
                    tail_entry = entry
        except OSError:
            return None, True, entries, last_seq, offset
        if tail_entry is None:
            return None, damaged, entries, last_seq, offset
        return hashlib.sha256(_canonical(tail_entry)).hexdigest(), damaged, entries, last_seq, offset

    def _read_anchor(self) -> dict | None:
        try:
            content = self.anchor_path.read_text(encoding="utf-8")
        except OSError:
            return None
        return _load_entry(content)

    def _check_anchor(self) -> None:
        """Compare the log tail with the anchor to detect removed entries."""

        anchor = self._read_anchor()
        if anchor is None:
            return
        anchor_seq = anchor.get("seq")
        if not isinstance(anchor_seq, int) or isinstance(anchor_seq, bool):
            return
        if self._last_seq < anchor_seq:
            self.degraded = True
        elif self._last_seq == anchor_seq and self._last_hash_value != anchor.get("entry_hash"):
            self.degraded = True

    def _write_anchor(self) -> None:
        """Persist the tail position so a later truncation becomes visible."""

        anchor = {
            "seq": self._last_seq,
            "entry_hash": self._last_hash_value,
            "entries": self.entries,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        temporary = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(anchor, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.anchor_path)
        except OSError:
            self.degraded = True

    def append(self, event: dict, decision: dict) -> dict:
        with self._lock:
            self._last_seq += 1
            entry = {
                "seq": self._last_seq,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "previous_hash": self._last_hash_value,
                "event": event,
                "decision": decision,
            }
            entry["entry_hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
            line = json.dumps(entry, sort_keys=True) + "\n"
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            self._last_hash_value = entry["entry_hash"]
            self.entries += 1
            if not self.degraded:
                self._anchor_pending += 1
                if self._anchor_pending >= ANCHOR_INTERVAL:
                    self._write_anchor()
                    self._anchor_pending = 0
        return entry

    def checkpoint(self) -> None:
        """Write the anchor checkpoint now, before the process exits."""

        with self._lock:
            if not self.degraded:
                self._write_anchor()
                self._anchor_pending = 0

    def _walk(self, start_offset: int, previous_hash: str | None, previous_seq: int) -> bool:
        """Verify entries from ``start_offset`` to the end of the log."""

        offset = 0
        verified_seq = previous_seq
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    offset += len(line.encode("utf-8"))
                    if offset <= start_offset:
                        continue
                    if not line.strip():
                        continue
                    entry = _load_entry(line)
                    if entry is None:
                        return False
                    if entry.get("previous_hash") != previous_hash:
                        return False
                    recorded_hash = entry.pop("entry_hash", None)
                    if recorded_hash != hashlib.sha256(_canonical(entry)).hexdigest():
                        return False
                    seq = entry.get("seq")
                    if isinstance(seq, int) and not isinstance(seq, bool):
                        if seq != verified_seq + 1:
                            return False
                        verified_seq = seq
                    previous_hash = recorded_hash
        except (OSError, TypeError):
            return False
        self._verified_offset = offset
        self._verified_hash = previous_hash
        self._verified_seq = verified_seq
        try:
            self._verified_mtime = self.path.stat().st_mtime_ns
        except OSError:
            self._verified_mtime = None
        return True

    def verify(self, full: bool = False) -> bool:
        """Walk the hash chain.

        Repeated calls are cheap: an unchanged log returns the previous result,
        and an appended log only walks the new lines.  A log whose size did not
        change but whose contents did is re-walked in full, and a shortened log
        fails immediately.  A targeted edit that also appends new lines is only
        caught by a full walk, so the guard verifies the whole chain at startup.
        """

        with self._lock:
            if self.degraded:
                return False
            if not self.path.exists():
                return True
            try:
                stat = self.path.stat()
            except OSError:
                return False
            if full:
                return self._walk(0, None, 0)
            if stat.st_size < self._verified_offset:
                return False
            if stat.st_size == self._verified_offset:
                if stat.st_mtime_ns == self._verified_mtime:
                    return True
                return self._walk(0, None, 0)
            return self._walk(self._verified_offset, self._verified_hash, self._verified_seq)
