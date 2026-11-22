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

# One log file is capped so that a long-lived guard cannot grow a single audit
# file without bound; the guard rotates it into a numbered segment and keeps the
# hash chain running into the new file.
DEFAULT_MAX_LOG_BYTES = 32 * 1024 * 1024
ANCHOR_SUFFIX = ".anchor"
UNKNOWN = object()


def _segment_key(name: str, stem: str, suffix: str) -> tuple[int, int] | None:
    """Return the sequence range encoded in a segment name, if it has one."""

    if not name.startswith(f"{stem}.") or not name.endswith(suffix):
        return None
    middle = name[len(stem) + 1 : -len(suffix)]
    first, separator, last = middle.partition("-")
    if not separator or len(first) != 12 or len(last) != 12:
        return None
    if not first.isdigit() or not last.isdigit():
        return None
    return int(first), int(last)


class AuditLog:
    """Append-only JSONL audit log with a hash chain and a tail anchor.

    The ``<log path>.anchor`` sidecar records the last sequence number and
    entry hash.  Removing the tail of the log therefore leaves the log and the
    anchor disagreeing, which is reported as ``degraded``.

    A log that reaches ``max_bytes`` is renamed to a sequence-numbered segment
    (``<stem>.000000000001-0000000120.jsonl``) with its own anchor, and the chain
    continues in a fresh live file.  With ``keep_segments`` set, the oldest
    segment bodies are removed once the limit is passed; their anchors are always
    kept, because the anchor is what proves the removed segment's sequence range
    and boundary hash.  Nothing is ever truncated in place.
    """

    def __init__(
        self,
        path: str | Path,
        max_bytes: int = DEFAULT_MAX_LOG_BYTES,
        keep_segments: int | None = None,
    ):
        self.path = Path(path).expanduser()
        self.anchor_path = self.path.with_name(self.path.name + ANCHOR_SUFFIX)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes if max_bytes and max_bytes > 0 else 0
        self.keep_segments = keep_segments if keep_segments and keep_segments > 0 else None
        self.segments = 0
        self.expired_segments = 0
        self.retention_blocked = False
        self._lock = Lock()
        (
            self._last_hash_value,
            self.degraded,
            self.entries,
            self._last_seq,
            self._first_seq,
            _,
        ) = self._scan()
        # Nothing has been verified yet: the first verify() walks the whole
        # chain, later calls only read what was appended since.
        self._verified_offset = 0
        self._verified_hash: str | None = None
        self._verified_seq = 0
        self._verified_mtime: int | None = None
        self._verified_tail_digest: str | None = None
        self._anchor_pending = 0
        # Chain state expected before the first entry of the live file.  After a
        # rotation that is the tail of the newest segment, not an empty chain.
        self._chain_hash: str | None = None
        self._chain_seq = 0
        if not self.degraded:
            self._check_anchor()
            # A log that already looks tampered with keeps its old anchor: over-
            # writing it would erase the evidence of the removal on next start.
            if not self.degraded:
                self._write_anchor()
            self._check_segments()
        self._verified_hash = self._chain_hash
        self._verified_seq = self._chain_seq

    def _scan(self) -> tuple[str | None, bool, int, int, int, int]:
        """Read the log once.

        Returns the true hash of the last entry, whether the log is damaged, the
        entry count, the last sequence number, the first sequence number, and the
        byte offset.  A truncated or malformed final line must not stop the guard
        from starting: the damage is reported through ``degraded`` and
        ``verify()`` so the operator still gets scanning and a truthful health
        status.

        The tail hash is recomputed instead of read from the file, so editing an
        entry while leaving its recorded hash untouched is visible to the
        anchor check.
        """

        if not self.path.exists():
            return None, False, 0, 0, 0, 0
        tail_entry: dict | None = None
        damaged = False
        entries = 0
        first_seq = 0
        last_seq = 0
        offset = 0
        try:
            with self.path.open("r", encoding="utf-8", newline="") as stream:
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
                        if not first_seq:
                            first_seq = seq
                        last_seq = seq
                    entry.pop("entry_hash", None)
                    tail_entry = entry
        except OSError:
            return None, True, entries, last_seq, first_seq, offset
        if tail_entry is None:
            return None, damaged, entries, last_seq, first_seq, offset
        return hashlib.sha256(_canonical(tail_entry)).hexdigest(), damaged, entries, last_seq, first_seq, offset

    def _read_json(self, path: Path | None) -> dict | None:
        if path is None:
            return None
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return None
        return _load_entry(content)

    def _write_json(self, path: Path, payload: dict) -> bool:
        temporary = path.with_name(path.name + ".tmp")
        try:
            with temporary.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError:
            return False
        return True

    def _check_anchor(self) -> None:
        """Compare the log tail with the anchor to detect removed entries."""

        anchor = self._read_json(self.anchor_path)
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
        if not self._write_json(self.anchor_path, anchor):
            self.degraded = True

    def _segments(self) -> list[dict]:
        """List rotated segments, oldest first, bodies and anchors together.

        An expired segment has no body but keeps its anchor, so it still appears
        here and still proves its sequence range and boundary hash.
        """

        stem, suffix = self.path.stem, self.path.suffix
        bodies: dict[tuple[int, int], Path] = {}
        anchors: dict[tuple[int, int], Path] = {}
        try:
            candidates = list(self.path.parent.iterdir())
        except OSError:
            return []
        for candidate in candidates:
            if candidate == self.path or candidate == self.anchor_path:
                continue
            name = candidate.name
            if name.endswith(ANCHOR_SUFFIX):
                key = _segment_key(name[: -len(ANCHOR_SUFFIX)], stem, suffix)
                if key is not None:
                    anchors[key] = candidate
            else:
                key = _segment_key(name, stem, suffix)
                if key is not None:
                    bodies[key] = candidate
        segments = []
        for key in sorted(set(bodies) | set(anchors)):
            segments.append(
                {"first": key[0], "last": key[1], "body": bodies.get(key), "anchor": anchors.get(key)}
            )
        return segments

    def _first_previous_hash(self, path: Path | None):
        """Return the ``previous_hash`` of a file's first entry, or UNKNOWN."""

        if path is None:
            return UNKNOWN
        try:
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.strip():
                        continue
                    entry = _load_entry(line)
                    if entry is None:
                        return UNKNOWN
                    value = entry.get("previous_hash")
                    return value if value is None or isinstance(value, str) else UNKNOWN
        except OSError:
            return UNKNOWN
        return UNKNOWN

    def _check_segments(self) -> None:
        """Check that rotated segments still line up with each other and the log.

        Only the anchors and the first line of each file are read, so the check
        stays cheap no matter how much history has accumulated.  It proves that
        no whole segment was removed or replaced: that breaks either the sequence
        ranges or the boundary hash.  It does not re-walk a closed segment, so an
        edit inside one is only found by verifying that segment directly.
        """

        segments = self._segments()
        self.segments = len(segments)
        self.expired_segments = sum(1 for segment in segments if segment["body"] is None)
        if not segments or not self._last_seq:
            # A legacy log without sequence numbers has no ranges to line up.
            return
        if segments[0]["first"] != 1:
            # The oldest surviving segment must reach back to the first entry,
            # otherwise a whole segment (body and anchor) has disappeared.
            self.degraded = True
        previous_tail: str | None = None
        previous_last = 0
        for segment in segments:
            if previous_last and segment["first"] != previous_last + 1:
                self.degraded = True
            first_hash = self._first_previous_hash(segment["body"])
            if previous_tail is not None and first_hash is not UNKNOWN and first_hash != previous_tail:
                self.degraded = True
            anchor = self._read_json(segment["anchor"])
            if isinstance(anchor, dict):
                tail = anchor.get("entry_hash")
                previous_tail = tail if isinstance(tail, str) else None
            else:
                previous_tail = None
            previous_last = segment["last"]
        self._chain_hash = previous_tail
        self._chain_seq = previous_last
        if self._first_seq and self._first_seq != previous_last + 1:
            self.degraded = True
        live_first = self._first_previous_hash(self.path)
        if previous_tail is not None and live_first is not UNKNOWN and live_first != previous_tail:
            self.degraded = True

    def _rotate(self) -> None:
        """Close the live log as a numbered segment and continue in a new file."""

        if not self.entries or not self._first_seq:
            return
        if not self.degraded:
            self._write_anchor()
        name = f"{self.path.stem}.{self._first_seq:012d}-{self._last_seq:012d}{self.path.suffix}"
        segment = self.path.with_name(name)
        try:
            os.replace(self.path, segment)
        except OSError:
            self.degraded = True
            return
        if self.anchor_path.exists():
            try:
                os.replace(self.anchor_path, segment.with_name(segment.name + ANCHOR_SUFFIX))
            except OSError:
                self.degraded = True
        self._chain_hash = self._last_hash_value
        self._chain_seq = self._last_seq
        self._first_seq = 0
        self.entries = 0
        self._anchor_pending = 0
        self.segments += 1
        self._verified_offset = 0
        self._verified_hash = self._chain_hash
        self._verified_seq = self._chain_seq
        self._verified_mtime = None
        self._verified_tail_digest = None

    def _expire_segments(self) -> None:
        """Remove the oldest segment bodies once the anchor can vouch for them.

        The anchor is never removed: it is the only remaining proof of the
        segment's sequence range and boundary hash, and an attacker who deletes a
        segment together with its anchor leaves a gap this guard reports.
        """

        if self.keep_segments is None:
            return
        segments = [segment for segment in self._segments() if segment["body"] is not None]
        while len(segments) > self.keep_segments:
            oldest = segments[0]
            anchor = self._read_json(oldest["anchor"])
            if not isinstance(anchor, dict) or not isinstance(anchor.get("entry_hash"), str):
                # Never delete evidence the anchor cannot vouch for.
                self.retention_blocked = True
                return
            try:
                oldest["body"].unlink()
            except OSError:
                self.retention_blocked = True
                return
            anchor["expired"] = True
            if not self._write_json(oldest["anchor"], anchor):
                self.degraded = True
            self.expired_segments += 1
            self._append_locked(
                {
                    "kind": "audit_segment_expired",
                    "segment": oldest["body"].name,
                    "first_seq": oldest["first"],
                    "last_seq": oldest["last"],
                },
                {"action": "expired", "reason": "audit retention limit"},
            )
            segments = segments[1:]

    def append(self, event: dict, decision: dict) -> dict:
        with self._lock:
            entry = self._append_locked(event, decision)
            if self.max_bytes and not self.degraded:
                try:
                    size = self.path.stat().st_size
                except OSError:
                    size = 0
                if size >= self.max_bytes:
                    self._rotate()
            self._expire_segments()
        return entry

    def _append_locked(self, event: dict, decision: dict) -> dict:
        self._last_seq += 1
        if not self._first_seq:
            self._first_seq = self._last_seq
        entry = {
            "seq": self._last_seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": self._last_hash_value,
            "event": event,
            "decision": decision,
        }
        entry["entry_hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
        line = json.dumps(entry, sort_keys=True) + "\n"
        # newline="\n": keep LF on Windows too, so byte offsets and the tail
        # digest stay identical across platforms.
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
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
            with self.path.open("r", encoding="utf-8", newline="") as stream:
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
        self._verified_mtime = None
        self._verified_tail_digest = self._tail_digest(offset)
        return True

    _TAIL_DIGEST_BYTES = 4096

    def _tail_digest(self, offset: int) -> str | None:
        """Digest the tail of the already-verified region ``[0, offset)``.

        A same-length in-place edit keeps ``st_size`` and, on filesystems with
        coarse timestamps (Windows), can keep ``st_mtime`` unchanged.  The
        tail digest still changes, so ``verify`` can catch the edit cheaply
        before falling back to a full chain walk.
        """
        try:
            start = max(0, offset - self._TAIL_DIGEST_BYTES)
            if offset <= start:
                return hashlib.sha256(b"").hexdigest()
            with self.path.open("rb") as handle:
                handle.seek(start)
                return hashlib.sha256(handle.read(offset - start)).hexdigest()
        except OSError:
            return None

    def verify(self, full: bool = False) -> bool:
        """Walk the hash chain of the live log.

        Repeated calls are cheap: an unchanged log returns the previous result,
        and an appended log only walks the new lines.  A log whose size did not
        change but whose contents did is re-walked in full, and a shortened log
        fails immediately.  A targeted edit that also appends new lines is only
        caught by a full walk, so the guard verifies the whole chain at startup.
        Closed segments are checked at their boundaries by ``_check_segments``.
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
                return self._walk(0, self._chain_hash, self._chain_seq)
            if stat.st_size < self._verified_offset:
                return False
            if stat.st_size == self._verified_offset:
                # mtime alone cannot prove immutability (coarse Windows
                # timestamps); verify against a digest of the verified tail.
                if self._verified_tail_digest is not None:
                    if self._tail_digest(self._verified_offset) == self._verified_tail_digest:
                        return True
                    return self._walk(0, self._chain_hash, self._chain_seq)
                if stat.st_mtime_ns == self._verified_mtime:
                    return True
                return self._walk(0, self._chain_hash, self._chain_seq)
            return self._walk(self._verified_offset, self._verified_hash, self._verified_seq)
