"""Polling model-directory watcher that never opens artifacts for execution."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import stat as stat_module
from threading import Event, Thread
from uuid import uuid4

from .scanner import SCANNABLE_EXTENSIONS, scan_model
from .intel import ThreatFeed

FileSignature = tuple[int, int, int, int, int]

# A file that changes on every poll used to be deferred forever, which is an
# easy way to keep an artifact out of the scan.  After this many polls the
# watcher scans it anyway and labels the result as possibly partial.
MAX_DEFER_POLLS = 12


@dataclass(frozen=True)
class WatchResult:
    report: dict
    quarantined_to: str | None = None
    quarantine_error: str | None = None


class ModelWatcher:
    """Scan stable model files and optionally isolate files the scanner blocks."""

    def __init__(
        self,
        paths: tuple[str, ...],
        interval_seconds: float = 5.0,
        quarantine_dir: str | None = None,
        on_result: Callable[[WatchResult], None] | None = None,
        threat_feed: ThreatFeed | None = None,
        max_defer_polls: int = MAX_DEFER_POLLS,
    ):
        if interval_seconds <= 0:
            raise ValueError("watch interval must be greater than zero")
        if max_defer_polls < 1:
            raise ValueError("max_defer_polls must be at least one")
        self.paths = tuple(Path(path).expanduser().resolve(strict=False) for path in paths)
        self.interval_seconds = interval_seconds
        self.quarantine_dir = (
            Path(quarantine_dir).expanduser().resolve(strict=False) if quarantine_dir else None
        )
        if self.quarantine_dir and any(
            self.quarantine_dir == path or path in self.quarantine_dir.parents for path in self.paths
        ):
            raise ValueError("quarantine directory must not be inside a watched path")
        self.on_result = on_result
        self.threat_feed = threat_feed
        self.max_defer_polls = max_defer_polls
        self._seen: dict[Path, FileSignature] = {}
        self._scanned: dict[Path, FileSignature] = {}
        self._failed: dict[Path, FileSignature] = {}
        self._deferred: dict[Path, int] = {}
        self._stop = Event()
        self._thread: Thread | None = None
        self.last_error: str | None = None

    @staticmethod
    def _signature(path: Path) -> FileSignature:
        metadata = path.lstat()
        if not stat_module.S_ISREG(metadata.st_mode):
            raise ValueError(f"watch target must be a regular file: {path}")
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_ctime_ns,
            metadata.st_mtime_ns,
            metadata.st_size,
        )

    def _files(self) -> list[Path]:
        files: list[Path] = []
        for root in self.paths:
            if not root.exists() or not root.is_dir():
                continue
            try:
                files.extend(
                    path
                    for path in root.rglob("*")
                    if path.suffix.lower() in SCANNABLE_EXTENSIONS
                    and path.is_file()
                    and not path.is_symlink()
                )
            except OSError:
                continue
        return files

    def _quarantine(self, path: Path, report: dict, expected: FileSignature) -> str:
        if self.quarantine_dir is None:
            # An assert disappears under python -O, and the failure that follows
            # would be an AttributeError on None instead of a reported error.
            raise OSError("quarantine directory is not configured")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        # Blocked artifacts stay readable only to their owner.  mkdir alone is
        # not enough: an existing directory keeps whatever mode it already had.
        os.chmod(self.quarantine_dir, 0o700)
        if self._signature(path) != expected:
            raise OSError("model changed while it was being scanned")
        if path.lstat().st_dev != self.quarantine_dir.stat().st_dev:
            raise OSError("quarantine directory must be on the same filesystem as the watched file")
        links = path.lstat().st_nlink
        if links > 1:
            # Renaming one name cannot remove content that other links still
            # point at, so the leftover exposure becomes part of the evidence.
            report["findings"].append(
                {
                    "severity": "medium",
                    "code": "quarantine_hardlink_remaining",
                    "message": "The artifact has other hard links; moving one name does not remove the content.",
                    "evidence": f"st_nlink={links}",
                }
            )
        destination = self.quarantine_dir / f"{path.name}.{report['sha256'][:12]}.{uuid4().hex}.quarantined"
        # A quarantined artifact must not retain an executable mode.  This is
        # defense in depth: the scanner never executes artifacts, but other
        # local tools may still see the quarantine directory.
        # follow_symlinks=False is unsupported on Windows (symlinks there are
        # always followed); the path was already verified not to be a symlink.
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except NotImplementedError:
            os.chmod(path, 0o600)
        os.replace(path, destination)
        return str(destination)

    def _failure_report(self, path: Path, signature: FileSignature, error: Exception) -> dict:
        """Describe an artifact that could not be read, so the gap is auditable."""

        suffix = path.suffix.lower().removeprefix(".")
        return {
            "schema_version": 1,
            "path": str(path),
            "size_bytes": signature[4],
            "sha256": None,
            "detected_format": suffix or "unknown",
            "status": "review",
            "findings": [
                {
                    "severity": "medium",
                    "code": "scan_failed",
                    "message": "The artifact could not be read completely, so it was not assessed.",
                    "evidence": str(error),
                }
            ],
        }

    def poll_once(self) -> list[WatchResult]:
        """Scan files unchanged since the preceding poll, returning new results."""

        current: dict[Path, FileSignature] = {}
        results: list[WatchResult] = []
        for path in self._files():
            try:
                signature = self._signature(path)
            except (OSError, ValueError):
                continue
            current[path] = signature
            if self._scanned.get(path) == signature:
                continue
            stable = self._seen.get(path) == signature
            if stable:
                self._deferred.pop(path, None)
                deferrals = 0
            else:
                deferrals = self._deferred.get(path, 0) + 1
                self._deferred[path] = deferrals
                if deferrals < self.max_defer_polls:
                    continue
            try:
                report = scan_model(path, self.threat_feed)
                if not stable:
                    report["findings"].append(
                        {
                            "severity": "medium",
                            "code": "artifact_unstable",
                            "message": (
                                "The file kept changing across polls; it was scanned anyway and the "
                                "result may cover a partial write."
                            ),
                            "evidence": f"deferred {deferrals} polls",
                        }
                    )
                    if report["status"] == "clean":
                        report["status"] = "review"
                quarantined_to = None
                quarantine_error = None
                if report["status"] == "blocked" and self.quarantine_dir:
                    try:
                        quarantined_to = self._quarantine(path, report, signature)
                    except (OSError, ValueError) as error:
                        # Do not silently drop a blocked result when the
                        # enforcement action fails.  Emit it for the audit
                        # layer and expose the failure to the caller.
                        quarantine_error = str(error)
                        self.last_error = quarantine_error
                result = WatchResult(
                    report=report,
                    quarantined_to=quarantined_to,
                    quarantine_error=quarantine_error,
                )
                results.append(result)
                if self.on_result:
                    self.on_result(result)
                self._scanned[path] = signature
                self._deferred.pop(path, None)
            except (OSError, ValueError) as error:
                # A file that cannot be read is a gap in coverage, not a silent
                # skip: report it once per content signature and keep retrying.
                self.last_error = str(error)
                if self._failed.get(path) != signature:
                    self._failed[path] = signature
                    failure = WatchResult(report=self._failure_report(path, signature, error))
                    results.append(failure)
                    if self.on_result:
                        self.on_result(failure)
                continue
        self._seen = current
        self._scanned = {
            path: signature for path, signature in self._scanned.items() if path in current
        }
        self._failed = {
            path: signature for path, signature in self._failed.items() if path in current
        }
        self._deferred = {
            path: count for path, count in self._deferred.items() if path in current
        }
        return results

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as error:
                self.last_error = str(error)
            self._stop.wait(self.interval_seconds)

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="ai-antivirus-model-watcher", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_seconds + 1)
            if not self._thread.is_alive():
                self._thread = None
