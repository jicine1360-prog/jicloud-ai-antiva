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
    ):
        if interval_seconds <= 0:
            raise ValueError("watch interval must be greater than zero")
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
        self._seen: dict[Path, FileSignature] = {}
        self._scanned: dict[Path, FileSignature] = {}
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
        assert self.quarantine_dir is not None
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        if self._signature(path) != expected:
            raise OSError("model changed while it was being scanned")
        if path.lstat().st_dev != self.quarantine_dir.stat().st_dev:
            raise OSError("quarantine directory must be on the same filesystem as the watched file")
        destination = self.quarantine_dir / f"{path.name}.{report['sha256'][:12]}.{uuid4().hex}.quarantined"
        # A quarantined artifact must not retain an executable mode.  This is
        # defense in depth: the scanner never executes artifacts, but other
        # local tools may still see the quarantine directory.
        os.chmod(path, 0o600, follow_symlinks=False)
        os.replace(path, destination)
        return str(destination)

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
            if self._seen.get(path) != signature or self._scanned.get(path) == signature:
                continue
            try:
                report = scan_model(path, self.threat_feed)
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
            except (OSError, ValueError) as error:
                self.last_error = str(error)
                continue
        self._seen = current
        self._scanned = {
            path: signature for path, signature in self._scanned.items() if path in current
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
