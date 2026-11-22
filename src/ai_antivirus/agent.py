"""Loopback-only local guard API."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import signal
import sys
from threading import Lock
from urllib.parse import urlsplit

from .audit import AuditLog
from .intel import ThreatFeed
from .linux_runtime import DEFAULT_PROCESS_NAMES, LinuxRuntimeMonitor
from .policy import Policy, evaluate_event, normalize_event, payload_fingerprint
from .watcher import ModelWatcher, WatchResult


MAX_EVENT_BYTES = 1024 * 1024
MAX_RECORDED_REJECTIONS = 100
LOCAL_HOST_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


class _ShutdownRequested(Exception):
    """Raised inside the server loop when a termination signal arrives."""


def _stop_gracefully(signum: int, frame: object) -> None:
    raise _ShutdownRequested()


def _host_is_local(host_header: str) -> bool:
    """Accept only loopback Host headers, which blocks DNS rebinding attacks."""

    host = (host_header or "").strip().lower()
    if not host:
        return False
    if host.startswith("["):
        return host.split("]")[0][1:] in LOCAL_HOST_NAMES
    name, separator, _ = host.rpartition(":")
    if separator and name:
        host = name
    return host in LOCAL_HOST_NAMES


def _origin_is_local(origin: str) -> bool:
    """Accept only browser origins that are themselves loopback."""

    return (urlsplit(origin).hostname or "").lower() in LOCAL_HOST_NAMES


def _audit_event(event: dict) -> dict:
    sanitized = {key: value for key, value in event.items() if key != "data"}
    if "data" in event:
        sanitized["data_sha256"] = payload_fingerprint(event["data"])
        sanitized["data_length"] = len(str(event["data"]))
    return sanitized


class GuardState:
    def __init__(self, policy: Policy, audit: AuditLog):
        self.policy = policy
        self.audit = audit
        self.lock = Lock()
        self.events_seen = 0
        self.events_blocked = 0
        self.last_decision: dict | None = None
        self.models_scanned = 0
        self.models_quarantined = 0
        self.last_model_scan: dict | None = None
        self.rejections = 0
        # Truthful component health: this build observes and records, it does
        # not enforce network or process policy, and the status output says so.
        self.health = {
            "enforcement_mode": "none",
            "enforcement_health": "unavailable",
            "file_watcher": "disabled",
            "runtime_monitor": "disabled",
            "threat_feed": "disabled",
            "auth": "disabled",
        }

    def record_rejection(self, code: str) -> None:
        """Count a rejected request and keep bounded audit evidence of it."""

        with self.lock:
            self.rejections += 1
            observed = self.rejections
        if observed <= MAX_RECORDED_REJECTIONS:
            self.audit.append(
                {"event_type": "api_rejection", "code": code},
                {"status": "rejected", "risk_score": 0, "findings": [code]},
            )

    def inspect(self, event: dict) -> dict:
        event = normalize_event(event)
        decision = evaluate_event(event, self.policy).as_dict()
        with self.lock:
            self.events_seen += 1
            if decision["status"] == "blocked":
                self.events_blocked += 1
            self.last_decision = decision
            self.audit.append(_audit_event(event), decision)
        return decision

    def record_model_scan(self, result: WatchResult) -> None:
        report = result.report
        decision = {
            "status": report["status"],
            "risk_score": 100 if report["status"] == "blocked" else 40 if report["status"] == "review" else 0,
            "findings": report["findings"],
        }
        event = {
            "event_type": "model_scan",
            "path": report["path"],
            "sha256": report["sha256"],
            "size_bytes": report["size_bytes"],
            "detected_format": report["detected_format"],
        }
        if result.quarantined_to:
            event["quarantined_to"] = result.quarantined_to
        if result.quarantine_error:
            event["quarantine_error"] = result.quarantine_error
        with self.lock:
            self.models_scanned += 1
            if result.quarantined_to:
                self.models_quarantined += 1
            self.last_model_scan = {
                "path": report["path"],
                "status": report["status"],
                "quarantined_to": result.quarantined_to,
                "quarantine_error": result.quarantine_error,
            }
            self.audit.append(event, decision)

    def status(self) -> dict:
        with self.lock:
            return {
                "events_seen": self.events_seen,
                "events_blocked": self.events_blocked,
                "rejections": self.rejections,
                "audit_integrity": self.audit.verify(),
                "audit_degraded": self.audit.degraded,
                "audit_entries": self.audit.entries,
                "audit_segments": self.audit.segments,
                "audit_expired_segments": self.audit.expired_segments,
                "audit_retention_blocked": self.audit.retention_blocked,
                "last_decision": self.last_decision,
                "models_scanned": self.models_scanned,
                "models_quarantined": self.models_quarantined,
                "last_model_scan": self.last_model_scan,
                **self.health,
            }


class _Handler(BaseHTTPRequestHandler):
    server: "GuardServer"

    def _send(self, status: int, body: dict) -> None:
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _reject(self, status: int, code: str) -> None:
        self.server.state.record_rejection(code)
        self._send(status, {"error": code})

    def _authorized(self) -> bool:
        token = self.server.auth_token
        if token is None:
            return True
        supplied = self.headers.get("Authorization", "")
        return hmac.compare_digest(supplied, f"Bearer {token}")

    def _request_is_addressed_to_us(self) -> bool:
        if not _host_is_local(self.headers.get("Host", "")):
            self._reject(400, "invalid_host")
            return False
        origin = self.headers.get("Origin")
        if origin and not _origin_is_local(origin):
            self._reject(403, "forbidden_origin")
            return False
        return True

    def do_GET(self) -> None:  # noqa: N802
        if not self._request_is_addressed_to_us():
            return
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/v1/status":
            if not self._authorized():
                self._reject(401, "unauthorized")
                return
            self._send(200, self.server.state.status())
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._request_is_addressed_to_us():
            return
        if not self._authorized():
            self._reject(401, "unauthorized")
            return
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self._reject(415, "unsupported_media_type")
            return
        if self.path != "/v1/events":
            self._send(404, {"error": "not_found"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > MAX_EVENT_BYTES:
                raise ValueError("invalid content length")
            event = json.loads(self.rfile.read(content_length))
            if not isinstance(event, dict):
                raise ValueError("event must be a JSON object")
        except (ValueError, TypeError, json.JSONDecodeError):
            self._send(400, {"error": "invalid_event"})
            return

        try:
            decision = self.server.state.inspect(event)
        except ValueError:
            self._send(400, {"error": "invalid_event"})
            return
        self._send(200, decision)

    def log_message(self, format: str, *args: object) -> None:
        return


class GuardServer(ThreadingHTTPServer):
    def __init__(self, port: int, state: GuardState, auth_token: str | None = None):
        super().__init__(("127.0.0.1", port), _Handler)
        self.state = state
        self.auth_token = auth_token
        if auth_token:
            state.health["auth"] = "bearer_token"
        self.daemon_threads = True


def serve(
    port: int,
    audit_path: str,
    policy: Policy,
    watch_paths: tuple[str, ...] = (),
    watch_interval: float = 5.0,
    quarantine_dir: str | None = None,
    watch_runtime: bool = False,
    runtime_interval: float = 5.0,
    runtime_process_names: tuple[str, ...] = (),
    threat_feed_path: str | None = None,
    auth_token: str | None = None,
    audit_max_megabytes: float = 32.0,
    audit_keep_segments: int = 0,
) -> None:
    threat_feed = ThreatFeed(threat_feed_path) if threat_feed_path else None
    state = GuardState(
        policy,
        AuditLog(
            audit_path,
            max_bytes=int(audit_max_megabytes * 1024 * 1024) if audit_max_megabytes > 0 else 0,
            keep_segments=audit_keep_segments if audit_keep_segments > 0 else None,
        ),
    )
    if not state.audit.verify(full=True):
        print(
            f"Audit log failed verification: {state.audit.path}. Treat its history as unreliable.",
            file=sys.stderr,
            flush=True,
        )
    server = GuardServer(port, state, auth_token)
    watcher = (
        ModelWatcher(
            watch_paths,
            watch_interval,
            quarantine_dir,
            state.record_model_scan,
            threat_feed,
        )
        if watch_paths
        else None
    )
    if watch_runtime and sys.platform != "linux":
        raise ValueError("runtime monitoring is currently available only on Linux")
    runtime_monitor = (
        LinuxRuntimeMonitor(
            state.inspect,
            runtime_interval,
            tuple(dict.fromkeys(DEFAULT_PROCESS_NAMES + runtime_process_names)),
        )
        if watch_runtime
        else None
    )
    if watcher:
        state.health["file_watcher"] = "active"
    if runtime_monitor:
        state.health["runtime_monitor"] = "active"
    if threat_feed is not None:
        state.health["threat_feed"] = {
            "loaded": True,
            "indicators": len(threat_feed.indicators),
            "skipped": threat_feed.skipped,
            "path": str(threat_feed.path),
        }
    print(f"JICloud AI Antiva listening on http://127.0.0.1:{server.server_port}", flush=True)
    if auth_token:
        print("Requests to /v1/* require an Authorization: Bearer token.", flush=True)
    print("This build records decisions; it does not block network traffic or processes.", flush=True)
    if watcher:
        watcher.start()
    if runtime_monitor:
        runtime_monitor.start()
    # systemd and `kill` send SIGTERM, whose default action skips the cleanup
    # below.  Translate it into an orderly shutdown so the audit checkpoint and
    # the watcher stop still run.
    previous_handlers = {}
    try:
        previous_handlers[signal.SIGTERM] = signal.signal(signal.SIGTERM, _stop_gracefully)
        if sys.platform == "win32":
            # Windows console processes never receive SIGTERM; a graceful
            # shutdown there arrives as CTRL_BREAK_EVENT (SIGBREAK).
            previous_handlers[signal.SIGBREAK] = signal.signal(signal.SIGBREAK, _stop_gracefully)
    except ValueError:
        pass  # not the main thread: leave signal handling to the embedder
    try:
        server.serve_forever()
    except (KeyboardInterrupt, _ShutdownRequested):
        pass
    finally:
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass
        if watcher:
            watcher.stop()
        if runtime_monitor:
            runtime_monitor.stop()
        server.server_close()
        state.audit.checkpoint()
