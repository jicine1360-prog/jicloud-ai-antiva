"""Loopback-only local guard API."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
from threading import Lock

from .audit import AuditLog
from .intel import ThreatFeed
from .linux_runtime import DEFAULT_PROCESS_NAMES, LinuxRuntimeMonitor
from .policy import Policy, evaluate_event, normalize_event, payload_fingerprint
from .watcher import ModelWatcher, WatchResult


MAX_EVENT_BYTES = 1024 * 1024


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
                "audit_integrity": self.audit.verify(),
                "last_decision": self.last_decision,
                "models_scanned": self.models_scanned,
                "models_quarantined": self.models_quarantined,
                "last_model_scan": self.last_model_scan,
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

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/v1/status":
            self._send(200, self.server.state.status())
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
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
    def __init__(self, port: int, state: GuardState):
        super().__init__(("127.0.0.1", port), _Handler)
        self.state = state
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
) -> None:
    threat_feed = ThreatFeed(threat_feed_path) if threat_feed_path else None
    state = GuardState(policy, AuditLog(audit_path))
    server = GuardServer(port, state)
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
    print(f"JICloud AI Antiva listening on http://127.0.0.1:{server.server_port}")
    if watcher:
        watcher.start()
    if runtime_monitor:
        runtime_monitor.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if watcher:
            watcher.stop()
        if runtime_monitor:
            runtime_monitor.stop()
        server.server_close()
