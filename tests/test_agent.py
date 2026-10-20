import json
import os
from pathlib import Path
import sys
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.agent import (
    MAX_EVENT_BYTES,
    GuardServer,
    GuardState,
    _host_is_local,
    _origin_is_local,
)
from ai_antivirus.audit import AuditLog
from ai_antivirus.policy import Policy
from ai_antivirus.watcher import WatchResult


def _running_server(state: GuardState, auth_token: str | None = None) -> GuardServer:
    server = GuardServer(0, state, auth_token)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def _http(
    server: GuardServer,
    path: str,
    body: str | None = None,
    headers: dict | None = None,
) -> tuple[int, dict]:
    request = Request(
        f"http://127.0.0.1:{server.server_port}{path}",
        data=body.encode("utf-8") if body is not None else None,
        headers=headers or {},
        method="POST" if body is not None else "GET",
    )
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def test_sensitive_egress_is_blocked(tmp_path):
    state = GuardState(
        Policy(allowed_hosts=frozenset({"approved.example"}), flag_unknown_hosts=True),
        AuditLog(tmp_path / "audit.jsonl"),
    )

    decision = state.inspect(
        {
            "event_type": "network_egress",
            "host": "unknown.example",
            "data": "api_key=super-secret-value",
        }
    )

    assert decision["status"] == "blocked"
    assert state.audit.verify()


def test_audit_log_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append({"event_type": "model_output"}, {"status": "allowed", "risk_score": 0, "findings": []})
    assert audit.verify()

    path.write_text(path.read_text(encoding="utf-8").replace("allowed", "blocked"), encoding="utf-8")
    assert not audit.verify()


def test_loopback_api_returns_decision(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = GuardServer(0, state)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/v1/events"
        request = Request(
            url,
            data=json.dumps({"event_type": "model_output", "data": "normal response"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            body = json.loads(response.read())
        assert body["status"] == "allowed"
    finally:
        server.shutdown()
        server.server_close()


def test_model_scan_is_recorded_in_status_and_audit(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    state.record_model_scan(
        WatchResult(
            report={
                "path": "model.zip",
                "sha256": "a" * 64,
                "size_bytes": 1,
                "detected_format": "zip",
                "status": "blocked",
                "findings": [],
            },
            quarantined_to="quarantine/model.zip",
        )
    )

    assert state.status()["models_scanned"] == 1
    assert state.status()["models_quarantined"] == 1
    assert state.audit.verify()


def test_loopback_api_rejects_invalid_event_types(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = GuardServer(0, state)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = Request(
            f"http://127.0.0.1:{server.server_port}/v1/events",
            data=json.dumps({"event_type": "unknown", "secret": "not recorded"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(request, timeout=2)
        except Exception as error:
            assert getattr(error, "code", None) == 400
        else:
            raise AssertionError("expected invalid event to be rejected")
    finally:
        server.shutdown()
        server.server_close()


def test_host_and_origin_checks():
    assert _host_is_local("127.0.0.1:8765")
    assert _host_is_local("localhost:8765")
    assert _host_is_local("[::1]:8765")
    assert not _host_is_local("evil.example")
    assert not _host_is_local("127.0.0.1.evil.example")
    assert not _host_is_local("")

    assert _origin_is_local("http://localhost:8765")
    assert _origin_is_local("http://127.0.0.1:8765")
    assert not _origin_is_local("http://evil.example")
    assert not _origin_is_local("http://127.0.0.1.evil.example")


def test_api_rejects_a_foreign_host_header(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = _running_server(state)
    try:
        status, body = _http(
            server,
            "/v1/events",
            json.dumps({"event_type": "model_output", "data": "hello"}),
            {"Content-Type": "application/json", "Host": "evil.example"},
        )

        assert (status, body["error"]) == (400, "invalid_host")
        assert state.rejections == 1
        assert state.events_seen == 0
    finally:
        server.shutdown()
        server.server_close()


def test_api_rejects_a_cross_origin_post(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = _running_server(state)
    try:
        status, body = _http(
            server,
            "/v1/events",
            json.dumps({"event_type": "model_output", "data": "hello"}),
            {"Content-Type": "application/json", "Origin": "http://evil.example"},
        )

        assert (status, body["error"]) == (403, "forbidden_origin")
    finally:
        server.shutdown()
        server.server_close()


def test_api_requires_a_json_content_type(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = _running_server(state)
    try:
        status, body = _http(
            server,
            "/v1/events",
            json.dumps({"event_type": "model_output"}),
            {"Content-Type": "text/plain"},
        )

        assert (status, body["error"]) == (415, "unsupported_media_type")
    finally:
        server.shutdown()
        server.server_close()


def test_api_rejects_an_oversized_request_body(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = _running_server(state)
    try:
        status, body = _http(
            server,
            "/v1/events",
            json.dumps({"event_type": "model_output", "data": "a" * (MAX_EVENT_BYTES + 1)}),
            {"Content-Type": "application/json"},
        )

        assert (status, body["error"]) == (400, "invalid_event")
    finally:
        server.shutdown()
        server.server_close()


def test_api_requires_the_bearer_token_when_configured(tmp_path):
    token = "test-token-value-1234"
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))
    server = _running_server(state, auth_token=token)
    try:
        status, body = _http(server, "/v1/status")
        assert (status, body["error"]) == (401, "unauthorized")

        status, body = _http(server, "/v1/status", None, {"Authorization": f"Bearer {token}"})
        assert status == 200
        assert body["auth"] == "bearer_token"

        status, body = _http(server, "/health")
        assert (status, body["status"]) == (200, "ok")

        status, body = _http(
            server,
            "/v1/events",
            json.dumps({"event_type": "model_output", "data": "hello"}),
            {"Content-Type": "application/json"},
        )
        assert (status, body["error"]) == (401, "unauthorized")
    finally:
        server.shutdown()
        server.server_close()


def test_status_reports_enforcement_mode_and_component_health(tmp_path):
    state = GuardState(Policy(), AuditLog(tmp_path / "audit.jsonl"))

    status = state.status()

    assert status["enforcement_mode"] == "none"
    assert status["enforcement_health"] == "unavailable"
    assert status["file_watcher"] == "disabled"
    assert status["runtime_monitor"] == "disabled"
    assert status["threat_feed"] == "disabled"
    assert status["auth"] == "disabled"
    assert status["rejections"] == 0


def test_sigterm_still_writes_the_audit_checkpoint(tmp_path):
    import signal
    import subprocess

    audit = tmp_path / "audit.jsonl"
    process = subprocess.Popen(
        [sys.executable, "-m", "ai_antivirus.agent_cli", "--port", "0", "--audit-log", str(audit)],
        cwd=Path(__file__).parents[1],
        env={**os.environ, "PYTHONPATH": "src"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        listening = process.stdout.readline()
        port = int(listening.rsplit(":", 1)[1].strip())
        request = Request(
            f"http://127.0.0.1:{port}/v1/events",
            data=json.dumps({"event_type": "model_output", "text": "reply"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{port}"},
            method="POST",
        )
        with urlopen(request, timeout=5):
            pass

        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()

    anchor = json.loads((tmp_path / "audit.jsonl.anchor").read_text(encoding="utf-8"))
    assert anchor["seq"] == 1
    assert anchor["entries"] == 1
