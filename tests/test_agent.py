import json
from pathlib import Path
import sys
from threading import Thread
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.agent import GuardServer, GuardState
from ai_antivirus.audit import AuditLog
from ai_antivirus.policy import Policy
from ai_antivirus.watcher import WatchResult


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
