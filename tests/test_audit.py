from pathlib import Path
import sys
from threading import Thread

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.audit import AuditLog

ALLOWED = {"status": "allowed", "risk_score": 0, "findings": []}


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _append_entries(audit: AuditLog, count: int) -> None:
    for index in range(count):
        audit.append({"event_type": "model_output", "data": f"response {index}"}, ALLOWED)


def test_healthy_log_is_not_degraded(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    _append_entries(audit, 3)

    assert audit.degraded is False
    assert audit.verify()


def test_guard_starts_when_final_line_is_truncated(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 2)
    raw = path.read_bytes()
    path.write_bytes(raw[: len(raw) - 40])

    reopened = AuditLog(path)

    assert reopened.degraded is True
    assert reopened.verify() is False


def test_non_object_last_line_is_reported_as_damage(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 1)
    with path.open("a", encoding="utf-8") as stream:
        stream.write("[1, 2, 3]\n")

    reopened = AuditLog(path)

    assert reopened.degraded is True
    assert reopened.verify() is False


def test_damaged_log_still_accepts_new_evidence(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 1)
    with path.open("a", encoding="utf-8") as stream:
        stream.write('{"entry_hash": "deadbeef"\n')

    reopened = AuditLog(path)
    reopened.append({"event_type": "model_output"}, ALLOWED)

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 3
    assert reopened.verify() is False


def test_missing_log_starts_clean(tmp_path):
    audit = AuditLog(tmp_path / "nested" / "audit.jsonl")

    assert audit.degraded is False
    assert audit.verify()


def test_concurrent_appends_keep_the_chain_intact(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    workers = [Thread(target=_append_entries, args=(audit, 25)) for _ in range(3)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert audit.verify()
    assert len(_lines(tmp_path / "audit.jsonl")) == 75
