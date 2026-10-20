import hashlib
import json
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


def test_verify_stays_correct_while_the_log_grows(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")

    for index in range(50):
        audit.append({"event_type": "model_output", "data": f"response {index}"}, ALLOWED)
        assert audit.verify()

    assert audit.entries == 50
    assert audit.verify(full=True)


def test_entries_are_numbered_in_order(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    _append_entries(audit, 3)

    sequences = [json.loads(line)["seq"] for line in _lines(tmp_path / "audit.jsonl")]
    assert sequences == [1, 2, 3]
    assert audit.entries == 3


def test_removed_tail_is_detected_from_the_anchor(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 4)
    audit.checkpoint()

    lines = _lines(path)
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    reopened = AuditLog(path)

    assert reopened.degraded is True
    assert reopened.verify() is False


def test_replaced_tail_is_detected_from_the_anchor(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 3)
    audit.checkpoint()

    lines = _lines(path)
    forged = json.loads(lines[-1])
    forged["event"] = {"event_type": "model_output", "data": "edited"}
    lines[-1] = json.dumps(forged, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert AuditLog(path).degraded is True


def test_a_degraded_log_keeps_its_old_anchor(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 4)
    audit.checkpoint()

    lines = _lines(path)
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    reopened = AuditLog(path)
    reopened.append({"event_type": "model_output"}, ALLOWED)

    anchor = json.loads((tmp_path / "audit.jsonl.anchor").read_text(encoding="utf-8"))
    assert anchor["seq"] == 4
    assert AuditLog(path).degraded is True


def test_a_lagging_anchor_does_not_raise_a_false_alarm(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 25)

    reopened = AuditLog(path)

    assert reopened.degraded is False
    assert reopened.entries == 25


def test_runtime_truncation_fails_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 3)
    assert audit.verify()

    path.write_text("\n".join(_lines(path)[:1]) + "\n", encoding="utf-8")

    assert audit.verify() is False


def test_sequence_gap_is_rejected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    _append_entries(audit, 3)

    lines = _lines(path)
    middle = json.loads(lines[1])
    middle["seq"] = 9
    lines[1] = json.dumps(middle, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert AuditLog(path).verify() is False


def test_legacy_log_without_sequence_numbers_still_verifies(tmp_path):
    # Written by hand the way an older build did it: no seq field, chain built
    # from scratch so the hashes line up.
    path = tmp_path / "audit.jsonl"
    lines = []
    previous_hash = None
    for index in range(2):
        entry = {
            "timestamp": f"2026-01-0{index + 1}T00:00:00+00:00",
            "previous_hash": previous_hash,
            "event": {"event_type": "model_output", "data": f"response {index}"},
            "decision": ALLOWED,
        }
        entry["entry_hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        previous_hash = entry["entry_hash"]
        lines.append(json.dumps(entry, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reopened = AuditLog(path)

    assert reopened.degraded is False
    assert reopened.verify()
    reopened.append({"event_type": "model_output"}, ALLOWED)
    assert reopened.verify()


def test_anchor_checkpoint_records_the_tail(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    _append_entries(audit, 3)
    audit.checkpoint()

    anchor = tmp_path / "audit.jsonl.anchor"

    assert anchor.exists()
    recorded = json.loads(anchor.read_text(encoding="utf-8"))
    assert recorded["seq"] == 3
    assert recorded["entries"] == 3


def _segments(audit: AuditLog) -> list[Path]:
    return sorted(
        path
        for path in audit.path.parent.iterdir()
        if path != audit.path
        and path.name.startswith(audit.path.stem + ".")
        and path.name.endswith(audit.path.suffix)
        and path.name[len(audit.path.stem) + 1 : -len(audit.path.suffix)].replace("-", "").isdigit()
    )


def test_rotation_keeps_the_chain_running(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    _append_entries(audit, 40)

    assert audit.segments >= 2
    assert not audit.degraded
    assert audit.verify(full=True)

    restarted = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    assert not restarted.degraded
    assert restarted.verify(full=True)
    assert restarted._last_seq == 40


def test_rotation_anchors_every_closed_segment(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    _append_entries(audit, 40)

    for segment in _segments(audit):
        anchor = segment.with_name(segment.name + ".anchor")
        assert anchor.exists(), segment.name
        recorded = json.loads(anchor.read_text(encoding="utf-8"))
        assert recorded["seq"] > 0


def test_a_removed_segment_leaves_a_gap(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    _append_entries(audit, 40)
    audit.checkpoint()
    segments = _segments(audit)
    assert len(segments) >= 2

    removed = segments[0]
    removed.unlink()
    removed.with_name(removed.name + ".anchor").unlink()

    restarted = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    assert restarted.degraded
    assert not restarted.verify()


def test_retention_removes_bodies_but_keeps_anchors(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000, keep_segments=2)
    _append_entries(audit, 60)
    audit.checkpoint()

    bodies = _segments(audit)
    assert len(bodies) == 2
    assert audit.expired_segments >= 1
    anchors = [
        path for path in audit.path.parent.iterdir() if path.name.endswith(".jsonl.anchor")
    ]
    assert len(anchors) >= audit.expired_segments + 1

    restarted = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000, keep_segments=2)
    assert not restarted.degraded
    assert restarted.verify(full=True)
    kinds = [
        entry["event"].get("kind")
        for entry in map(json.loads, _lines(audit.path))
        if isinstance(entry.get("event"), dict)
    ]
    assert "audit_segment_expired" in kinds


def test_retention_never_deletes_an_unanchored_segment(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000)
    _append_entries(audit, 30)
    audit.checkpoint()
    segments = _segments(audit)
    assert len(segments) >= 2
    for segment in segments:
        segment.with_name(segment.name + ".anchor").unlink()

    bounded = AuditLog(tmp_path / "audit.jsonl", max_bytes=2_000, keep_segments=1)
    _append_entries(bounded, 20)

    assert bounded.retention_blocked
    assert len(_segments(bounded)) == len(segments)
