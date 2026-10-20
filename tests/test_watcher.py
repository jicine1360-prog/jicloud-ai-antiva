from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.intel import ThreatFeed
from ai_antivirus.watcher import ModelWatcher


def test_watcher_scans_only_after_file_is_stable(tmp_path):
    model = tmp_path / "model.safetensors"
    model.write_bytes((2).to_bytes(8, "little") + b"{}")
    watcher = ModelWatcher((str(tmp_path),), interval_seconds=1)

    assert watcher.poll_once() == []
    results = watcher.poll_once()

    assert len(results) == 1
    assert results[0].report["status"] == "clean"
    assert watcher.poll_once() == []


def test_watcher_quarantines_blocked_model(tmp_path):
    model = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("../escape.py", "not executed")
    quarantine = tmp_path.parent / "quarantine"
    watcher = ModelWatcher((str(tmp_path),), interval_seconds=1, quarantine_dir=str(quarantine))

    watcher.poll_once()
    results = watcher.poll_once()

    assert len(results) == 1
    assert results[0].report["status"] == "blocked"
    assert results[0].quarantined_to is not None
    assert results[0].quarantine_error is None
    assert not model.exists()
    quarantined = Path(results[0].quarantined_to)
    assert quarantined.exists()
    if sys.platform == "win32":
        # os.chmod on Windows only toggles the read-only flag, so the mode
        # assertion is Linux-specific.  The portable enforcement here is the
        # atomic move out of the watched directory.
        assert quarantined.read_bytes()
    else:
        assert quarantined.stat().st_mode & 0o777 == 0o600


def test_watcher_records_quarantine_failure_when_file_changes(tmp_path, monkeypatch):
    model = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("../escape.py", "not executed")
    quarantine = tmp_path.parent / "quarantine"
    watcher = ModelWatcher((str(tmp_path),), interval_seconds=1, quarantine_dir=str(quarantine))
    watcher.poll_once()
    original_quarantine = watcher._quarantine

    def changed_file(path, report, signature):
        model.write_bytes(b"changed")
        return original_quarantine(path, report, signature)

    monkeypatch.setattr(watcher, "_quarantine", changed_file)
    results = watcher.poll_once()
    assert len(results) == 1
    assert results[0].report["status"] == "blocked"
    assert results[0].quarantined_to is None
    assert results[0].quarantine_error == "model changed while it was being scanned"
    assert watcher.last_error == "model changed while it was being scanned"


def test_watcher_rejects_quarantine_inside_watched_directory(tmp_path):
    try:
        ModelWatcher((str(tmp_path),), quarantine_dir=str(tmp_path / "quarantine"))
    except ValueError as error:
        assert "must not be inside" in str(error)
    else:
        raise AssertionError("expected quarantine path validation to fail")


def test_watcher_quarantines_hash_listed_clean_model(tmp_path):
    import hashlib
    import json

    payload = (2).to_bytes(8, "little") + b"{}"
    sha256 = hashlib.sha256(payload).hexdigest()
    model = tmp_path / "model.safetensors"
    model.write_bytes(payload)
    feed_path = tmp_path.parent / "feed.jsonl"
    feed_path.write_text(json.dumps({"sha256": sha256, "reason": "revoked model"}) + "\n", encoding="utf-8")
    quarantine = tmp_path.parent / "quarantine"
    watcher = ModelWatcher(
        (str(tmp_path),),
        interval_seconds=1,
        quarantine_dir=str(quarantine),
        threat_feed=ThreatFeed(feed_path),
    )

    watcher.poll_once()
    results = watcher.poll_once()

    assert len(results) == 1
    assert results[0].report["status"] == "blocked"
    assert results[0].quarantined_to is not None
    assert results[0].quarantine_error is None
    assert not model.exists()
