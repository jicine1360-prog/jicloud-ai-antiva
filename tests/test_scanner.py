import json
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.cli import main
from ai_antivirus.intel import ThreatFeed
from ai_antivirus.scanner import model_files, scan_model


def test_clean_safetensors_report(tmp_path):
    model = tmp_path / "model.safetensors"
    model.write_bytes((2).to_bytes(8, "little") + b"{}")

    report = scan_model(model)

    assert report["status"] == "clean"
    assert report["detected_format"] == "safetensors"
    assert len(report["sha256"]) == 64


def test_pickle_based_format_requires_review(tmp_path):
    model = tmp_path / "model.pt"
    model.write_bytes(b"untrusted model placeholder")

    report = scan_model(model)

    assert report["status"] == "review"
    assert any(item["code"] == "unsafe_serialization_format" for item in report["findings"])


def test_archive_path_traversal_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("../escape.py", "print('not executed')")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_path_traversal" for item in report["findings"])


def test_report_is_json_serializable(tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"GGUF" + (3).to_bytes(4, "little"))

    json.dumps(scan_model(model))


def test_model_files_recursively_lists_supported_artifacts(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (tmp_path / "model.gguf").write_bytes(b"model")
    (nested / "unsafe.pt").write_bytes(b"model")
    (nested / "notes.txt").write_text("not a model", encoding="utf-8")

    files = {path.name for path in model_files(tmp_path)}

    assert files == {"model.gguf", "unsafe.pt"}


def test_recursive_cli_streams_jsonl_reports(tmp_path, capsys):
    (tmp_path / "model.gguf").write_bytes(b"model")

    assert main([str(tmp_path), "--recursive", "--json"]) == 0

    report = json.loads(capsys.readouterr().out)
    assert report["path"] == str(tmp_path / "model.gguf")


def test_invalid_known_format_requires_review(tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"not a GGUF model")

    report = scan_model(model)

    assert report["status"] == "review"
    assert report["findings"][0]["code"] == "invalid_gguf_header"


def test_invalid_zip_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    model.write_bytes(b"not a ZIP archive")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert report["findings"][0]["code"] == "invalid_archive"


def test_windows_absolute_archive_path_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("C:\\Windows\\escape.py", "not executed")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_path_traversal" for item in report["findings"])


def test_threat_feed_blocks_listed_hash(tmp_path):
    import hashlib

    model = tmp_path / "model.safetensors"
    payload = (2).to_bytes(8, "little") + b"{}"
    model.write_bytes(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    feed_path = tmp_path / "feed.jsonl"
    feed_path.write_text(
        json.dumps({"sha256": sha256, "reason": "known malicious model"}) + "\n"
        + json.dumps({"sha256": "not-a-hash"}) + "\n",
        encoding="utf-8",
    )
    feed = ThreatFeed(feed_path)

    assert feed.skipped == 1
    report = scan_model(model, feed)

    assert report["status"] == "blocked"
    assert report["findings"][-1]["code"] == "threat_intel_match"


def test_cli_threat_feed_blocks_file(tmp_path, capsys):
    import hashlib

    model = tmp_path / "model.gguf"
    payload = b"GGUF" + (3).to_bytes(4, "little")
    model.write_bytes(payload)
    sha256 = hashlib.sha256(payload).hexdigest()
    feed_path = tmp_path / "feed.json"
    feed_path.write_text(json.dumps([{"sha256": sha256, "reason": "revoked"}]), encoding="utf-8")

    assert main([str(model), "--threat-feed", str(feed_path)]) == 1
    assert "threat_intel_match" in capsys.readouterr().out
