import json
import os
from pathlib import Path
import stat
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from ai_antivirus.cli import main
from ai_antivirus.intel import ThreatFeed
from ai_antivirus.scanner import (
    MAX_ARCHIVE_MEMBER_FINDINGS,
    model_files,
    scan_model,
)


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


def test_archive_symlink_member_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        info = zipfile.ZipInfo("weights/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "/etc/passwd")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_symlink" for item in report["findings"])


def test_archive_executable_payload_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("weights.so", b"\x7fELF fake native payload")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_executable_payload" for item in report["findings"])


def test_decompression_bomb_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(model, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("huge.bin", "w", force_zip64=True) as stream:
            for _ in range(101):
                stream.write(chunk)

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_bomb" for item in report["findings"])
    assert model.stat().st_size < 1024 * 1024


def test_high_ratio_but_small_archive_is_not_flagged_as_a_bomb(tmp_path):
    model = tmp_path / "model.zip"
    payload = bytes(range(256)) * 4096
    with zipfile.ZipFile(model, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("model.safetensors", payload)

    report = scan_model(model)

    assert "archive_bomb" not in [item["code"] for item in report["findings"]]


def test_archive_member_count_is_bounded(tmp_path, monkeypatch):
    from ai_antivirus import scanner

    monkeypatch.setattr(scanner, "MAX_ARCHIVE_MEMBERS", 100)
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        for index in range(105):
            archive.writestr(f"shard-{index}.bin", b"x")

    report = scan_model(model)

    assert "archive_too_many_members" in [item["code"] for item in report["findings"]]
    assert len(report["findings"]) <= MAX_ARCHIVE_MEMBER_FINDINGS + 2


def test_archive_special_file_member_is_blocked(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        info = zipfile.ZipInfo("weights/fifo")
        info.external_attr = (stat.S_IFIFO | 0o644) << 16
        archive.writestr(info, "")

    report = scan_model(model)

    assert report["status"] == "blocked"
    assert any(item["code"] == "archive_special_file" for item in report["findings"])


def test_archive_member_findings_are_capped(tmp_path):
    model = tmp_path / "model.zip"
    with zipfile.ZipFile(model, "w") as archive:
        for index in range(300):
            archive.writestr(f"../escape-{index}.dat", "not executed")

    report = scan_model(model)

    codes = [item["code"] for item in report["findings"]]
    assert codes.count("archive_path_traversal") == MAX_ARCHIVE_MEMBER_FINDINGS
    assert "archive_finding_limit" in codes
    assert report["status"] == "blocked"


def test_pickle_framed_checkpoint_is_reported_precisely(tmp_path):
    # Signature copied from a live 4x-UltraSharp.pth checkpoint.
    model = tmp_path / "upscaler.pth"
    model.write_bytes(b"\x80\x02\x8a\nl\xfc\x9cF\xf9 j\xa8P\x19.\x80\x02M\xe9\x03." + b"\0" * 64)

    report = scan_model(model)

    codes = [item["code"] for item in report["findings"]]
    assert "pickle_framed_artifact" in codes
    assert "unsafe_serialization_format" not in codes
    assert "unknown_format" not in codes
    assert report["status"] == "review"


def test_raw_tensor_blob_without_pickle_framing_keeps_the_extension_signal(tmp_path):
    model = tmp_path / "dense.bin"
    model.write_bytes(b"\xfc\x15\x81\x0f\x04\xf7\x05\n" + b"\0" * 64)

    report = scan_model(model)

    codes = [item["code"] for item in report["findings"]]
    assert codes == ["unsafe_serialization_format"]


def test_torch_zip_archive_reports_its_pickle_member(tmp_path):
    model = tmp_path / "checkpoint.pt"
    with zipfile.ZipFile(model, "w") as archive:
        archive.writestr("checkpoint/version", "3")
        archive.writestr("checkpoint/data.pkl", b"\x80\x02}q\x00.")
        archive.writestr("checkpoint/data/0", b"\0" * 32)

    report = scan_model(model)

    assert "archive_unsafe_member" in [item["code"] for item in report["findings"]]
    assert report["status"] == "review"


def test_valid_onnx_preamble_is_accepted(tmp_path):
    # Preamble copied from a live pytorch-exported sound_model.onnx.
    model = tmp_path / "sound_model.onnx"
    model.write_bytes(b"\x08\n\x12\x07pytorch\x1a\n2.14.0+cpu:" + b"\0" * 32)

    report = scan_model(model)

    codes = [item["code"] for item in report["findings"]]
    assert "invalid_onnx_header" not in codes
    assert "format_not_validated" not in codes
    assert report["status"] == "clean"


def test_onnx_with_a_bad_preamble_is_flagged(tmp_path):
    model = tmp_path / "fake.onnx"
    model.write_bytes(b"this is not a ModelProto" + b"\0" * 32)

    report = scan_model(model)

    assert "invalid_onnx_header" in [item["code"] for item in report["findings"]]
    assert report["status"] == "review"


def test_symlink_is_refused_before_any_read(tmp_path):
    if os.name == "nt":
        # Windows has no O_NOFOLLOW; opening a symlink resolves the target and
        # the symlink refusal cannot be enforced at open time.
        pytest.skip("symlink refusal requires O_NOFOLLOW")
    real = tmp_path / "real.safetensors"
    real.write_bytes((2).to_bytes(8, "little") + b"{}")
    link = tmp_path / "link.safetensors"
    link.symlink_to(real)

    with pytest.raises(ValueError):
        scan_model(link)


def test_fifo_is_refused_without_blocking(tmp_path):
    # A FIFO would block an ordinary open() forever; the scanner opens with
    # O_NONBLOCK and rejects anything that is not a regular file instead.
    if not hasattr(os, "mkfifo"):
        pytest.skip("mkfifo is not available on this platform")
    fifo = tmp_path / "model.safetensors"
    os.mkfifo(fifo)

    with pytest.raises(ValueError):
        scan_model(fifo)


def test_directory_is_refused(tmp_path):
    with pytest.raises(ValueError):
        scan_model(tmp_path)


def test_archive_member_with_a_serialized_extension_is_flagged(tmp_path):
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("weights/model.pkl", b"\x80\x04}q\x00.")
        bundle.writestr("payload.pt", b"\x80\x02\x8a\nl\xfc\x9cF\xf9")
        bundle.writestr("config.json", "{}")

    report = scan_model(archive)

    unsafe = [item for item in report["findings"] if item["code"] == "archive_unsafe_member"]
    assert sorted(item["evidence"] for item in unsafe) == ["payload.pt", "weights/model.pkl"]
    assert report["status"] == "review"


def _safetensors_bytes(header: dict, data: bytes) -> bytes:
    body = json.dumps(header).encode("utf-8")
    return len(body).to_bytes(8, "little") + body + data


def _tensor(offsets):
    return {"dtype": "F32", "shape": [1], "data_offsets": offsets}


def test_safetensors_bytes_nobody_claims_are_reported(tmp_path):
    model = tmp_path / "padded.safetensors"
    model.write_bytes(_safetensors_bytes({"a": _tensor([0, 4])}, b"\0" * 4 + b"hidden"))

    report = scan_model(model)

    assert "safetensors_trailing_data" in [item["code"] for item in report["findings"]]
    assert report["status"] == "review"


def test_safetensors_offsets_past_the_end_are_reported(tmp_path):
    model = tmp_path / "truncated.safetensors"
    model.write_bytes(_safetensors_bytes({"a": _tensor([0, 64])}, b"\0" * 4))

    report = scan_model(model)

    assert "safetensors_offsets_out_of_range" in [item["code"] for item in report["findings"]]


def test_safetensors_overlapping_tensors_are_reported(tmp_path):
    model = tmp_path / "overlap.safetensors"
    header = {"a": _tensor([4, 12]), "b": _tensor([0, 8])}
    model.write_bytes(_safetensors_bytes(header, b"\0" * 12))

    report = scan_model(model)

    assert "safetensors_overlapping_tensors" in [item["code"] for item in report["findings"]]


def test_safetensors_entry_without_offsets_is_reported(tmp_path):
    model = tmp_path / "broken.safetensors"
    model.write_bytes(_safetensors_bytes({"a": {"dtype": "F32", "shape": [1]}}, b"\0" * 4))

    report = scan_model(model)

    codes = [(item["code"], item.get("evidence")) for item in report["findings"]]
    assert ("safetensors_invalid_tensor_range", "a") in codes


def test_safetensors_metadata_entry_is_not_treated_as_a_tensor(tmp_path):
    model = tmp_path / "metadata.safetensors"
    header = {"__metadata__": {"format": "pt"}, "a": _tensor([0, 4])}
    model.write_bytes(_safetensors_bytes(header, b"\0" * 4))

    report = scan_model(model)

    assert report["status"] == "clean"
    assert report["findings"] == []
