"""Safe, non-executing inspection of AI model artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from pathlib import PurePosixPath, PureWindowsPath
import hashlib
import stat
import struct
import zipfile

from .intel import ThreatFeed


SUPPORTED_EXTENSIONS = {
    ".bin",
    ".ckpt",
    ".gguf",
    ".onnx",
    ".safetensors",
    ".tflite",
    ".zip",
}
UNSAFE_SERIALIZATION_EXTENSIONS = {".bin", ".ckpt", ".joblib", ".pkl", ".pickle", ".pt", ".pth"}
SCANNABLE_EXTENSIONS = SUPPORTED_EXTENSIONS | UNSAFE_SERIALIZATION_EXTENSIONS
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".js", ".ps1", ".py", ".sh"}
NATIVE_EXTENSIONS = {".dll", ".dylib", ".exe", ".so"}
MAX_SAFETENSORS_HEADER_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_MEMBER_FINDINGS = 50
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 4 * 1024**3
MIN_ARCHIVE_BOMB_BYTES = 100 * 1024**2
ARCHIVE_COMPRESSION_RATIO = 100
PICKLE_MAX_PROTOCOL = 5
TORCH_ARCHIVE_PICKLE = "data.pkl"
ONNX_IR_VERSION_TAG = 0x08
ONNX_NEXT_FIELD_TAGS = {0x12, 0x1A, 0x22, 0x2A, 0x32}


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    evidence: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.evidence is not None:
            result["evidence"] = self.evidence
        return result


@dataclass
class ScanReport:
    path: str
    size_bytes: int
    sha256: str
    detected_format: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        severities = {finding.severity for finding in self.findings}
        if "high" in severities:
            return "blocked"
        if severities:
            return "review"
        return "clean"

    def as_dict(self) -> dict:
        return {
            "schema_version": 1,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "detected_format": self.detected_format,
            "status": self.status,
            "findings": [finding.as_dict() for finding in self.findings],
        }


def _open_regular_file(path: Path):
    """Open a file for reading without following symlinks.

    The watcher checks that a path is a regular file before scanning it, and a
    directory an untrusted process can write to may swap that entry between the
    check and the read.  Opening through a descriptor and checking it with fstat
    closes the window: every later read uses the same inode, and a symlink swap
    makes the open fail instead of reading someone else's file.  Windows has no
    O_NOFOLLOW, so there the check is limited to the regular-file test.
    """

    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"scan target must be a regular file: {path}") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"scan target must be a regular file: {path}")
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _sha256(stream) -> str:
    digest = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _format_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix:
        return suffix.removeprefix(".")
    return "unknown"


def _is_archive(stream) -> bool:
    return zipfile.is_zipfile(stream)


def _unsafe_archive_path(member_name: str) -> bool:
    normalized = member_name.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(member_name)
    return (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or bool(windows_path.drive)
        or ".." in posix_path.parts
    )


def _archive_member_findings(member: zipfile.ZipInfo) -> list[Finding]:
    """Report the per-member risks of one archive entry, without extracting it."""

    findings: list[Finding] = []
    normalized_member = member.filename.replace("\\", "/")
    suffix = Path(member.filename).suffix.lower()
    if (
        normalized_member == TORCH_ARCHIVE_PICKLE
        or normalized_member.endswith(f"/{TORCH_ARCHIVE_PICKLE}")
        or suffix in UNSAFE_SERIALIZATION_EXTENSIONS
    ):
        findings.append(
            Finding(
                "medium",
                "archive_unsafe_member",
                "Archive holds an object-serialized member; loading it can execute arbitrary code.",
                member.filename,
            )
        )
    if _unsafe_archive_path(member.filename):
        findings.append(
            Finding(
                "high",
                "archive_path_traversal",
                "Archive member can escape the extraction directory.",
                member.filename,
            )
        )

    if suffix in SCRIPT_EXTENSIONS or suffix in NATIVE_EXTENSIONS:
        findings.append(
            Finding(
                "high",
                "archive_executable_payload",
                "Archive contains a script or native binary; do not extract or load it.",
                member.filename,
            )
        )

    mode = member.external_attr >> 16
    if stat.S_ISLNK(mode):
        findings.append(
            Finding(
                "high",
                "archive_symlink",
                "Archive contains a symbolic link; extraction may escape its target directory.",
                member.filename,
            )
        )
    elif stat.S_IFMT(mode) in {stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK}:
        findings.append(
            Finding(
                "high",
                "archive_special_file",
                "Archive declares a device, FIFO, or socket member; extraction can block or corrupt the system.",
                member.filename,
            )
        )
    return findings


def _inspect_archive(stream, findings: list[Finding]) -> None:
    """Inspect archive metadata only, with bounds a hostile archive cannot exceed.

    Nothing is extracted or decompressed: the checks read the central directory.
    Per-member findings are capped so an archive declaring hundreds of thousands
    of entries cannot exhaust memory through the report itself.
    """

    members = 0
    uncompressed = 0
    compressed = 0
    reported = 0
    suppressed = 0
    stream.seek(0)
    with zipfile.ZipFile(stream) as archive:
        for member in archive.infolist():
            members += 1
            uncompressed += member.file_size
            compressed += member.compress_size
            if reported >= MAX_ARCHIVE_MEMBER_FINDINGS:
                suppressed += 1
                continue
            member_findings = _archive_member_findings(member)
            findings.extend(member_findings)
            reported += len(member_findings)

    if suppressed:
        findings.append(
            Finding(
                "medium",
                "archive_finding_limit",
                "Archive member findings were truncated at the scanner limit; treat the artifact as untrusted.",
                f"{suppressed} additional members not reported",
            )
        )
    if members > MAX_ARCHIVE_MEMBERS:
        findings.append(
            Finding(
                "medium",
                "archive_too_many_members",
                "Archive declares more members than the scanner inspects in one pass.",
                f"{members} members",
            )
        )
    if uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        findings.append(
            Finding(
                "high",
                "archive_bomb",
                "Archive declares more uncompressed data than the scanner accepts.",
                f"{uncompressed} bytes declared",
            )
        )
    elif (
        uncompressed >= MIN_ARCHIVE_BOMB_BYTES
        and compressed
        and uncompressed / compressed > ARCHIVE_COMPRESSION_RATIO
    ):
        findings.append(
            Finding(
                "high",
                "archive_bomb",
                "Archive compression ratio is consistent with a decompression bomb.",
                f"{uncompressed} bytes from {compressed} compressed bytes",
            )
        )


def _inspect_safetensors(stream, size: int, findings: list[Finding]) -> None:
    stream.seek(0)
    header_length_data = stream.read(8)
    if len(header_length_data) != 8:
        findings.append(Finding("medium", "invalid_safetensors_header", "SafeTensors header is missing."))
        return
    header_length = struct.unpack("<Q", header_length_data)[0]
    if header_length < 2 or header_length > MAX_SAFETENSORS_HEADER_BYTES or header_length > size - 8:
        findings.append(Finding("medium", "invalid_safetensors_header", "SafeTensors header length is invalid."))
        return
    try:
        header = json.loads(stream.read(header_length))
    except (UnicodeDecodeError, json.JSONDecodeError):
        findings.append(Finding("medium", "invalid_safetensors_header", "SafeTensors header is not valid JSON."))
        return
    if not isinstance(header, dict):
        findings.append(Finding("medium", "invalid_safetensors_header", "SafeTensors header is not an object."))
        return
    _inspect_safetensors_ranges(header, header_length, size, findings)


def _inspect_safetensors_ranges(header: dict, header_length: int, size: int, findings: list[Finding]) -> None:
    """Check the byte ranges a SafeTensors header declares for its tensors.

    A SafeTensors file is a JSON header followed by one data region, and every
    tensor declares ``data_offsets`` relative to the end of that header.  A range
    that runs past the end of the file, overlaps another tensor, or leaves bytes
    that no tensor claims is either a corrupt artifact or a place to keep content
    no loader will ever hand to the model.  Only the header is read; the tensor
    data is never touched.
    """

    data_length = size - 8 - header_length
    ranges: list[tuple[int, int]] = []
    for name, entry in header.items():
        if name == "__metadata__":
            continue
        offsets = entry.get("data_offsets") if isinstance(entry, dict) else None
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(isinstance(value, int) and not isinstance(value, bool) for value in offsets)
            or offsets[0] < 0
            or offsets[1] < offsets[0]
        ):
            findings.append(
                Finding(
                    "medium",
                    "safetensors_invalid_tensor_range",
                    "SafeTensors tensor entry declares no usable data_offsets.",
                    name,
                )
            )
            continue
        ranges.append((offsets[0], offsets[1]))
    if not ranges:
        return

    declared_end = max(end for _, end in ranges)
    if declared_end > data_length:
        findings.append(
            Finding(
                "medium",
                "safetensors_offsets_out_of_range",
                "SafeTensors tensor data extends past the end of the file.",
                f"declared {declared_end} bytes, file holds {data_length}",
            )
        )

    ordered = sorted(ranges)
    highest = ordered[0][1]
    for begin, end in ordered[1:]:
        if begin < highest:
            findings.append(
                Finding("medium", "safetensors_overlapping_tensors", "SafeTensors tensors share bytes.")
            )
            break
        highest = max(highest, end)

    trailing = data_length - declared_end
    if trailing > 0:
        findings.append(
            Finding(
                "low",
                "safetensors_trailing_data",
                "File has bytes after the last tensor that no tensor claims.",
                f"{trailing} bytes",
            )
        )


def _pickle_protocol(stream) -> int | None:
    """Return the pickle protocol version when the file starts with a framing opcode.

    Torch and TensorFlow checkpoints are pickle streams, and loading one runs
    arbitrary code.  Detecting the framing is a much stronger signal than the
    file extension alone.
    """

    stream.seek(0)
    head = stream.read(2)
    if head[:1] != b"\x80":
        return None
    version = head[1]
    return version if version <= PICKLE_MAX_PROTOCOL else None


def _read_varint(data: bytes, cursor: int) -> tuple[int | None, int]:
    value = 0
    shift = 0
    while cursor < len(data):
        byte = data[cursor]
        value |= (byte & 0x7F) << shift
        cursor += 1
        if not byte & 0x80:
            return value, cursor
        shift += 7
        if shift > 63:
            return None, cursor
    return None, cursor


def _inspect_onnx(stream, findings: list[Finding]) -> None:
    """Check the leading ModelProto fields without a protobuf dependency.

    Only the preamble is validated: field 1 must be a varint ``ir_version``
    followed by a plausible field tag.  Graph contents are not interpreted.
    """

    stream.seek(0)
    head = stream.read(64)
    if not head or head[0] != ONNX_IR_VERSION_TAG:
        findings.append(
            Finding(
                "medium",
                "invalid_onnx_header",
                "ONNX ModelProto does not start with the ir_version field.",
            )
        )
        return
    ir_version, cursor = _read_varint(head, 1)
    if ir_version is None or ir_version < 1 or cursor >= len(head) or head[cursor] not in ONNX_NEXT_FIELD_TAGS:
        findings.append(
            Finding(
                "medium",
                "invalid_onnx_header",
                "ONNX ModelProto preamble is malformed.",
                f"ir_version={ir_version}" if ir_version is not None else "unreadable ir_version",
            )
        )


def _inspect_known_format(stream, suffix: str, size: int, findings: list[Finding]) -> None:
    if suffix == ".safetensors":
        _inspect_safetensors(stream, size, findings)
        return
    if suffix == ".onnx":
        _inspect_onnx(stream, findings)
        return
    stream.seek(0)
    prefix = stream.read(8)
    if suffix == ".gguf" and (prefix[:4] != b"GGUF" or len(prefix) != 8):
        findings.append(Finding("medium", "invalid_gguf_header", "GGUF magic or version header is invalid."))
    elif suffix == ".tflite" and prefix[4:8] != b"TFL3":
        findings.append(Finding("medium", "invalid_tflite_header", "TFLite file identifier is invalid."))


def scan_model(path_value: str | Path, threat_feed: ThreatFeed | None = None) -> dict:
    """Inspect a model artifact without importing or executing it."""

    path = Path(path_value).expanduser()
    if not path.exists():
        raise FileNotFoundError(path)

    findings: list[Finding] = []
    suffix = path.suffix.lower()
    detected_format = _format_for(path)
    # One descriptor for the whole scan: the regular-file check and every read
    # below refer to the same inode, so an entry swapped inside a watched
    # directory cannot redirect the scan to someone else's file.
    with _open_regular_file(path) as stream:
        size = os.fstat(stream.fileno()).st_size
        is_archive = _is_archive(stream)

        if suffix not in SUPPORTED_EXTENSIONS and suffix not in UNSAFE_SERIALIZATION_EXTENSIONS:
            findings.append(
                Finding(
                    "low",
                    "unknown_format",
                    "File extension is not in the initial model format allowlist.",
                    suffix or "no extension",
                )
            )

        if suffix in UNSAFE_SERIALIZATION_EXTENSIONS and not is_archive:
            protocol = _pickle_protocol(stream)
            if protocol is None:
                findings.append(
                    Finding(
                        "medium",
                        "unsafe_serialization_format",
                        "Format may require deserialization; use a restricted loader and sandbox.",
                        suffix,
                    )
                )
            else:
                findings.append(
                    Finding(
                        "medium",
                        "pickle_framed_artifact",
                        "Artifact is a pickle stream; loading it can execute arbitrary code.",
                        f"pickle protocol {protocol}",
                    )
                )

        if suffix == ".zip" and not is_archive:
            findings.append(Finding("high", "invalid_archive", "File has an invalid ZIP structure."))
        elif is_archive:
            detected_format = "zip"
            if suffix != ".zip":
                findings.append(
                    Finding(
                        "medium",
                        "format_extension_mismatch",
                        "ZIP content does not match the file extension.",
                        suffix,
                    )
                )
            try:
                _inspect_archive(stream, findings)
            except zipfile.BadZipFile:
                findings.append(
                    Finding("high", "invalid_archive", "File has an invalid ZIP structure.")
                )
        elif suffix in {".gguf", ".onnx", ".safetensors", ".tflite"}:
            _inspect_known_format(stream, suffix, size, findings)

        sha256 = _sha256(stream)

    if threat_feed is not None:
        indicator = threat_feed.lookup(sha256)
        if indicator is not None:
            findings.append(
                Finding(
                    "high",
                    "threat_intel_match",
                    indicator.reason or "SHA-256 matched the configured threat feed.",
                    indicator.sha256,
                )
            )

    return ScanReport(
        path=str(path),
        size_bytes=size,
        sha256=sha256,
        detected_format=detected_format,
        findings=findings,
    ).as_dict()


def model_files(root_value: str | Path):
    """Yield supported model artifacts below a directory without following links."""

    root = Path(root_value).expanduser()
    if not root.is_dir():
        raise ValueError(f"scan root must be a directory: {root}")
    try:
        for path in root.rglob("*"):
            if (
                path.suffix.lower() in SCANNABLE_EXTENSIONS
                and path.is_file()
                and not path.is_symlink()
            ):
                yield path
    except OSError as error:
        raise ValueError(f"unable to read scan root: {root}") from error
