"""Risk scoring for events emitted by an AI host integration."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from pathlib import Path


SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}", re.IGNORECASE),
    "generic_secret": re.compile(r"\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,]{8,}", re.IGNORECASE),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
}
SENSITIVE_PATH_PARTS = {".env", ".ssh", "credentials", "id_rsa", "shadow"}
PROMPT_INJECTION_PATTERN = re.compile(
    r"(?:ignore|disregard)\s+(?:all\s+)?(?:previous|prior)\s+instructions|system\s+prompt",
    re.IGNORECASE,
)
MAX_EVENT_TEXT_CHARS = 256 * 1024


@dataclass(frozen=True)
class Policy:
    allowed_hosts: frozenset[str] = frozenset()
    allowed_paths: tuple[str, ...] = ()
    flag_unknown_hosts: bool = False


@dataclass
class EventDecision:
    status: str
    risk_score: int
    findings: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "findings": self.findings,
        }


def _add(decision: EventDecision, score: int, code: str, message: str) -> None:
    decision.risk_score = min(100, decision.risk_score + score)
    decision.findings.append({"code": code, "message": message})


def _path_is_allowed(path_value: str, allowed_paths: tuple[str, ...]) -> bool:
    if not allowed_paths:
        return True
    try:
        candidate = Path(path_value).expanduser().resolve(strict=False)
        return any(candidate == Path(root).expanduser().resolve(strict=False) or root_path in candidate.parents for root in allowed_paths for root_path in [Path(root).expanduser().resolve(strict=False)])
    except (OSError, RuntimeError):
        return False


def _scan_text(decision: EventDecision, text: str) -> None:
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            _add(decision, 80, "sensitive_data_detected", f"Possible sensitive data detected: {name}.")
    if PROMPT_INJECTION_PATTERN.search(text):
        _add(decision, 35, "prompt_injection_signal", "Input contains a prompt-injection pattern.")


def _text_field(event: dict, name: str, required: bool = False, maximum: int = 4096) -> str | None:
    value = event.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"invalid {name}")
    return value


def _integer_field(event: dict, name: str, default: int = 0, minimum: int = 0) -> int:
    value = event.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"invalid {name}")
    return value


def _add_attribution(event: dict, normalized: dict) -> None:
    """Carry optional process attribution so audit records stay attributable."""

    if "pid" in event:
        normalized["pid"] = _integer_field(event, "pid", minimum=1)
    if "process_name" in event:
        normalized["process_name"] = _text_field(event, "process_name", maximum=255)


def normalize_event(event: dict) -> dict:
    """Return the small, bounded event schema accepted by the local API."""

    event_type = _text_field(event, "event_type", required=True, maximum=64)
    normalized = {"event_type": event_type}
    if event_type == "file_read":
        normalized["path"] = _text_field(event, "path", required=True)
        normalized["file_count"] = _integer_field(event, "file_count", default=1, minimum=1)
    elif event_type == "network_egress":
        normalized["host"] = _text_field(event, "host", required=True, maximum=255)
        normalized["port"] = _integer_field(event, "port", default=0, minimum=0)
        if normalized["port"] > 65535:
            raise ValueError("invalid port")
        normalized["bytes"] = _integer_field(event, "bytes")
    elif event_type == "tool_call":
        normalized["tool"] = _text_field(event, "tool", required=True, maximum=128)
    elif event_type == "process_start":
        normalized["pid"] = _integer_field(event, "pid", minimum=1)
        normalized["process_name"] = _text_field(event, "process_name", required=True, maximum=255)
    elif event_type != "model_output":
        raise ValueError("unsupported event_type")
    if event_type != "process_start":
        _add_attribution(event, normalized)
    if "data" in event:
        normalized["data"] = _text_field(event, "data", maximum=MAX_EVENT_TEXT_CHARS)
    return normalized


def evaluate_event(event: dict, policy: Policy = Policy()) -> EventDecision:
    """Evaluate an event without retaining its raw payload."""

    decision = EventDecision(status="allowed", risk_score=0)
    event_type = str(event.get("event_type", "unknown"))

    if event_type == "file_read":
        path_value = str(event.get("path", ""))
        path_parts = {part.lower() for part in Path(path_value).parts}
        if path_parts & SENSITIVE_PATH_PARTS:
            _add(decision, 75, "sensitive_path_access", "AI process accessed a sensitive host path.")
        if path_value and not _path_is_allowed(path_value, policy.allowed_paths):
            _add(decision, 60, "path_outside_allowlist", "File access is outside the configured path allowlist.")
        if _integer_field(event, "file_count", default=1, minimum=1) > 100:
            _add(decision, 35, "bulk_file_access", "Event reports a large file access batch.")

    if event_type == "network_egress":
        host = str(event.get("host", "")).lower().rstrip(".")
        if policy.flag_unknown_hosts and host not in policy.allowed_hosts:
            _add(decision, 75, "host_outside_allowlist", "Network destination is not in the configured allowlist.")
        if _integer_field(event, "bytes") > 10 * 1024 * 1024:
            _add(decision, 35, "large_egress", "Event reports a large outbound transfer.")

    if event_type == "tool_call":
        tool = str(event.get("tool", "")).lower()
        if tool in {"shell", "exec", "subprocess", "upload", "send_email"}:
            _add(decision, 55, "high_impact_tool", "AI requested a high-impact tool call.")

    payload = event.get("data")
    if isinstance(payload, str):
        _scan_text(decision, payload)

    if decision.risk_score >= 80:
        decision.status = "blocked"
    elif decision.risk_score >= 40:
        decision.status = "review"
    return decision


def payload_fingerprint(payload: object) -> str | None:
    """Return an unhashed-payload correlation hash; it is not a secret vault."""

    if payload is None:
        return None
    text = str(payload).encode("utf-8", errors="replace")
    return hashlib.sha256(text).hexdigest()
