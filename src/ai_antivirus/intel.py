"""SHA-256 threat-intelligence feed loading and matching."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re


HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ThreatIndicator:
    sha256: str
    reason: str = ""
    source: str = ""


class ThreatFeed:
    """A local, lowercase-hex SHA-256 block list loaded from JSONL or JSON."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.indicators: dict[str, ThreatIndicator] = {}
        self.skipped = 0
        self._load()

    def _load(self) -> None:
        try:
            content = self.path.read_text(encoding="utf-8")
        except OSError as error:
            raise ValueError(f"unable to read threat feed: {self.path}") from error
        records: list[dict] = []
        stripped = content.strip()
        if not stripped:
            return
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            for line in stripped.splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    self.skipped += 1
                    continue
                if isinstance(record, dict):
                    records.append(record)
                else:
                    self.skipped += 1
        else:
            if isinstance(parsed, dict) and isinstance(parsed.get("indicators"), list):
                parsed = parsed["indicators"]
            if isinstance(parsed, dict):
                records = [parsed]
            elif isinstance(parsed, list):
                records = [item for item in parsed if isinstance(item, dict)]
                self.skipped += len(parsed) - len(records)
            else:
                raise ValueError("threat feed must be a JSON array or JSONL records")
        for record in records:
            sha256 = str(record.get("sha256", "")).strip().lower()
            if not HEX64.match(sha256):
                self.skipped += 1
                continue
            self.indicators[sha256] = ThreatIndicator(
                sha256,
                str(record.get("reason", "")),
                str(record.get("source", "")),
            )

    def lookup(self, sha256: str) -> ThreatIndicator | None:
        return self.indicators.get(sha256.strip().lower())
