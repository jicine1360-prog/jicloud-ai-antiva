"""Command-line interface for the initial scanner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .scanner import model_files, scan_model
from .intel import ThreatFeed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safely inspect an AI model artifact.")
    parser.add_argument("path", type=Path, help="model artifact to scan")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument("--recursive", action="store_true", help="scan model artifacts below a directory")
    parser.add_argument("--threat-feed", type=Path, help="JSONL or JSON file of blocked SHA-256 indicators")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        threat_feed = ThreatFeed(args.threat_feed) if args.threat_feed else None
    except ValueError as error:
        print(f"error: {error}")
        return 2
    if args.path.is_dir():
        if not args.recursive:
            print("error: directory scanning requires --recursive")
            return 2
        return _scan_directory(args.path, args.json, threat_feed)
    if args.recursive:
        print("error: --recursive requires a directory")
        return 2
    try:
        report = scan_model(args.path, threat_feed)
    except (FileNotFoundError, ValueError) as error:
        print(f"error: {error}")
        return 2
    _print_report(report, args.json)
    return 1 if report["status"] == "blocked" else 0


def _scan_directory(path: Path, as_json: bool, threat_feed: ThreatFeed | None) -> int:
    blocked = False
    failed = False
    try:
        for model_path in model_files(path):
            try:
                report = scan_model(model_path, threat_feed)
                blocked = blocked or report["status"] == "blocked"
                _print_report(report, as_json, stream=as_json)
            except (FileNotFoundError, OSError, ValueError) as error:
                failed = True
                if as_json:
                    print(json.dumps({"path": str(model_path), "error": str(error)}, sort_keys=True), flush=True)
                else:
                    print(f"error: {model_path}: {error}")
    except ValueError as error:
        print(f"error: {error}")
        return 2
    return 2 if failed else 1 if blocked else 0


def _print_report(report: dict, as_json: bool, stream: bool = False) -> None:
    if as_json:
        output = json.dumps(report, sort_keys=True) if stream else json.dumps(report, indent=2, sort_keys=True)
        print(output, flush=stream)
        return
    print(f"path: {report['path']}")
    print(f"status: {report['status']}")
    print(f"format: {report['detected_format']}")
    print(f"sha256: {report['sha256']}")
    for finding in report["findings"]:
        evidence = f" ({finding['evidence']})" if "evidence" in finding else ""
        print(f"[{finding['severity']}] {finding['code']}: {finding['message']}{evidence}")


if __name__ == "__main__":
    raise SystemExit(main())
