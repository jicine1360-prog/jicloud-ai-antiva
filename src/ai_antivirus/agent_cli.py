"""CLI entry point for the local guard agent."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from .agent import serve
from .policy import Policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local JICloud AI Antiva guard.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--audit-log",
        default="~/.local/state/ai-antivirus/audit.jsonl",
        help="append-only audit log path",
    )
    parser.add_argument(
        "--audit-max-megabytes",
        type=float,
        default=32.0,
        help="rotate the live audit log into a numbered segment at this size (0 never rotates)",
    )
    parser.add_argument(
        "--audit-keep-segments",
        type=int,
        default=0,
        help="keep only this many rotated segment bodies; anchors are always kept (0 keeps all)",
    )
    parser.add_argument("--allowed-host", action="append", default=[])
    parser.add_argument("--allowed-path", action="append", default=[])
    parser.add_argument(
        "--flag-unknown-hosts",
        action="store_true",
        help="record a review finding for destinations outside --allowed-host; does not block traffic",
    )
    parser.add_argument(
        "--watch-path",
        action="append",
        default=[],
        help="model directory to scan continuously; may be specified more than once",
    )
    parser.add_argument("--watch-interval", type=float, default=5.0, help="seconds between directory polls")
    parser.add_argument("--quarantine-dir", help="move blocked model artifacts to this directory")
    parser.add_argument(
        "--watch-runtime",
        action="store_true",
        help="monitor known AI processes and their external TCP connections on Linux",
    )
    parser.add_argument("--runtime-interval", type=float, default=5.0, help="seconds between Linux runtime polls")
    parser.add_argument(
        "--watch-process",
        action="append",
        default=[],
        help="additional exact process name to monitor",
    )
    parser.add_argument(
        "--threat-feed",
        help="JSONL or JSON file of blocked SHA-256 indicators for watched models",
    )
    parser.add_argument(
        "--auth-token",
        help="require Authorization: Bearer <token> on /v1 routes; AI_ANTIVA_AUTH_TOKEN is used when omitted",
    )
    args = parser.parse_args(argv)

    auth_token = args.auth_token or os.environ.get("AI_ANTIVA_AUTH_TOKEN") or None
    if auth_token is not None and len(auth_token) < 16:
        parser.error("auth token must be at least 16 characters")

    policy = Policy(
        allowed_hosts=frozenset(host.lower().rstrip(".") for host in args.allowed_host),
        allowed_paths=tuple(args.allowed_path),
        flag_unknown_hosts=args.flag_unknown_hosts,
    )
    try:
        serve(
            args.port,
            str(Path(args.audit_log).expanduser()),
            policy,
            tuple(args.watch_path),
            args.watch_interval,
            args.quarantine_dir,
            args.watch_runtime,
            args.runtime_interval,
            tuple(args.watch_process),
            args.threat_feed,
            auth_token,
            audit_max_megabytes=args.audit_max_megabytes,
            audit_keep_segments=args.audit_keep_segments,
        )
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
