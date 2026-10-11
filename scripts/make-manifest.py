#!/usr/bin/env python3
"""make-manifest.py <dist-root> <version>

Emits dist-root/release-manifest.json: per-platform artifact inventory with
SHA-256 checksums and sizes. Minimal SBOM for the current release boundary
(source is stdlib-only; build tooling versions are tracked in CI logs).
"""
import datetime
import hashlib
import json
import os
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <dist-root> <version>", file=sys.stderr)
        return 2

    root = os.path.abspath(sys.argv[1])
    version = sys.argv[2]

    manifest = {
        "product": "JICloud AI Antiva",
        "version": version,
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platforms": {},
    }

    for platform in sorted(os.listdir(root)):
        platform_dir = os.path.join(root, platform)
        if not os.path.isdir(platform_dir):
            continue
        files = []
        for name in sorted(os.listdir(platform_dir)):
            if name in ("SHA-256SUMS", "release-manifest.json"):
                continue
            path = os.path.join(platform_dir, name)
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            files.append({"name": name, "size": os.path.getsize(path), "sha256": digest})
        manifest["platforms"][platform] = files

    out = os.path.join(root, "release-manifest.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())