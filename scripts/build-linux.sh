#!/usr/bin/env sh
set -eu

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STAGING_DIRECTORY=$(mktemp -d)
trap 'rm -rf "$STAGING_DIRECTORY"' EXIT

mkdir -p "$STAGING_DIRECTORY/package"
mkdir -p "$PROJECT_ROOT/dist/linux"
cp -R "$PROJECT_ROOT/src/ai_antivirus" "$STAGING_DIRECTORY/package/"
rm -rf "$STAGING_DIRECTORY/package/ai_antivirus/__pycache__"

python3 -m zipapp "$STAGING_DIRECTORY/package" \
    --python "/usr/bin/env python3" \
    --main "ai_antivirus.cli:main" \
    --output "$PROJECT_ROOT/dist/linux/ai-model-scan"
python3 -m zipapp "$STAGING_DIRECTORY/package" \
    --python "/usr/bin/env python3" \
    --main "ai_antivirus.agent_cli:main" \
    --output "$PROJECT_ROOT/dist/linux/ai-model-guard"
chmod 755 "$PROJECT_ROOT/dist/linux/ai-model-scan" "$PROJECT_ROOT/dist/linux/ai-model-guard"

printf '%s\n' "Linux executables built in $PROJECT_ROOT/dist/linux"
