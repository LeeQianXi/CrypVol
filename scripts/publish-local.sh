#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_IDENTIFIER="${2:-linux-x64}"
OUTPUT_DIRECTORY="${1:-$REPOSITORY_ROOT/publish/local/$RUNTIME_IDENTIFIER}"

mkdir -p "$OUTPUT_DIRECTORY/cli" "$OUTPUT_DIRECTORY/gui"

dotnet publish "$REPOSITORY_ROOT/CrypVol.Cli/CrypVol.Cli.csproj" \
    --configuration Release \
    --runtime "$RUNTIME_IDENTIFIER" \
    --self-contained true \
    -p:PublishSingleFile=true \
    -p:PublishTrimmed=true \
    --output "$OUTPUT_DIRECTORY/cli"

dotnet publish "$REPOSITORY_ROOT/CrypVol/CrypVol.csproj" \
    --configuration Release \
    --runtime "$RUNTIME_IDENTIFIER" \
    --self-contained true \
    -p:PublishSingleFile=true \
    --output "$OUTPUT_DIRECTORY/gui"

printf '本地发布完成: %s\n' "$OUTPUT_DIRECTORY"
