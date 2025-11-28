#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-compromised-packages.txt}"
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
THREATS_FILE="tmp/threats-$TIMESTAMP.txt"
CONCURRENCY="${CONCURRENCY:-10}"

mkdir -p tmp
: > "$THREATS_FILE"

# Cleanup incomplete file on interruption
trap 'rm -f "$THREATS_FILE"; exit 1' INT TERM ERR

check_pkg() {
  local line="$1"

  # Skip empty lines or comments
  [[ -z "${line// /}" || "$line" =~ ^[[:space:]]*# ]] && return

  # Parse package:version
  local pkg="${line%%:*}"
  local ver="${line#*:}"

  # Validate format
  if [[ -z "$pkg" || -z "$ver" || "$pkg" == "$line" ]]; then
    echo "SKIP    Invalid line: $line"
    return
  fi

  local spec="${pkg}@${ver}"

  if npm view "$spec" version >/dev/null 2>&1; then
    echo "THREAT  $spec"
    echo "$spec" >> "$THREATS_FILE"
  else
    echo "SAFE    $spec"
  fi
}

export -f check_pkg
export THREATS_FILE

# Use xargs for parallel execution
grep -v '^[[:space:]]*#' "$INPUT_FILE" | grep -v '^[[:space:]]*$' | \
  xargs -P "$CONCURRENCY" -I {} bash -c 'check_pkg "$@"' _ {}

# Sort threats alphabetically
sort -o "$THREATS_FILE" "$THREATS_FILE"

# Clear trap on successful completion
trap - INT TERM ERR

echo
echo "Finished. Threats saved to: $THREATS_FILE"
