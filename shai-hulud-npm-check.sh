#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-compromised-packages.txt}"
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
THREATS_FILE="tmp/threats-$TIMESTAMP.txt"
CONCURRENCY="${CONCURRENCY:-50}" # bottleneck is network I/O
START_TIME=$(date +%s)

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
  local url="https://registry.npmjs.org/${pkg}/${ver}"

  # Get HTTP status code without downloading body
  local http_code=$(curl -I -s --max-time 5 -w "%{http_code}" -o /dev/null "$url" 2>/dev/null || echo "000")

  if [[ "$http_code" == "200" ]]; then
    echo "THREAT  $spec"
    echo "$spec" >> "$THREATS_FILE"
  elif [[ "$http_code" != "404" ]]; then
    case "$http_code" in
      000) echo "ERROR  $spec (timeout/network)" ;;
      429) echo "ERROR  $spec (rate limited)" ;;
      5*) echo "ERROR  $spec (npm registry error)" ;;
      *) echo "ERROR  $spec (HTTP $http_code)" ;;
    esac
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

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo
echo "Finished in ${DURATION}s. Threats saved to: $THREATS_FILE"

echo
echo "Summary:"
echo "  Threats: $(wc -l < "$THREATS_FILE" | tr -d ' ')"
echo "  Total checked: $(grep -cv '^[[:space:]]*#' "$INPUT_FILE")"
