#!/usr/bin/env bash
set -euo pipefail

INPUT_FILE="${1:-compromised-packages.txt}"
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
TMP_DIR="tmp"
THREATS_FILE="$TMP_DIR/threats-$TIMESTAMP.txt"
THREATS_TEMP="$TMP_DIR/threats-$TIMESTAMP.tmp"
CONCURRENCY="${CONCURRENCY:-20}"  # change or: CONCURRENCY=20 ./script.sh

# Create tmp directory if it doesn't exist
mkdir -p "$TMP_DIR"

# Clean threats file at start
: > "$THREATS_FILE"

if ! command -v npm >/dev/null 2>&1; then
  echo "Error: npm is not installed or not in PATH" >&2
  exit 1
fi

check_pkg() {
  local line="$1"

  # Trim whitespace
  line="${line#"${line%%[![:space:]]*}"}"
  line="${line%"${line##*[![:space:]]}"}"

  # Skip empty lines or comments
  if [[ -z "$line" || "${line:0:1}" == "#" ]]; then
    return
  fi

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
    # appends are fine from parallel processes
    echo "$spec" >> "$THREATS_FILE"
  else
    echo "SAFE    $spec"
  fi
}

# Simple concurrency control using a PID queue
pids=()

run_with_limit() {
  check_pkg "$1" &
  pids+=("$!")

  # If we reached max concurrency, wait for the oldest job to finish
  if ((${#pids[@]} >= CONCURRENCY)); then
    wait "${pids[0]}"
    pids=("${pids[@]:1}")
  fi
}

# Schedule checks
while IFS= read -r line; do
  run_with_limit "$line"
done < "$INPUT_FILE"

# Wait for remaining jobs
for pid in "${pids[@]}"; do
  wait "$pid"
done

# Sort threats alphabetically
if [[ -f "$THREATS_FILE" && -s "$THREATS_FILE" ]]; then
  sort "$THREATS_FILE" -o "$THREATS_TEMP"
  mv "$THREATS_TEMP" "$THREATS_FILE"
fi

echo
echo "Finished. Threats saved to: $THREATS_FILE"
