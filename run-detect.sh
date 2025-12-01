#!/usr/bin/env bash
set -euo pipefail

SCAN_DIR="${1:-.}"
DIR_NAME=$(basename "$SCAN_DIR")
LOG_FILE="shai-hulud-report_${DIR_NAME}_$(date +%Y%m%d-%H%M%S).txt"
ANSI_ESCAPE_REGEX=$'s/\x1B\[[0-9;]*[A-Za-z]//g'
mkdir -p tmp

# Run the original script and filter out progress lines from the log
# Improve dx as opposed to running: ./shai-hulud-detect.sh /path/to/project 2>&1 | tee "shai-hulud-report-$(date +%Y%m%d-%H%M%S).log"
./shai-hulud-detector.sh "$@" 2>&1 | tee >(sed -E "$ANSI_ESCAPE_REGEX" > "tmp/$LOG_FILE")

echo
echo "Log written to tmp/$LOG_FILE"
