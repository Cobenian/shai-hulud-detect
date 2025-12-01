#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="shai-hulud-report-$(date +%Y%m%d-%H%M%S).txt"

# Run the original script and filter out progress lines from the log
# Improve dx as opposed to running: ./shai-hulud-detect.sh /path/to/project 2>&1 | tee "shai-hulud-report-$(date +%Y%m%d-%H%M%S).log"
./shai-hulud-detector.sh "$@" 2>&1 | tee >(perl -pe 's/\x1b\[[0-9;]*[A-Za-z]//g' > "tmp/$LOG_FILE")

echo ""
echo "Log written to tmp/$LOG_FILE"


