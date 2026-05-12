#!/bin/sh
# TEST FIXTURE - Inert stand-in for the Mini Shai-Hulud dead-man's-switch monitor.
# The real script polls api.github.com/user every 60s with a stolen GitHub token
# and triggers a destructive wipe when the token is revoked. This file exists
# only so the detector can match the gh-token-monitor.sh filename in scan trees.
echo "this is a test fixture, not the real payload"
