# Destructive Patterns Test Case

This test case validates detection of destructive payload patterns that can cause permanent data loss when credential theft fails.

## Malicious Files (Should be detected)

### malicious_fallback.js
- JavaScript with destructive patterns
- Contains: `rm -rf $HOME/*`, `fs.rmSync(..., {recursive: true})`
- Simulates fallback behavior when credential extraction fails

### cleanup.sh
- Bash script with shell destructive patterns
- Contains: `rm -rf $HOME/*`, `rm -rf ~/*`, `find $HOME -delete`
- Shows conditional destruction based on credential theft failure

### windows_payload.ps1
- PowerShell script with Windows destructive patterns
- Contains: `Remove-Item -Recurse`, `del /s /q`
- Demonstrates cross-platform destruction capabilities

## Legitimate Files (Should NOT be detected)

### legitimate_cleanup.js
- Safe cleanup script that only removes specific temp/log files
- Uses controlled, scoped file operations
- Should NOT trigger destructive pattern alerts

## Expected Detection

When running with `./shai-hulud-detector.sh test-cases/destructive-patterns/`:

**Should detect (CRITICAL level):**
- Destructive pattern detected: rm -rf \$HOME
- Destructive pattern detected: fs\.rmSync.*recursive
- Destructive pattern detected: Remove-Item -Recurse
- Destructive pattern detected: del /s /q
- Destructive pattern detected: find.*-delete

**Should NOT detect:**
- The legitimate_cleanup.js file (scoped operations only)

## Attack Context

From Koi.ai report: When credential exfiltration fails, malware "deletes every writable file owned by the current user under their home folder" as a destructive fallback. This test case validates detection of:

1. **Primary destructive commands** targeting user home directory
2. **Conditional destruction** triggered by credential theft failures
3. **Cross-platform patterns** (Linux/macOS/Windows)
4. **Multiple destruction methods** (rm, fs.rmSync, Remove-Item, etc.)

## Warning Level: CRITICAL

These patterns indicate potential for permanent data loss and require immediate quarantine.