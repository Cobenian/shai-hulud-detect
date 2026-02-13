# Destructive Patterns Test Case

This test case validates detection of destructive payload patterns that can cause permanent data loss when credential theft fails.

## Defanging Approach

These test files contain malicious pattern **signatures as inert string data**, not as executable code. The detector uses grep-based pattern matching against file contents, so the exact command text needs to be present in the files but does not need to be functional. This follows the industry standard practice of using defanged samples for security tool testing (similar to EICAR test files for antivirus software).

All destructive commands are stored as string variable assignments or inside comments. Running these files directly does nothing harmful.

## Malicious Pattern Files (Should be detected)

### malicious_fallback.js
- String constants containing Shai-Hulud 2.0 wiper signatures
- Patterns: `Bun.spawnSync` with `cmd.exe`/`bash`, `rm -rf $HOME/*`, `fs.rmSync` with recursive

### cleanup.sh
- String variables containing shell-based destructive patterns
- Patterns: `rm -rf $HOME/*`, `rm -rf ~/*`, `find $HOME -delete`, `find ~ -exec rm`

### windows_payload.ps1
- String variables containing Windows destructive patterns
- Patterns: `Remove-Item -Recurse`, `del /s /q`, `Get-ChildItem` with `Remove-Item`

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
2. **Cross-platform patterns** (Linux/macOS/Windows)
3. **Multiple destruction methods** (rm, fs.rmSync, Remove-Item, etc.)

## Warning Level: CRITICAL

These patterns indicate potential for permanent data loss and require immediate quarantine.
