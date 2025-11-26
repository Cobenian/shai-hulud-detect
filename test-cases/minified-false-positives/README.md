# Minified JavaScript False Positives Test Case

This test case validates the fix for GitHub issue #74 - destructive patterns generating false positives on minified files.

## Problem Description

The original patterns were too broad and caused false positives in minified JavaScript files:
- `find.*-delete` matched UI code like `icon=something-delete`
- `if.*credential.*fail.*rm` spanned across entire minified files
- `error.*delete.*home` matched unrelated error handling + navigation

## Test Files

### minified-library.js (Should NOT trigger alerts)
- Simulated minified JavaScript similar to AutoNumeric.js
- Contains legitimate UI code with icons like "icon-delete"
- Contains words like "error", "delete", "home" in unrelated contexts
- Should NOT produce false positive CRITICAL alerts

### legitimate-destructive.js (Should trigger alerts)
- Contains real malicious patterns that should be detected
- Uses limited-span conditional patterns appropriate for JavaScript
- Should produce CRITICAL alerts for actual destructive behavior

### legitimate-destructive.sh (Should trigger alerts)
- Shell script with actual destructive patterns
- Should use broader pattern matching appropriate for shell scripts
- Should produce CRITICAL alerts for destructive commands

## Expected Results

When running: `./shai-hulud-detector.sh test-cases/minified-false-positives/`

**Should NOT detect (no false positives):**
- The minified-library.js file despite containing "icon-delete", "error", "delete", "home"

**Should detect (real threats):**
- legitimate-destructive.js: Limited-span conditional destruction patterns
- legitimate-destructive.sh: Both specific and broader destructive patterns

## Pattern Refinements

1. **File Type Awareness**: Different pattern strictness based on file extension
2. **Limited Spans**: Conditional patterns use `.{1,200}` instead of `.*` to prevent spanning entire minified files
3. **Command Structure**: `find` patterns require proper command structure with spaces
4. **Context Boundaries**: Patterns respect code boundaries and contexts

This test validates that the pattern refinements successfully eliminate false positives while maintaining detection of real threats.