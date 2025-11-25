# Semver Wildcards Test Case

This test case validates the fix for GitHub issue #56 regarding semver parsing errors with wildcard patterns like "4.x".

## Problem

The original semver parsing logic failed when encountering wildcard patterns containing "x" characters, causing syntax errors:

```
./shai-hulud-detector.sh: line 555: [[: 4.x: syntax error: invalid arithmetic operator (error token is ".x")
```

## Fix

Added wildcard pattern detection in the `semver_match()` function to handle patterns like:
- `4.x` - matches any version where major=4, minor=any, patch=any
- `1.2.x` - matches any version where major=1, minor=2, patch=any
- `x.x.x` - matches any version (equivalent to "*")

## Test Files

- `package.json` - Contains various wildcard patterns that would trigger the original error
- `test_semver_wildcards.sh` - Unit test suite with 20 test cases covering:
  - Original issue patterns ("4.x", "4.0.0", etc.)
  - Additional wildcard combinations
  - Backwards compatibility with existing semver patterns

## Usage

Test the fix:
```bash
# Test with actual package.json containing wildcards
./shai-hulud-detector.sh test-cases/semver-wildcards/

# Run comprehensive unit tests
cd test-cases/semver-wildcards && ./test_semver_wildcards.sh
```

Both should complete without syntax errors and all unit tests should pass.