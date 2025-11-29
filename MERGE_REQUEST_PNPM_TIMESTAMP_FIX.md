# Fix: pnpm-lock.yaml Timestamp Check Uses Wrong File

## Branch
`fix/pnpm-lockfile-timestamp`

## Problem Description

In `check_package_integrity()`, when processing `pnpm-lock.yaml` files, the script creates a temporary file to normalize the YAML format for parsing. However, the "recently modified lockfile" check incorrectly uses the timestamp of this **temporary file** instead of the original `pnpm-lock.yaml`.

Since the temporary file was just created, it always has an age of 0 seconds, which is always less than 30 days. This causes the check to **always fire as a false positive** for any pnpm project containing `@ctrl` packages.

### Buggy Code (Line ~1446)
```bash
# Transform pnpm-lock.yaml into pseudo-package-lock
org_file="$lockfile"
if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
    org_file="$lockfile"
    lockfile=$(mktemp "${TMPDIR:-/tmp}/lockfile.XXXXXXXX")  # Creates temp file
    transform_pnpm_yaml "$org_file" > "$lockfile"
fi

# ... later in the same function ...

# BUG: $lockfile is now the TEMP file, not the original!
file_age=$(date -r "$lockfile" +%s 2>/dev/null || echo "0")
```

## How to Reproduce

Use the included test case `test-cases/infected-lockfile-pnpm` which contains a `pnpm-lock.yaml` with `@ctrl` packages that was last modified more than 30 days ago.

### Before the Fix (on `main` branch)

```bash
git checkout main
./shai-hulud-detector.sh test-cases/infected-lockfile-pnpm
```

**Result (INCORRECT):**
```
⚠️  MEDIUM RISK: Package integrity issues detected:
   - Issue: Recently modified lockfile contains @ctrl packages (potential worm activity)

   High Risk Issues: 0
   Medium Risk Issues: 1
```

The warning fires even though the lockfile is 45+ days old, because the code checked the temp file's timestamp (0 seconds old).

### After the Fix (on this branch)

```bash
git checkout fix/pnpm-lockfile-timestamp
./shai-hulud-detector.sh test-cases/infected-lockfile-pnpm
```

**Result (CORRECT):**
```
✅ No indicators of Shai-Hulud compromise detected.
```

No false positive because the fix now checks the **original file's** timestamp.

## The Fix

```diff
             if grep -q "@ctrl" "$lockfile" 2>/dev/null; then
                 local file_age
-                file_age=$(date -r "$lockfile" +%s 2>/dev/null || echo "0")
+                # FIX: Use $org_file for timestamp, not $lockfile (which may be a temp file for pnpm)
+                file_age=$(date -r "$org_file" +%s 2>/dev/null || echo "0")
                 local current_time
```

## Impact

- **False Positives Eliminated:** pnpm projects with `@ctrl` packages no longer trigger spurious "recently modified" warnings
- **No Regression:** The fix only affects pnpm-lock.yaml files; package-lock.json and yarn.lock are unaffected
- **Correct Behavior:** The 30-day check now works as intended for all lockfile types
