# Fix: Comment Filtering Fails After grep -n in Network Exfiltration Detection

## Branch
`fix/network-exfiltration-comment-filter`

## Problem Description

In `check_network_exfiltration()`, the code attempts to filter out comments (lines starting with `#` or `//`) to avoid false positives when detecting suspicious domains. However, when using `grep -n` to get line numbers, the output format changes from:

```
// https://webhook.site/example
```

to:

```
1:// https://webhook.site/example
```

The comment filter regex `^[[:space:]]*//` looks for lines **starting with** `//`, but after `grep -n`, lines start with a line number like `1://`. This causes the filter to **fail silently**, and comments are incorrectly reported as findings.

### Buggy Code (Line ~1714)
```bash
# This works (no line numbers):
suspicious_usage=$(grep -E "...$domain..." "$file" | grep -vE "^[[:space:]]*#|^[[:space:]]*//" | head -1)

# This FAILS (line numbers break the pattern):
line_info=$(grep -nE "...$domain..." "$file" | grep -vE "^[[:space:]]*#|^[[:space:]]*//" | head -1)
#                  ^^ -n adds "NNN:" prefix          ^^ Pattern expects line to START with // but it starts with "1://"
```

## How to Reproduce

### Create a Test Case

Create a test directory with a JavaScript file containing both a comment and actual code with a suspicious domain:

```bash
mkdir -p test-cases/comment-filter-test
cat > test-cases/comment-filter-test/test.js << 'EOF'
// https://webhook.site/this-is-a-comment
const safe = true;
const config = {
  hostname: "webhook.site",
  path: "/actual-usage"
};
EOF
```

### Before the Fix (on `main` branch)

```bash
git checkout main
./shai-hulud-detector.sh --paranoid test-cases/comment-filter-test
```

**Result (INCORRECT):**
```
⚠️  MEDIUM RISK: Network exfiltration patterns detected:
   - Pattern: webhook.site reference
   - Warning: Suspicious domain found: webhook.site at line 1: ...

Medium Risk Issues: 1
```

The comment on line 1 is incorrectly flagged as suspicious because the filter didn't work.

### After the Fix (on this branch)

```bash
git checkout fix/network-exfiltration-comment-filter
./shai-hulud-detector.sh --paranoid test-cases/comment-filter-test
```

**Result (CORRECT):**
```
⚠️  MEDIUM RISK: Network exfiltration patterns detected:
   - Pattern: webhook.site reference
   - Warning: Suspicious domain found: webhook.site at line 4: hostname: "webhook.site",...

Medium Risk Issues: 1
```

Now only line 4 (the actual code usage) is reported. The comment on line 1 is correctly filtered out.

### Cleanup

```bash
rm -rf test-cases/comment-filter-test
```

## The Fix

```diff
                         if [[ -n "$suspicious_usage" ]]; then
                             # Get line number and context
+                            # FIX: grep -n prefixes lines with "NNN:" so we must account for that in comment filtering
                             local line_info
-                            line_info=$(grep -nE "...$domain..." "$file" | grep -vE "^[[:space:]]*#|^[[:space:]]*//" | head -1)
+                            line_info=$(grep -nE "...$domain..." "$file" | grep -vE "^[0-9]+:[[:space:]]*#|^[0-9]+:[[:space:]]*//" | head -1)
                             local line_num
```

The new pattern `^[0-9]+:[[:space:]]*//` correctly matches lines like `1:// comment` after `grep -n` processing.

## Impact

- **False Positives Eliminated:** Comments containing suspicious domains are no longer reported
- **Accurate Line Numbers:** The reported line number now points to actual code, not comments
- **Paranoid Mode Quality:** Improves the signal-to-noise ratio of the `--paranoid` security scan
