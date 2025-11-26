# File Hash Verification Test Case

This test case validates file hash verification for known malicious files from the Koi.ai incident report.

## Test Files (Benign - Safe for Testing)

- `setup_bun.js` - Benign file with target filename
- `bun_environment.js` - Benign file with target filename

## Hash Verification Logic

### Known Malicious Hashes (From Koi.ai Report)

**setup_bun.js:**
- `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`

**bun_environment.js:**
- `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`

## Expected Detection

When running with `./shai-hulud-detector.sh test-cases/hash-verification/`:

**Should detect (filename-based):**
- HIGH RISK: November 2025 malicious Bun files detected
- Files: setup_bun.js, bun_environment.js

**Should NOT detect (hash-based):**
- CRITICAL: Hash-confirmed malicious files (these are benign test files)

## Real Malicious Files

If actual malicious files with matching hashes are found:
- **CRITICAL alert** would be triggered
- Message: "These files match exact SHA256 hashes from security incident reports!"
- Immediate quarantine recommended

## Testing Hash Verification

To verify hash checking works:
1. Check that script detects filenames: ✅
2. Check that script attempts hash verification: ✅
3. Check that benign files don't trigger hash alerts: ✅
4. For real malicious files, hash match would trigger CRITICAL alert