# Destructive Home Wipe Test Case

This test case locks in the false-**negative** half of the
`basic_destructive_regex` fix in `check_destructive_patterns`.

## Problem Description

The old regex only accepted a bare `$HOME` or `~` followed by a character that
was neither alphanumeric nor `/`. It had no allowance for a leading quote, no
brace-expansion alternative, and could not match at end-of-line. As a result
these real home-directory wipes were silently **missed**:

```
rm -rf ~
rm -rf ~/
rm -rf ~/*
rm -rf "$HOME"
rm -rf ${HOME}
rm -rf ~bob
rm -rf "/home/bob"
```

Note that `rm -rf ~/*` is literally `PATTERN_2` of
`test-cases/destructive-patterns/cleanup.sh`; that fixture only passed because
of its *other* lines.

## Defanging Approach

`wiper.sh` stores every command as an inert string variable, following the same
convention as `test-cases/destructive-patterns`. Running the file does nothing.

## Test Files

### wiper.sh (Should trigger alerts)

- `rm -rf "$HOME"` (quoted)
- `rm -rf ${HOME}` (brace-expanded)
- `rm -rf ~` and `rm -rf ~/` (bare tilde)
- `rm -rf ~bob` (other user's home)
- `rm -rf "/home/bob"` (quoted absolute home)
- `rm -rf /home/` (whole /home tree)

## Expected Results

When running `./shai-hulud-detector.sh test-cases/destructive-home-wipe/`:

**Should detect (CRITICAL level):**

- Basic destructive pattern detected in `wiper.sh`
- HIGH RISK verdict, exit code 1

The complementary negative case lives in
`test-cases/destructive-home-subdir-fp/`.

## Warning Level: CRITICAL

These patterns indicate potential for permanent data loss and require immediate
quarantine.
