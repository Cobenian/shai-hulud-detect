# Destructive Home Subdirectory False-Positive Test Case

This test case locks in the fix for the `/home/` over-match in
`check_destructive_patterns` (`basic_destructive_regex`).

## Problem Description

The `/home/` alternative of the destructive-payload regex used to match **any**
path below `/home/`. A perfectly legitimate deployment line such as

```
rm -rf /home/myapp/.deployer
```

was therefore reported as `CRITICAL: Destructive payload patterns detected`,
which escalates the whole scan to HIGH RISK.

The regex now allows at most **one** path component after `$HOME` / `${HOME}` /
`~` / `/home/`, optionally followed by `/` or `/*`, and then requires a
non-path character or end-of-line. Two levels deep is a scoped subdirectory
removal, not a home-directory wipe.

## Defanging Approach

`deploy.sh` stores every command as an inert string variable, following the
same convention as `test-cases/destructive-patterns`. Running the file does
nothing.

## Test Files

### deploy.sh (Should NOT trigger alerts)

Scoped removals that must all stay below the detection threshold:

- `rm -rf /home/myapp/.deployer` (the regressed line)
- `rm -rf /home/user/project/node_modules`
- `rm -rf /home/ci/workspace/build`
- `rm -rf $HOME/.cache/foo`, `rm -rf $HOME/project/build`
- `rm -rf ~/tmp/build`, `rm -rf ~/.npm/_cacache`
- `rm -rf ./dist`
- `find /home/app/logs -mtime +30 -delete`

## Expected Results

When running `./shai-hulud-detector.sh test-cases/destructive-home-subdir-fp/`:

**Should NOT detect:**

- No destructive payload patterns
- Clean result, exit code 0

The complementary positive case lives in
`test-cases/destructive-home-wipe/`.
