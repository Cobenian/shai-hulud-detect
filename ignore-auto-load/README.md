# ignore-auto-load

This fixture validates automatic loading of `.shai-hulud-ignore`.

- It intentionally includes `.github/workflows/shai-hulud-workflow.yml` (normally HIGH risk).
- `.shai-hulud-ignore` suppresses that workflow path by default.
- Tests can disable auto-ignore by passing `--ignore-file /dev/null` as a control.
