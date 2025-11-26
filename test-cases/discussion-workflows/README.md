# Discussion Workflows Test Case

This test case validates detection of malicious GitHub Actions workflows that use discussion triggers for arbitrary command execution.

## Malicious Files (Should be detected)

- `discussion.yaml` - Exact filename match from Koi.ai incident report
- `comment-trigger.yml` - Alternative malicious workflow with discussion trigger

Both files contain:
- `on: discussion` trigger
- `runs-on: self-hosted` execution
- Dynamic payload execution via `${{ github.event.discussion.body }}`

## Legitimate Files (Should NOT be detected)

- `legitimate.yml` - Normal CI workflow with push/PR triggers

## Expected Detection

When running with `./shai-hulud-detector.sh test-cases/discussion-workflows/`:

**Should detect:**
- HIGH RISK: Discussion trigger detected
- HIGH RISK: Self-hosted runner with dynamic payload execution
- HIGH RISK: Suspicious discussion workflow filename

**Should NOT detect:**
- The legitimate.yml file (different triggers, ubuntu-latest runner)