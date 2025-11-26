# GitHub Actions Runners Test Case

This test case validates detection of malicious self-hosted GitHub Actions runners used as persistent backdoors.

## Malicious Files/Directories (Should be detected)

### .dev-env/ Directory (Koi.ai IOC)
- `.dev-env/.runner` - Runner configuration file
- `.dev-env/.credentials` - Runner credentials (OAuth tokens)

### actions-runner/ Directory
- `actions-runner/Runner.Worker` - Runner executable binary
- `actions-runner/run.sh` - Runner startup script

### .runner-dir/ Directory
- `.runner-dir/config.sh` - Runner configuration script

## Expected Detection

When running with `./shai-hulud-detector.sh test-cases/github-actions-runners/`:

**Should detect:**
- HIGH RISK: Runner configuration files found
- HIGH RISK: Runner executable files found
- HIGH RISK: Suspicious .dev-env directory (matches Koi.ai report)

## Attack Context

Self-hosted runners enable persistent backdoor access by:
1. Installing runner in hidden directories like `.dev-env/`
2. Configuring runner to connect to attacker-controlled repositories
3. Using discussion workflows to trigger arbitrary command execution
4. Maintaining persistent access even after initial compromise is cleaned