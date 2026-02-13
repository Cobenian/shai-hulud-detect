# DEFANGED TEST FIXTURE - Destructive pattern signatures for detection testing
# These patterns are stored as inert string data, not executable commands.
# Based on Koi Security disclosure of Shai-Hulud 2.0 wiper behavior.
#
# The detector uses grep to match these patterns in file contents.
# The exact command text must be present for detection, but does not need
# to be executable code.

# Pattern 1: Home directory removal
PATTERN_1='rm -rf $HOME/*'

# Pattern 2: Tilde-based home directory removal
PATTERN_2='rm -rf ~/*'

# Pattern 3: Find and delete all files in home directory
PATTERN_3='find $HOME -type f -delete'

# Pattern 4: Find and exec rm on home directory
PATTERN_4='find ~ -exec rm -f {} \;'

# Credential scanning patterns (triggers secret scanning detection)
# These represent the credential theft stage that precedes destruction:
CRED_1='GITHUB_TOKEN=$(grep -r "github_pat_" ~/ 2>/dev/null | head -1)'
CRED_2='NPM_TOKEN=$(cat ~/.npmrc 2>/dev/null | grep "authToken")'

# Conditional pattern: credential failure triggers destruction
# if credential extraction fails then rm -rf $HOME
