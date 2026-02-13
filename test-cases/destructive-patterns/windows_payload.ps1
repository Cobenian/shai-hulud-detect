# DEFANGED TEST FIXTURE - Destructive pattern signatures for detection testing
# These patterns are stored as inert string data, not executable commands.
# Based on Koi Security disclosure of Shai-Hulud 2.0 wiper behavior.
#
# The detector uses grep to match these patterns in file contents.
# The exact command text must be present for detection, but does not need
# to be executable code.

# Pattern 1: PowerShell Remove-Item with recursion targeting user profile
$PATTERN_1 = 'Remove-Item -Recurse -Force "$env:USERPROFILE\*"'

# Pattern 2: Alternative destruction via Get-ChildItem pipeline
$PATTERN_2 = 'Get-ChildItem $env:USERPROFILE -Recurse | Remove-Item -Force'

# Pattern 3: CMD-style deletion fallback
$PATTERN_3 = 'del /s /q $env:USERPROFILE\*'
