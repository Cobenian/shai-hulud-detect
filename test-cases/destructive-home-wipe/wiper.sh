# DEFANGED TEST FIXTURE - home-directory wipe signatures for detection testing.
# These patterns are stored as inert string data, not executable commands, in
# the same style as test-cases/destructive-patterns. Running this file does
# nothing harmful.
#
# Every line below wipes the whole home directory and MUST be reported as
# "CRITICAL: Destructive payload patterns detected". The quoted, braced and
# bare-tilde spellings were all MISSED by the previous regex.

# Quoted $HOME - previously missed (no allowance for a leading quote).
WIPE_1='rm -rf "$HOME"'

# Brace-expanded ${HOME} - previously missed.
WIPE_2='rm -rf ${HOME}'

# Bare tilde and tilde with trailing slash - previously missed because the old
# ~[^a-zA-Z0-9_/] alternative excluded "/" and could not match at end-of-line.
WIPE_3='rm -rf ~'
WIPE_4='rm -rf ~/'

# Other-user home directory via tilde expansion - previously missed.
WIPE_5='rm -rf ~bob'

# Quoted absolute home path - previously missed.
WIPE_6='rm -rf "/home/bob"'

# Whole /home tree.
WIPE_7='rm -rf /home/'
