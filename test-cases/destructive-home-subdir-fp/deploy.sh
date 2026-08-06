# INERT TEST FIXTURE - legitimate scoped cleanup below a home directory.
# Nothing here executes: every command is stored as an inert string variable,
# exactly like the neighbouring test-cases/destructive-patterns fixture.
#
# All of these target a SUBDIRECTORY (two or more levels below $HOME / ~ / /home/).
# That is an ordinary scoped removal, not a home-directory wipe, and it must NOT
# be reported as "CRITICAL: Destructive payload patterns detected".

# The line that regressed: a deployment doc / script removing one app's state dir.
SCOPED_1='rm -rf /home/myapp/.deployer'

# Further scoped removals that used to over-match the old "/home/" alternative.
SCOPED_2='rm -rf /home/user/project/node_modules'
SCOPED_3='rm -rf /home/ci/workspace/build'

# Scoped removals below $HOME and ~.
SCOPED_4='rm -rf $HOME/.cache/foo'
SCOPED_5='rm -rf $HOME/project/build'
SCOPED_6='rm -rf ~/tmp/build'
SCOPED_7='rm -rf ~/.npm/_cacache'

# Relative removal - never home-directory related.
SCOPED_8='rm -rf ./dist'

# find(1) restricted to an application log directory, not to the home directory.
SCOPED_9='find /home/app/logs -mtime +30 -delete'
