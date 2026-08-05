# pnpm-first-entry-attack

The compromised entry is the FIRST package in the lockfile. The pseudo-lockfile
wrapper `"packages": {` used to be consumed as a package name by the shared
parser, swallowing entry #1 — so exactly this shape reported clean.
