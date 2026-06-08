# SYNTHETIC, INERT test fixture for the June 7, 2026 Hades/Miasma PyPI wave.
#
# This file contains ONLY harmless marker strings, as plain comments, so the
# detector's content-pattern checks (check_hades_miasma_indicators) fire.
# There is NO real loader, NO startup hook, NO obfuscated payload, and NO
# network call anywhere in this fixture. Nothing here executes. It is safe to
# read, copy, and run (it does nothing).
#
# --- Inert IoC marker strings (text only, never contacted/executed) ---
#
# Dead-man's-switch token-nuke marker:
#   IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully
#
# Exfil-repo beacon / GitHub repository description:
#   Hades - The End for the Damned
#
# C2 camouflage path (a path under the legitimate Anthropic API host that is
# NOT a real endpoint — listed here only as a string for detection):
#   api.anthropic.com/v1/api

INERT_FIXTURE = "no payload — marker strings above are detection bait only"
