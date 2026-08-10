# secret-scanner-mention

A bare reference to the trufflehog tool name is a MEDIUM finding
(`Contains trufflehog references in source code`) — common in security tooling
and CI glue, and not on its own evidence of anything.

This fixture pins *severity attribution*. `trufflehog_activity.txt` stores
`path:SEVERITY:message` and mixes HIGH, MEDIUM and LOW; the `--save-log` and
`--json` writers used to dump the whole file into the HIGH bucket, so this
MEDIUM finding was recorded as HIGH. Under `--bulk` that produced rows reading
`🟡 MEDIUM RISK (H:4 M:0 L:0)` — label from the exit code, counts from the log.

The directory is deliberately NOT named after the tool: a path containing
"trufflehog" matches the binary-name check and would be flagged HIGH,
defeating the point.

Inert: a string constant naming the tool. Nothing is downloaded or executed.
