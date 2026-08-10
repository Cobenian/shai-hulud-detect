# durabletask-endpoint-corroborated

Counterpart to `durabletask-endpoint-fp`.

The durabletask C2 endpoint paths are no longer matched as bare literals,
because `/v1/models` and friends occur in every AI SDK. Dropping them outright
would have lost the one case a bare match caught and the C2 host literal does
not: a variant that **rotates the C2 domain** while keeping the endpoints.

This fixture models exactly that — a rotated host, a campaign endpoint, and a
campaign marker (the `durabletask` import the dropper injects into) in one
file — and must be flagged HIGH.

Inert: no payload, no real C2, no network calls. Strings only.
