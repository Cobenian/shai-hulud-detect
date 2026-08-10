# durabletask-endpoint-fp

False-positive regression fixture for `check_durabletask_indicators`.

The May 19, 2026 durabletask campaign fetches its stage-2 payload from
`check.git-service.com` using the endpoints `/api/public/version`, `/v1/models`
and `/audio.mp3`. Those paths were matched as bare literals, but they are
ordinary URL paths — `/v1/models` is the standard OpenAI- and
Gemini-compatible inference endpoint, so it appears in every AI SDK and in
vendored typings for them.

The result was a HIGH RISK finding, complete with "rotate
AWS/GCP/Azure/Kubernetes/Vault/GitHub credentials" guidance, on any machine
with an AI CLI installed.

Everything here is ordinary benign client code and must stay clean. The
corroborated case — a campaign marker in the same file — is asserted
separately in `run-tests.sh`.
