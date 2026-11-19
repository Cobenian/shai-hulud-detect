# Clean: ordinary LiteLLM use and look-alike strings that must not fire.
# Inert: string constants only. The import and attribute lines are kept as text,
# because the scanner matches text and must not flag them; nothing is imported or run.
IMPORT_LINES = "import litellm\nimport cook"
DEV_MODE = "litellm.dev_mode = True"
DOCS = "https://docs.litellm.ai"
IMAGE = "ghcr.io/berriai/litellm:v1.106.4"
SERVICE = "svc-telemetry"
# Internal hostnames that start with an attacker domain but are not it.
PROXY = "http://litellm.dev.svc.cluster.local:4000"
PROXY_ALT = "http://litellm.dev-proxy:4000"
ARTIFACTS = "https://ci-artifacts.dev.internal/builds"
