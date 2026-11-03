# Clean: ordinary LiteLLM use and look-alike strings that must not fire.
import litellm
import cook
litellm.dev_mode = True
DOCS = "https://docs.litellm.ai"
IMAGE = "ghcr.io/berriai/litellm:v1.106.4"
SERVICE = "svc-telemetry"
