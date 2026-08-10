# INERT FIXTURE - models the durabletask dropper with a rotated C2 domain.
# The host is intentionally NOT check.git-service.com, so only the endpoint
# path plus the campaign marker below can identify it. No code executes.
import durabletask

BASE = "https://rotated-c2.example"
STAGE2 = BASE + "/v1/models"
HEALTH = BASE + "/api/public/version"
