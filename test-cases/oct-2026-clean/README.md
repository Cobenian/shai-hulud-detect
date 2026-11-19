# oct-2026-clean

Clean counterpart to `oct-2026-attack`. `app.py` pins the false-positive guards:
`litellm.dev_mode`, the real docs domain, a clean image tag, and `svc-telemetry` as an
ordinary service name.

It also holds internal hostnames that begin with an attacker domain
(`litellm.dev.svc.cluster.local`, `litellm.dev-proxy`, `ci-artifacts.dev.internal`)
and a lone `.napi_cache` with no worm loader beside it. None of these may fire.
