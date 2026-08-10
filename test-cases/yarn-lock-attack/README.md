# yarn-lock-attack

Yarn v1 lockfile pinning two versions from the Aug 4, 2026 keyv/cacheable wave
(`keyv@6.0.0`, scoped `@or-sdk/auth@0.38.2`). Exercises multi-descriptor headers
and scoped names. yarn.lock was previously collected but never parsed, so this
reported clean.
