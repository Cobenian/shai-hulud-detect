# bun-lock-attack

Bun text lockfile (`bun.lock`, Bun 1.2+) pinning two versions from the Aug 4, 2026
keyv/cacheable wave: scoped `@or-sdk/auth@0.38.2`, and `keyv@6.0.0` under a nested
install-path key (`cache-wrapper/keyv`) that only the transitive dependency declares.
Also carries a workspace entry, which has no semver version and must be skipped.
bun.lock was previously neither collected nor parsed, so this reported clean.
