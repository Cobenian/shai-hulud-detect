# hash-in-node-modules

Regression fixture: files inside `node_modules/` must be included in the SHA-256
hash sweep (`check_file_hashes`).

npm supply-chain payloads arrive inside `node_modules` by definition — the Aug 4,
2026 keyv/cacheable wave drops `setup.mjs` and `Math_Symbol.js` there — but the
hash sweep used to skip that directory entirely, so the payload hashes in
`MALICIOUS_HASHLIST` could never match where it actually lands.

All files here are inert placeholders. The test asserts that the hash sweep
covers every collected file rather than matching any particular hash, since a
fixture cannot reproduce a real malicious hash.
