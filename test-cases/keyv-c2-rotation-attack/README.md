# keyv-c2-rotation-attack

The C2-rotation channel of the August 4, 2026 Shai-Hulud "Here We Go Again"
keyv/cacheable wave.

The payload does not hard-code its exfil host. It reads the current C2 from an
Ethereum smart contract, which is why the fallback domain `npm-cache[.]com`
is short-lived while the rotation mechanism is not:

- contract `0xE1f2395ee43e45A1556EC6438a88c31B83493103`
- read over the `eth-mainnet.nodereal[.]io` RPC endpoint

Both are present here, plus the lowercase form of the address, since Ethereum
addresses are case-insensitive outside EIP-55 checksumming.

Inert: string constants only. No payload, no network calls, no real key.
