// TEST FIXTURE - May 21, 2026 Polymarket wallet-drainer typosquat IoCs.
// Inert string constants used to exercise check_polymarket_indicators. Based on
// the SafeDep disclosure (9 polymarketdev npm packages impersonating Polymarket
// trading tools, with a postinstall hook that prompts a fake wallet-onboarding
// flow and exfiltrates raw private keys to a Cloudflare Workers C2).

// C2: Cloudflare Workers subdomain under the attacker's account.
const C2_HOST = 'polymarketbot.polymarketdev.workers.dev';
const C2_ENDPOINT = 'https://polymarketbot.polymarketdev.workers.dev/v1/wallets/keys';

// Payload SHA-256 (the postinstall script body).
const PAYLOAD_SHA256 = 'e01b85c1437085a519217338fe4ee5ed7858c28a10f8c1477b2f1857c3386edb';

// npm publisher metadata fingerprint that npm caches into package.json after install.
// This is the strongest single-byte-sequence signal: ANY package.json containing this
// exact substring was published by the attacker-controlled `polymarketdev` account.
const PUBLISHER_FINGERPRINT = '"_npmUser":{"name":"polymarketdev"';

// Attacker's GitHub source repo the campaign was built from.
const ATTACKER_REPO = 'texsellix/polymarket-trading-bot';

// Local artifact paths the dropper creates to stage stolen wallet keys.
const ARTIFACT_PATHS = [
  '~/.polybot/device.json',
  '~/.polybot/wallets.json'
];
