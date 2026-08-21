// SYNTHETIC, INERT keyv/cacheable "Here We Go Again" C2 IoC fixture — string only.
// Nothing here runs: there is no loader, payload, or network call of any kind.
// Fallback exfiltration domain for the Aug 4, 2026 wave, corroborated by Wiz,
// Socket (DomainSender), and Aikido. Present purely as detection bait:
const KEYV_WAVE_C2_FALLBACK = "npm-cache.com";

// Rotated C2 for the same wave. The payload never hard-codes a domain: it reads the
// live one from the Ethereum contract at run time, so the attacker can swap hosts
// without republishing. On Aug 4, 2026 at 15:15 UTC an on-chain transaction did
// exactly that, moving the active C2 off npm-cache[.]com onto awqhnjewqjkl[.]icu, a
// freshly registered domain (Unit 42; Zscaler ThreatLabz). String only, as above:
const KEYV_WAVE_C2_ROTATED = "awqhnjewqjkl.icu";
