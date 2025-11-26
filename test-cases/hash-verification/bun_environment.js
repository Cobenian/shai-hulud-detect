// BENIGN TEST FILE - This is NOT the actual malicious bun_environment.js
// This file simulates the presence of bun_environment.js for testing detection
//
// Real malicious files would have these hashes:
// - 62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0
// - f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068
// - cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd
//
// This benign file will have a different hash and should NOT trigger hash match

console.log("This is a test file that simulates bun_environment.js");
console.log("The real malicious version would be ~10MB of obfuscated code");
console.log("Hash verification should detect filename but not confirm malicious hash");

// Simulate some environment setup (benign)
process.env.TEST_MODE = "true";
console.log("Test environment configured");