// BENIGN TEST FILE - This is NOT the actual malicious setup_bun.js
// This file simulates the presence of setup_bun.js for testing detection
//
// Real malicious file would have hash: a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a
// This benign file will have a different hash and should NOT trigger hash match

console.log("This is a test file that simulates setup_bun.js");
console.log("The real malicious version would contain obfuscated payload");
console.log("Hash verification should detect filename but not confirm malicious hash");