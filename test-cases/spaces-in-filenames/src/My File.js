// Test file with space in filename
// This should not crash the scanner (issue #92)

function hello() {
  console.log("Hello from a file with spaces in its name!");
}

module.exports = { hello };
