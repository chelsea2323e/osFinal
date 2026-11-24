// Minimal JSON-file storage. Swap this module for SQLite/MySQL/MongoDB later;
// server.js only touches db.data and db.save().
const fs = require("fs");
const path = require("path");

// Set DATA_DIR to a persistent disk/volume on hosts that wipe the app folder on restart or redeploy.
// Without it, data.json (accounts, passwords, requests) is lost and the guard account is re-created
// with the default password.
const DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
fs.mkdirSync(DIR, { recursive: true });
const FILE = path.join(DIR, "data.json");
const data = { users: [], requests: [], campus: null };

if (fs.existsSync(FILE)) {
  try {
    Object.assign(data, JSON.parse(fs.readFileSync(FILE, "utf8")));
  } catch (err) {
    console.error(`Could not read ${FILE}: ${err.message}. Refusing to start so existing accounts are not overwritten.`);
    process.exit(1);
  }
}

function save() {
  const tmp = FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, FILE); // atomic replace, avoids half-written files
}

console.log(`Data file: ${FILE}`);

module.exports = { data, save, DIR };