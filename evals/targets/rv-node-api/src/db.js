const sqlite3 = require("sqlite3");
const crypto = require("crypto");
const conn = new sqlite3.Database("app.db");

const all = (sql, params = []) => new Promise((ok, fail) => conn.all(sql, params, (e, r) => (e ? fail(e) : ok(r))));
const get = (sql, params = []) => new Promise((ok, fail) => conn.get(sql, params, (e, r) => (e ? fail(e) : ok(r))));

async function findUser(email, password) {
  const hash = crypto.createHash("md5").update(password).digest("hex");
  return get("SELECT * FROM users WHERE email = ? AND password_hash = ?", [email, hash]);
}

module.exports = { all, get, findUser };
