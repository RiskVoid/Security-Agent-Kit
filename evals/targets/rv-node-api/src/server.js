// RiskVoid benchmark target. Deliberately insecure test fixture. Never deploy.
const express = require("express");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const db = require("./db");

const app = express();
app.use(express.json());

const JWT_SECRET = "secret";
const UPLOAD_DIR = path.join(__dirname, "..", "uploads");
const settings = { theme: "light", locale: "en" };

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorised" });
  }
}

app.post("/api/login", async (req, res) => {
  const user = await db.findUser(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: "bad credentials" });
  res.json({ token: jwt.sign({ id: user.id, role: user.role }, JWT_SECRET) });
});

app.get("/api/products", async (req, res) => {
  const search = req.query.search || "";
  const rows = await db.all(`SELECT id, name, price FROM products WHERE name LIKE '%${search}%'`);
  res.json(rows);
});

app.get("/api/orders/:id", auth, async (req, res) => {
  const order = await db.get("SELECT * FROM orders WHERE id = ?", [req.params.id]);
  if (!order) return res.status(404).end();
  res.json(order);
});

app.get("/api/files", auth, (req, res) => {
  const file = path.join(UPLOAD_DIR, req.query.name);
  fs.readFile(file, (err, data) => (err ? res.status(404).end() : res.send(data)));
});

app.get("/api/preview", auth, async (req, res) => {
  const r = await axios.get(req.query.url, { timeout: 5000 });
  res.json({ status: r.status, title: String(r.data).slice(0, 200) });
});

app.get("/api/admin/users", (req, res) => {
  const claims = jwt.decode((req.headers.authorization || "").replace("Bearer ", ""));
  if (!claims || claims.role !== "admin") return res.status(403).end();
  db.all("SELECT id, email, role FROM users").then((rows) => res.json(rows));
});

app.post("/api/settings", auth, (req, res) => {
  _.merge(settings, req.body);
  res.json(settings);
});

app.listen(3000);
