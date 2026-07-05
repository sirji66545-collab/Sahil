// server.js — main Express app: admin UI, API proxy, rate limiting, logging, overrides
require("dotenv").config();
const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const UPSTREAM_BASE = process.env.UPSTREAM_BASE;
const UPSTREAM_KEY = process.env.UPSTREAM_KEY;

// The 8 original endpoints the /all route fans out to
const ALL_ENDPOINTS = ["num", "ifsc", "insta", "adhar", "pak", "veh", "tg", "familyinfo"];

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use("/public", express.static(path.join(__dirname, "public")));
app.use(session({
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 8 }, // 8h
}));

// ── Helpers ─────────────────────────────────────────────────────────────
const now = () => Date.now();
const genKey = () => "sk_" + crypto.randomBytes(20).toString("hex");

function getClientIp(req) {
  // Behind a proxy you'd trust x-forwarded-for; for local/demo use socket addr
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim()
      || req.socket.remoteAddress || "unknown";
}

function logRequest(entry) {
  db.prepare(`INSERT INTO logs
    (key_id, api_key, endpoint, query, ip, status, status_code, resp_ms, ts)
    VALUES (@key_id,@api_key,@endpoint,@query,@ip,@status,@status_code,@resp_ms,@ts)`
  ).run({ ts: now(), ...entry });
}

// ── Admin auth middleware ────────────────────────────────────────────────
function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.redirect("/admin/login");
}
function requireAdminApi(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(401).json({ error: "not authenticated" });
}

// ═══════════════════════════════════════════════════════════════════════
//  ADMIN LOGIN / SESSION
// ═══════════════════════════════════════════════════════════════════════
app.get("/admin/login", (req, res) => res.render("login", { error: null }));

app.post("/admin/login", (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    req.session.admin = true;
    return res.redirect("/admin");
  }
  res.render("login", { error: "Invalid credentials" });
});

app.post("/admin/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/admin/login"));
});

app.get("/admin", requireAdmin, (req, res) => res.render("dashboard"));

// ═══════════════════════════════════════════════════════════════════════
//  ADMIN API (JSON) — all protected
// ═══════════════════════════════════════════════════════════════════════

// ── Users ──
app.get("/admin/api/users", requireAdminApi, (req, res) => {
  const users = db.prepare("SELECT * FROM users ORDER BY created DESC").all();
  // attach keys to each user
  const keysByUser = {};
  for (const k of db.prepare("SELECT * FROM keys").all()) {
    (keysByUser[k.user_id] ||= []).push(k);
  }
  res.json(users.map(u => ({ ...u, keys: keysByUser[u.id] || [] })));
});

app.post("/admin/api/users", requireAdminApi, (req, res) => {
  const { name, email, purpose } = req.body;
  if (!name) return res.status(400).json({ error: "name required" });
  const info = db.prepare(
    "INSERT INTO users (name,email,purpose,created) VALUES (?,?,?,?)"
  ).run(name, email || "", purpose || "", now());
  res.json({ id: info.lastInsertRowid });
});

// disable/enable a user
app.post("/admin/api/users/:id/toggle", requireAdminApi, (req, res) => {
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.params.id);
  if (!u) return res.status(404).json({ error: "not found" });
  db.prepare("UPDATE users SET disabled=? WHERE id=?").run(u.disabled ? 0 : 1, u.id);
  res.json({ ok: true, disabled: u.disabled ? 0 : 1 });
});

app.delete("/admin/api/users/:id", requireAdminApi, (req, res) => {
  db.prepare("DELETE FROM keys WHERE user_id=?").run(req.params.id);
  db.prepare("DELETE FROM users WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ── Keys ──
// Custom key creation: pass `custom` to set your own string, otherwise auto-generate
app.post("/admin/api/keys", requireAdminApi, (req, res) => {
  const { user_id, custom, rate_limit, rate_window } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(user_id);
  if (!user) return res.status(400).json({ error: "invalid user_id" });

  const apiKey = (custom && custom.trim()) ? custom.trim() : genKey();
  // reject duplicates
  if (db.prepare("SELECT 1 FROM keys WHERE api_key=?").get(apiKey))
    return res.status(409).json({ error: "key already exists" });

  const info = db.prepare(`INSERT INTO keys
    (user_id, api_key, rate_limit, rate_window, created)
    VALUES (?,?,?,?,?)`
  ).run(user_id, apiKey, rate_limit || 60, rate_window || 60, now());
  res.json({ id: info.lastInsertRowid, api_key: apiKey });
});

// regenerate (replaces the key string, keeps settings)
app.post("/admin/api/keys/:id/regenerate", requireAdminApi, (req, res) => {
  const newKey = genKey();
  db.prepare("UPDATE keys SET api_key=?, revoked=0 WHERE id=?").run(newKey, req.params.id);
  res.json({ api_key: newKey });
});

// revoke / unrevoke
app.post("/admin/api/keys/:id/revoke", requireAdminApi, (req, res) => {
  const k = db.prepare("SELECT * FROM keys WHERE id=?").get(req.params.id);
  if (!k) return res.status(404).json({ error: "not found" });
  db.prepare("UPDATE keys SET revoked=? WHERE id=?").run(k.revoked ? 0 : 1, k.id);
  res.json({ ok: true, revoked: k.revoked ? 0 : 1 });
});

// update rate limit / per-key override
app.post("/admin/api/keys/:id/update", requireAdminApi, (req, res) => {
  const { rate_limit, rate_window, override_on, override_body } = req.body;
  const k = db.prepare("SELECT * FROM keys WHERE id=?").get(req.params.id);
  if (!k) return res.status(404).json({ error: "not found" });
  db.prepare(`UPDATE keys SET rate_limit=?, rate_window=?, override_on=?, override_body=? WHERE id=?`)
    .run(
      rate_limit ?? k.rate_limit,
      rate_window ?? k.rate_window,
      override_on ? 1 : 0,
      override_body ?? k.override_body,
      k.id
    );
  res.json({ ok: true });
});

app.delete("/admin/api/keys/:id", requireAdminApi, (req, res) => {
  db.prepare("DELETE FROM keys WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

// ── Global settings (override mode) ──
app.get("/admin/api/settings", requireAdminApi, (req, res) => {
  res.json(db.prepare("SELECT * FROM settings WHERE id=1").get());
});
app.post("/admin/api/settings", requireAdminApi, (req, res) => {
  const { override_on, override_body } = req.body;
  const cur = db.prepare("SELECT * FROM settings WHERE id=1").get();
  db.prepare("UPDATE settings SET override_on=?, override_body=? WHERE id=1")
    .run(override_on ? 1 : 0, override_body ?? cur.override_body);
  res.json({ ok: true });
});

// ── IP blacklist ──
app.get("/admin/api/blocked-ips", requireAdminApi, (req, res) => {
  res.json(db.prepare("SELECT * FROM blocked_ips ORDER BY created DESC").all());
});
app.post("/admin/api/blocked-ips", requireAdminApi, (req, res) => {
  db.prepare("INSERT OR IGNORE INTO blocked_ips (ip,created) VALUES (?,?)")
    .run(req.body.ip, now());
  res.json({ ok: true });
});
app.delete("/admin/api/blocked-ips/:ip", requireAdminApi, (req, res) => {
  db.prepare("DELETE FROM blocked_ips WHERE ip=?").run(req.params.ip);
  res.json({ ok: true });
});

// ── Logs & analytics ──
app.get("/admin/api/logs", requireAdminApi, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  res.json(db.prepare("SELECT * FROM logs ORDER BY ts DESC LIMIT ?").all(limit));
});

app.get("/admin/api/logs/by-ip/:ip", requireAdminApi, (req, res) => {
  res.json(db.prepare("SELECT * FROM logs WHERE ip=? ORDER BY ts DESC LIMIT 500").all(req.params.ip));
});

app.get("/admin/api/analytics", requireAdminApi, (req, res) => {
  const day = 86400000, week = day * 7;
  const t = now();
  const count = (since) =>
    db.prepare("SELECT COUNT(*) c FROM logs WHERE ts >= ?").get(t - since).c;

  const topEndpoints = db.prepare(
    "SELECT endpoint, COUNT(*) c FROM logs GROUP BY endpoint ORDER BY c DESC LIMIT 5"
  ).all();

  const topUsers = db.prepare(`
    SELECT u.name, COUNT(*) c FROM logs l
    JOIN keys k ON k.id = l.key_id
    JOIN users u ON u.id = k.user_id
    GROUP BY u.id ORDER BY c DESC LIMIT 5`).all();

  const activeKeys = db.prepare("SELECT COUNT(*) c FROM keys WHERE revoked=0").get().c;
  const revokedKeys = db.prepare("SELECT COUNT(*) c FROM keys WHERE revoked=1").get().c;
  const recent = db.prepare("SELECT * FROM logs ORDER BY ts DESC LIMIT 10").all();

  res.json({
    today: count(day),
    week: count(week),
    allTime: db.prepare("SELECT COUNT(*) c FROM logs").get().c,
    topEndpoints, topUsers, activeKeys, revokedKeys, recent,
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  PUBLIC API PROXY  — /num, /ifsc, ... and /all
//  Flow: validate key → check IP blacklist → rate limit → override? → proxy
// ═══════════════════════════════════════════════════════════════════════

// simple in-memory sliding window: { keyId: [timestamps] }
const rateBuckets = new Map();

function checkRateLimit(k) {
  const windowMs = k.rate_window * 1000;
  const t = now();
  let hits = (rateBuckets.get(k.id) || []).filter(ts => ts > t - windowMs);
  const remaining = k.rate_limit - hits.length;
  const resetMs = hits.length ? (hits[0] + windowMs - t) : windowMs;
  return { allowed: remaining > 0, remaining: Math.max(0, remaining), resetMs, hits };
}
function recordHit(k, hits) {
  hits.push(now());
  rateBuckets.set(k.id, hits);
}

// Middleware that all API routes run through
function apiGate(req, res, next) {
  req._start = now();
  const apiKey = req.query.key;
  const ip = getClientIp(req);
  req._ip = ip;

  // IP blacklist
  if (db.prepare("SELECT 1 FROM blocked_ips WHERE ip=?").get(ip)) {
    logRequest({ key_id: null, api_key: apiKey, endpoint: req.path, query: req.query.q,
      ip, status: "blocked", status_code: 403, resp_ms: 0 });
    return res.status(403).json({ error: "IP blocked" });
  }

  // Key validation
  if (!apiKey) return res.status(401).json({ error: "missing key" });
  const k = db.prepare("SELECT * FROM keys WHERE api_key=?").get(apiKey);
  if (!k || k.revoked) {
    logRequest({ key_id: k?.id || null, api_key: apiKey, endpoint: req.path, query: req.query.q,
      ip, status: "error", status_code: 401, resp_ms: 0 });
    return res.status(401).json({ error: "invalid or revoked key" });
  }
  const user = db.prepare("SELECT * FROM users WHERE id=?").get(k.user_id);
  if (!user || user.disabled) return res.status(403).json({ error: "user disabled" });

  // Rate limit
  const rl = checkRateLimit(k);
  res.set("X-RateLimit-Limit", k.rate_limit);
  res.set("X-RateLimit-Remaining", rl.remaining);
  res.set("X-RateLimit-Reset", Math.ceil(rl.resetMs / 1000));
  if (!rl.allowed) {
    logRequest({ key_id: k.id, api_key: apiKey, endpoint: req.path, query: req.query.q,
      ip, status: "blocked", status_code: 429, resp_ms: 0 });
    return res.status(429).json({
      error: "rate limit exceeded",
      reset_seconds: Math.ceil(rl.resetMs / 1000),
    });
  }
  recordHit(k, rl.hits);

  req._key = k;
  next();
}

// Resolve override: per-key wins over global
function resolveOverride(k) {
  if (k.override_on && k.override_body) return k.override_body;
  const s = db.prepare("SELECT * FROM settings WHERE id=1").get();
  if (s.override_on && s.override_body) return s.override_body;
  return null;
}

// Try to parse override as JSON, else return as plain text payload
function sendOverride(res, body) {
  try { return res.json(JSON.parse(body)); }
  catch { return res.json({ message: body }); }
}

// Call one upstream endpoint
async function callUpstream(endpoint, q) {
  const url = `${UPSTREAM_BASE}/${endpoint}?key=${encodeURIComponent(UPSTREAM_KEY)}&q=${encodeURIComponent(q || "")}`;
  const r = await fetch(url);
  const text = await r.text();
  try { return { ok: r.ok, status: r.status, data: JSON.parse(text) }; }
  catch { return { ok: r.ok, status: r.status, data: text }; }
}

// ── Single endpoints: /num, /ifsc, ... ──
for (const ep of ALL_ENDPOINTS) {
  app.get(`/${ep}`, apiGate, async (req, res) => {
    const k = req._key, q = req.query.q;
    const override = resolveOverride(k);
    if (override) {
      logRequest({ key_id: k.id, api_key: k.api_key, endpoint: `/${ep}`, query: q,
        ip: req._ip, status: "success", status_code: 200, resp_ms: now() - req._start });
      return sendOverride(res, override);
    }
    try {
      const out = await callUpstream(ep, q);
      logRequest({ key_id: k.id, api_key: k.api_key, endpoint: `/${ep}`, query: q,
        ip: req._ip, status: out.ok ? "success" : "error", status_code: out.status,
        resp_ms: now() - req._start });
      res.status(out.status).json(out.data);
    } catch (e) {
      logRequest({ key_id: k.id, api_key: k.api_key, endpoint: `/${ep}`, query: q,
        ip: req._ip, status: "error", status_code: 502, resp_ms: now() - req._start });
      res.status(502).json({ error: "upstream failed", detail: String(e) });
    }
  });
}

// ── Combined endpoint: /all — fans out to all 8 ──
app.get("/all", apiGate, async (req, res) => {
  const k = req._key, q = req.query.q;
  const override = resolveOverride(k);
  if (override) {
    logRequest({ key_id: k.id, api_key: k.api_key, endpoint: "/all", query: q,
      ip: req._ip, status: "success", status_code: 200, resp_ms: now() - req._start });
    return sendOverride(res, override);
  }
  // fire all upstream calls in parallel
  const results = await Promise.allSettled(ALL_ENDPOINTS.map(ep => callUpstream(ep, q)));
  const aggregated = {};
  ALL_ENDPOINTS.forEach((ep, i) => {
    const r = results[i];
    aggregated[ep] = r.status === "fulfilled" ? r.value.data : { error: String(r.reason) };
  });
  logRequest({ key_id: k.id, api_key: k.api_key, endpoint: "/all", query: q,
    ip: req._ip, status: "success", status_code: 200, resp_ms: now() - req._start });
  res.json(aggregated);
});

app.get("/", (req, res) => res.redirect("/admin"));

app.listen(PORT, () => {
  console.log(`Admin panel:  http://localhost:${PORT}/admin`);
  console.log(`Login page:   http://localhost:${PORT}/admin/login`);
});
