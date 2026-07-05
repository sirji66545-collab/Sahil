// db.js — SQLite storage layer using better-sqlite3 (synchronous, zero-config)
const Database = require("better-sqlite3");
const db = new Database("data.db");

// WAL mode = better concurrency for a small app
db.pragma("journal_mode = WAL");

// ── Schema ────────────────────────────────────────────────────────────
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  name      TEXT NOT NULL,
  email     TEXT,
  purpose   TEXT,
  disabled  INTEGER NOT NULL DEFAULT 0,   -- 0 active, 1 disabled
  created   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER NOT NULL,
  api_key       TEXT NOT NULL UNIQUE,
  revoked       INTEGER NOT NULL DEFAULT 0, -- 0 active, 1 revoked
  rate_limit    INTEGER NOT NULL DEFAULT 60,   -- X requests
  rate_window   INTEGER NOT NULL DEFAULT 60,   -- per Y seconds
  override_on   INTEGER NOT NULL DEFAULT 0,     -- per-key override toggle
  override_body TEXT,                            -- per-key custom response
  created       INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  key_id      INTEGER,
  api_key     TEXT,
  endpoint    TEXT,
  query       TEXT,
  ip          TEXT,
  status      TEXT,          -- 'success' | 'error' | 'blocked'
  status_code INTEGER,
  resp_ms     INTEGER,
  ts          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocked_ips (
  ip      TEXT PRIMARY KEY,
  created INTEGER NOT NULL
);

-- Single-row settings table for global config
CREATE TABLE IF NOT EXISTS settings (
  id            INTEGER PRIMARY KEY CHECK (id = 1),
  override_on   INTEGER NOT NULL DEFAULT 0,
  override_body TEXT
);
INSERT OR IGNORE INTO settings (id, override_on, override_body)
  VALUES (1, 0, '{"message":"This is a demo response"}');
`);

module.exports = db;
