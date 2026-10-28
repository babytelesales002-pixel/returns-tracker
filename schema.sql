CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'sales',
  team TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS teams (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS returns (
  id TEXT PRIMARY KEY,
  date TEXT NOT NULL DEFAULT '',
  parcel TEXT NOT NULL DEFAULT '',
  carrier TEXT NOT NULL DEFAULT '',
  phone TEXT NOT NULL DEFAULT '',
  product TEXT NOT NULL DEFAULT '',
  customer TEXT NOT NULL DEFAULT '',
  address TEXT NOT NULL DEFAULT '',
  subdistrict TEXT NOT NULL DEFAULT '',
  district TEXT NOT NULL DEFAULT '',
  province TEXT NOT NULL DEFAULT '',
  zip TEXT NOT NULL DEFAULT '',
  seller TEXT NOT NULL DEFAULT '',
  team TEXT NOT NULL DEFAULT '',
  price REAL NOT NULL DEFAULT 0,
  order_qty REAL NOT NULL DEFAULT 0,
  return_qty REAL NOT NULL DEFAULT 0,
  reason_cat TEXT NOT NULL DEFAULT '',
  reason_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_returns_team ON returns(team);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
