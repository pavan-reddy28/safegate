
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

function initializeDatabase(config, logger) {
  logger.info('SQLite initialization started');

  const directory = path.dirname(config.dbPath);
  fs.mkdirSync(directory, { recursive: true });

  const db = new Database(config.dbPath);

  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('temp_store = MEMORY');

  logger.info('SQLite connection established');

  db.exec(`
    CREATE TABLE IF NOT EXISTS devices (
      device_id TEXT PRIMARY KEY,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS security_events (
      request_id TEXT PRIMARY KEY,
      device_id TEXT NOT NULL,
      event_time TEXT NOT NULL,
      decision TEXT NOT NULL
        CHECK(decision IN ('BLOCK', 'SUSPICIOUS', 'HOLD', 'SAFE')),
      score INTEGER NOT NULL
        CHECK(score >= 0 AND score <= 100),
      reasons_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK(status IN ('OPEN', 'REVIEWED', 'RESOLVED', 'ARCHIVED')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      action TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS device_commands (
      command_id TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      action TEXT NOT NULL
        CHECK(action IN ('BLOCK', 'UNBLOCK')),
      status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(status IN ('PENDING', 'APPLIED', 'FAILED')),
      created_at TEXT NOT NULL,
      acknowledged_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_events_created
      ON security_events(created_at);

    CREATE INDEX IF NOT EXISTS idx_events_device
      ON security_events(device_id);

    CREATE INDEX IF NOT EXISTS idx_events_decision
      ON security_events(decision);

    CREATE INDEX IF NOT EXISTS idx_commands_device_status
      ON device_commands(device_id, status);

    CREATE INDEX IF NOT EXISTS idx_admin_actions_request
      ON admin_actions(request_id);

    -- Persistent API request audit trail.
    CREATE TABLE IF NOT EXISTS api_request_logs (
      log_id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id TEXT NOT NULL,
      method TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      status_code INTEGER NOT NULL
        CHECK(status_code BETWEEN 100 AND 599),
      error_code TEXT,
      duration_ms REAL NOT NULL
        CHECK(duration_ms >= 0),
      occurred_at TEXT NOT NULL,
      auth_outcome TEXT NOT NULL
        CHECK(
          auth_outcome IN (
            'NOT_REQUIRED',
            'NOT_CHECKED',
            'SUCCESS',
            'FAILED'
          )
        ),
      operation TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_api_logs_occurred_at
      ON api_request_logs(occurred_at);

    CREATE INDEX IF NOT EXISTS idx_api_logs_request_id
      ON api_request_logs(request_id);

    CREATE INDEX IF NOT EXISTS idx_api_logs_endpoint
      ON api_request_logs(endpoint);

    CREATE INDEX IF NOT EXISTS idx_api_logs_status
      ON api_request_logs(status_code);
  `);

  const integrity = db.pragma('quick_check');

  if (
    !integrity.length ||
    integrity[0].quick_check !== 'ok'
  ) {
    db.close();
    throw new Error('SQLite integrity check failed');
  }

  logger.info('SQLite schema initialized');
  logger.info('SQLite indexes initialized');
  logger.info('Database integrity check passed');

  return db;
}

module.exports = { initializeDatabase };

