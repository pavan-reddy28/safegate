'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');

const V2_EVENTS_SCHEMA = `
  CREATE TABLE IF NOT EXISTS security_events (
    request_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    device_name TEXT,
    event_time TEXT NOT NULL,
    decision TEXT NOT NULL
      CHECK(decision IN ('BLOCK', 'SUSPICIOUS', 'HOLD', 'SAFE', 'KNOWN_SAFE', 'NO_KNOWN_THREAT')),
    score INTEGER NOT NULL
      CHECK(score >= 0 AND score <= 100),
    reasons_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN'
      CHECK(status IN ('OPEN', 'REVIEWED', 'RESOLVED', 'ARCHIVED')),
    verification_status TEXT NOT NULL DEFAULT 'COMPLETED'
      CHECK(verification_status IN ('COMPLETED', 'INCOMPLETE')),
    local_decision TEXT,
    stage TEXT,
    recommended_action TEXT,
    destination_host TEXT,
    registrable_domain TEXT,
    protocol TEXT,
    indicators_json TEXT NOT NULL DEFAULT '[]',
    security_checks_json TEXT NOT NULL DEFAULT '{}',
    url_inspection_json TEXT NOT NULL DEFAULT '{}',
    risk_level TEXT,
    layers_executed_count INTEGER NOT NULL DEFAULT 0,
    zero_egress INTEGER NOT NULL DEFAULT 1,
    proof_jti TEXT NOT NULL DEFAULT 'legacy',
    payload_hash TEXT NOT NULL DEFAULT '',
    app_version TEXT,
    operator_notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`;

function migrateSecurityEventsIfNeeded(db, logger) {
  const columns = db.prepare('PRAGMA table_info(security_events)').all();
  if (!columns || columns.length === 0) {
    return;
  }

  const columnNames = new Set(columns.map(col => col.name));
  const tableRow = db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'security_events'")
    .get();
  const tableSql = String(tableRow?.sql || '');

  const hasFullV2Schema =
    columnNames.has('proof_jti') &&
    columnNames.has('payload_hash') &&
    columnNames.has('destination_host') &&
    columnNames.has('security_checks_json') &&
    columnNames.has('url_inspection_json') &&
    columnNames.has('operator_notes') &&
    columnNames.has('device_name') &&
    tableSql.includes('KNOWN_SAFE');

  if (hasFullV2Schema) {
    return;
  }

  // Lightweight additive migration if operator_notes or device_name is missing on an existing v2 table
  if (
    columnNames.has('proof_jti') &&
    tableSql.includes('KNOWN_SAFE') &&
    (!columnNames.has('operator_notes') || !columnNames.has('device_name'))
  ) {
    if (!columnNames.has('operator_notes')) {
      logger.info('Adding operator_notes column to security_events');
      db.exec('ALTER TABLE security_events ADD COLUMN operator_notes TEXT;');
    }
    if (!columnNames.has('device_name')) {
      logger.info('Adding device_name column to security_events');
      db.exec('ALTER TABLE security_events ADD COLUMN device_name TEXT;');
    }
    return;
  }

  logger.info('Migrating security_events schema to v2');

  const runMigration = db.transaction(() => {
    db.exec('DROP TABLE IF EXISTS security_events_v2;');
    db.exec(
      V2_EVENTS_SCHEMA.replace('CREATE TABLE IF NOT EXISTS security_events', 'CREATE TABLE security_events_v2')
    );

    db.exec(`
      INSERT INTO security_events_v2 (
        request_id,
        device_id,
        event_time,
        decision,
        score,
        reasons_json,
        status,
        verification_status,
        proof_jti,
        payload_hash,
        created_at,
        updated_at
      )
      SELECT
        request_id,
        device_id,
        event_time,
        decision,
        score,
        reasons_json,
        status,
        'COMPLETED',
        'legacy-' || request_id,
        '',
        created_at,
        updated_at
      FROM security_events;
    `);

    db.exec('DROP TABLE security_events;');
    db.exec('ALTER TABLE security_events_v2 RENAME TO security_events;');
  });

  runMigration();
  logger.info('SQLite security_events migration completed');
}

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
      device_name TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL
    );
  `);

  const deviceColumns = db.prepare('PRAGMA table_info(devices)').all();
  if (deviceColumns && !deviceColumns.some(col => col.name === 'device_name')) {
    logger.info('Adding device_name column to devices');
    db.exec('ALTER TABLE devices ADD COLUMN device_name TEXT;');
  }

  migrateSecurityEventsIfNeeded(db, logger);

  db.exec(`
    ${V2_EVENTS_SCHEMA}

    CREATE TABLE IF NOT EXISTS consumed_proof_tokens (
      jti TEXT PRIMARY KEY,
      request_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      payload_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      consumed_at TEXT NOT NULL
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

    CREATE INDEX IF NOT EXISTS idx_events_device_name
      ON security_events(device_name);

    CREATE INDEX IF NOT EXISTS idx_events_decision
      ON security_events(decision);

    CREATE INDEX IF NOT EXISTS idx_events_domain
      ON security_events(registrable_domain);

    CREATE INDEX IF NOT EXISTS idx_proof_expires
      ON consumed_proof_tokens(expires_at);

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
