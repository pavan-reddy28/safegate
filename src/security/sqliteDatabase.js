
import { Capacitor } from "@capacitor/core";
import {
  CapacitorSQLite,
  SQLiteConnection,
} from "@capacitor-community/sqlite";

const DATABASE_NAME = "safegate";
const DATABASE_VERSION = 1;

const sqliteConnection = new SQLiteConnection(CapacitorSQLite);

let databaseInstance = null;
let initializationPromise = null;

function generateEncryptionSecret() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random generation is unavailable.");
  }

  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);

  return Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

async function prepareEncryptionSecret() {
  const encryptionConfig =
    await sqliteConnection.isInConfigEncryption();

  if (!encryptionConfig?.result) {
    throw new Error("SQLite encryption is not enabled in Capacitor config.");
  }

  const secretStatus = await sqliteConnection.isSecretStored();
  const databaseStatus =
    await sqliteConnection.isDatabase(DATABASE_NAME);

  const secretExists = Boolean(secretStatus?.result);
  const databaseExists = Boolean(databaseStatus?.result);

  if (!secretExists && databaseExists) {
    // Never generate a replacement key for an existing encrypted database.
    throw new Error(
      "The database exists, but its encryption secret is missing. Refusing to overwrite it."
    );
  }

  if (!secretExists) {
    const secret = generateEncryptionSecret();

    // The plugin stores this passphrase in its native secure store.
    await sqliteConnection.setEncryptionSecret(secret);
  }
}

async function openConnection() {
  const consistency =
    await sqliteConnection.checkConnectionsConsistency();

  const connectionStatus =
    await sqliteConnection.isConnection(DATABASE_NAME, false);

  let database;

  if (consistency?.result && connectionStatus?.result) {
    database = await sqliteConnection.retrieveConnection(
      DATABASE_NAME,
      false
    );
  } else {
    database = await sqliteConnection.createConnection(
      DATABASE_NAME,
      true,
      "secret",
      DATABASE_VERSION,
      false
    );
  }

  await database.open();

  return database;
}

async function createDatabaseSchema(database) {
  const statements = [
    `
      CREATE TABLE IF NOT EXISTS blocked_links (
        fingerprint TEXT PRIMARY KEY NOT NULL
          CHECK(length(fingerprint) = 64),

        decision TEXT NOT NULL
          CHECK(decision = 'BLOCK'),

        reason_codes_json TEXT NOT NULL DEFAULT '[]',

        threat_type TEXT,

        request_id TEXT NOT NULL,

        source TEXT NOT NULL DEFAULT 'SAFEGATE',

        created_at INTEGER NOT NULL
      );
    `,

    `
      CREATE INDEX IF NOT EXISTS idx_blocked_links_created_at
      ON blocked_links(created_at);
    `,

    `
      CREATE TABLE IF NOT EXISTS verification_cache (
        fingerprint TEXT PRIMARY KEY NOT NULL
          CHECK(length(fingerprint) = 64),

        decision TEXT NOT NULL
          CHECK(decision IN ('SAFE', 'NO_KNOWN_THREAT')),

        request_id TEXT,

        created_at INTEGER NOT NULL,

        expires_at INTEGER NOT NULL
      );
    `,

    `
      CREATE INDEX IF NOT EXISTS idx_verification_cache_expiry
      ON verification_cache(expires_at);
    `,

    "PRAGMA foreign_keys = ON;",
    "PRAGMA secure_delete = ON;",
  ];

  for (const statement of statements) {
    const result = await database.execute(statement);

    if (result?.changes?.changes === -1) {
      throw new Error("SafeGate database schema initialization failed.");
    }
  }
}

async function initializeDatabase() {
  if (Capacitor.getPlatform() !== "android") {
    throw new Error(
      "Native SafeGate SQLite is currently configured for Android."
    );
  }

  await prepareEncryptionSecret();

  const database = await openConnection();

  try {
    await createDatabaseSchema(database);

    const encryptionStatus =
      await sqliteConnection.isDatabaseEncrypted(DATABASE_NAME);

    if (!encryptionStatus?.result) {
      throw new Error("SafeGate database encryption verification failed.");
    }

    return database;
  } catch (error) {
    await sqliteConnection
      .closeConnection(DATABASE_NAME, false)
      .catch(() => {});

    throw error;
  }
}

export async function getSafeGateDatabase() {
  if (databaseInstance) {
    return databaseInstance;
  }

  if (!initializationPromise) {
    initializationPromise = initializeDatabase();
  }

  try {
    databaseInstance = await initializationPromise;
    return databaseInstance;
  } finally {
    initializationPromise = null;
  }
}

export async function closeSafeGateDatabase() {
  if (!databaseInstance) return;

  await sqliteConnection.closeConnection(DATABASE_NAME, false);
  databaseInstance = null;
}

export async function getSafeGateDatabaseStatus() {
  const database = await getSafeGateDatabase();

  const blockedCount = await database.query(
    "SELECT COUNT(*) AS total FROM blocked_links;"
  );

  const cacheCount = await database.query(
    "SELECT COUNT(*) AS total FROM verification_cache;"
  );

  const encryption = await sqliteConnection.isDatabaseEncrypted(
    DATABASE_NAME
  );

  return {
    initialized: true,
    encrypted: Boolean(encryption?.result),
    blockedLinks: blockedCount?.values?.[0]?.total ?? 0,
    cachedResults: cacheCount?.values?.[0]?.total ?? 0,
  };
}
