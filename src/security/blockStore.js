
import { Capacitor } from "@capacitor/core";
import { getSafeGateDatabase } from "./sqliteDatabase";

const DATABASE_NAME = "safegate-device-security";
const DATABASE_VERSION = 1;
const STORE_NAME = "blockedUrls";

let indexedDatabasePromise;

const isAndroid = () => Capacitor.getPlatform() === "android";

function validateFingerprint(fingerprint) {
  if (
    typeof fingerprint !== "string" ||
    !/^[a-f0-9]{64}$/i.test(fingerprint)
  ) {
    throw new Error("Invalid URL fingerprint");
  }
}

/* ---------------- ANDROID SQLITE ---------------- */

async function getNativeDatabase() {
  return getSafeGateDatabase();
}

function mapNativeBlock(record) {
  if (!record) return null;

  let reasonCodes = ["SECURITY_BLOCK"];

  try {
    const parsed = JSON.parse(record.reason_codes_json || "[]");

    if (Array.isArray(parsed)) {
      reasonCodes = parsed;
    }
  } catch {
    // Keep a safe default if stored metadata is malformed.
  }

  return {
    fingerprint: record.fingerprint,
    reasonCodes,
    source: record.source || "SAFEGATE",
    threatType: record.threat_type || null,
    requestId: record.request_id || null,
    createdAt: record.created_at
      ? new Date(Number(record.created_at)).toISOString()
      : null,
  };
}

async function getNativeBlockDetails(fingerprint) {
  const database = await getNativeDatabase();

  const result = await database.query(
    `SELECT
       fingerprint,
       reason_codes_json,
       source,
       threat_type,
       request_id,
       created_at
     FROM blocked_links
     WHERE fingerprint = ?
     LIMIT 1;`,
    [fingerprint]
  );

  return mapNativeBlock(result?.values?.[0] || null);
}

async function persistNativeBlock(fingerprint, details = {}) {
  const database = await getNativeDatabase();

  const reasonCodes = Array.isArray(details.reasonCodes)
    ? details.reasonCodes.filter((item) => typeof item === "string")
    : ["SECURITY_BLOCK"];

  const source =
    typeof details.source === "string"
      ? details.source
      : "SAFEGATE";

  const threatType =
    typeof details.threatType === "string"
      ? details.threatType
      : null;

  // The schema requires a non-null request_id.
  const requestId =
    typeof details.requestId === "string" && details.requestId.length > 0
      ? details.requestId
      : "UNKNOWN";

  const createdAt = Date.now();

  const result = await database.run(
    `INSERT INTO blocked_links (
       fingerprint,
       decision,
       reason_codes_json,
       threat_type,
       request_id,
       source,
       created_at
     )
     VALUES (?, 'BLOCK', ?, ?, ?, ?, ?)
     ON CONFLICT(fingerprint) DO UPDATE SET
       reason_codes_json = excluded.reason_codes_json,
       threat_type = excluded.threat_type,
       request_id = excluded.request_id,
       source = excluded.source;`,
    [
      fingerprint,
      JSON.stringify(reasonCodes),
      threatType,
      requestId,
      source,
      createdAt,
    ]
  );

  if (result?.changes?.changes === -1) {
    throw new Error("Could not save blocked URL fingerprint");
  }

  return true;
}

async function removeNativeBlock(fingerprint) {
  const database = await getNativeDatabase();

  const result = await database.run(
    "DELETE FROM blocked_links WHERE fingerprint = ?;",
    [fingerprint]
  );

  if (result?.changes?.changes === -1) {
    throw new Error("Could not remove blocked URL fingerprint");
  }

  return true;
}

/* ---------------- DESKTOP INDEXEDDB ---------------- */

function openIndexedDatabase() {
  if (indexedDatabasePromise) {
    return indexedDatabasePromise;
  }

  indexedDatabasePromise = new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error("Persistent security storage unavailable"));
      return;
    }

    const request = indexedDB.open(
      DATABASE_NAME,
      DATABASE_VERSION
    );

    request.onupgradeneeded = () => {
      const database = request.result;

      if (!database.objectStoreNames.contains(STORE_NAME)) {
        database.createObjectStore(STORE_NAME, {
          keyPath: "fingerprint",
        });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      indexedDatabasePromise = null;
      reject(new Error("Could not open security storage"));
    };

    request.onblocked = () => {
      indexedDatabasePromise = null;
      reject(new Error("Security storage upgrade blocked"));
    };
  });

  return indexedDatabasePromise;
}

async function getIndexedBlockDetails(fingerprint) {
  const database = await openIndexedDatabase();

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(
      STORE_NAME,
      "readonly"
    );

    const request = transaction
      .objectStore(STORE_NAME)
      .get(fingerprint);

    request.onsuccess = () => {
      resolve(request.result || null);
    };

    request.onerror = () => {
      reject(new Error("Could not retrieve blocked URL"));
    };
  });
}

async function persistIndexedBlock(fingerprint, details = {}) {
  const record = {
    fingerprint,
    reasonCodes: Array.isArray(details.reasonCodes)
      ? details.reasonCodes
      : ["SECURITY_BLOCK"],
    source: details.source || "SAFEGATE",
    threatType: details.threatType || null,
    requestId: details.requestId || "UNKNOWN",
    createdAt: new Date().toISOString(),
  };

  const database = await openIndexedDatabase();

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(
      STORE_NAME,
      "readwrite"
    );

    transaction.objectStore(STORE_NAME).put(record);

    transaction.oncomplete = () => resolve(true);

    transaction.onerror = () => {
      reject(new Error("Could not persist security block"));
    };

    transaction.onabort = () => {
      reject(new Error("Security block transaction aborted"));
    };
  });
}

async function removeIndexedBlock(fingerprint) {
  const database = await openIndexedDatabase();

  return new Promise((resolve, reject) => {
    const transaction = database.transaction(
      STORE_NAME,
      "readwrite"
    );

    transaction.objectStore(STORE_NAME).delete(fingerprint);

    transaction.oncomplete = () => resolve(true);

    transaction.onerror = () => {
      reject(new Error("Could not remove blocked URL"));
    };

    transaction.onabort = () => {
      reject(new Error("Block removal transaction aborted"));
    };
  });
}

/* ---------------- PUBLIC STORAGE API ---------------- */

export async function getBlockDetails(fingerprint) {
  validateFingerprint(fingerprint);

  if (isAndroid()) {
    return getNativeBlockDetails(fingerprint);
  }

  return getIndexedBlockDetails(fingerprint);
}

export async function isUrlBlocked(fingerprint) {
  const details = await getBlockDetails(fingerprint);
  return Boolean(details);
}

export async function persistBlockedUrl(fingerprint, details = {}) {
  validateFingerprint(fingerprint);

  if (isAndroid()) {
    return persistNativeBlock(fingerprint, details);
  }

  return persistIndexedBlock(fingerprint, details);
}

export async function removeBlockedUrl(fingerprint) {
  validateFingerprint(fingerprint);

  if (isAndroid()) {
    return removeNativeBlock(fingerprint);
  }

  return removeIndexedBlock(fingerprint);
}
