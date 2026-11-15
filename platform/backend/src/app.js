
"use strict";

const crypto = require("node:crypto");
const express = require("express");
const helmet = require("helmet");

const VALID_DECISIONS = [
  "BLOCK",
  "SUSPICIOUS",
  "HOLD",
  "SAFE"
];

const VALID_STATUSES = [
  "OPEN",
  "REVIEWED",
  "RESOLVED",
  "ARCHIVED"
];

const VALID_REASON = /^[A-Z0-9][A-Z0-9_.:-]{0,63}$/;
const VALID_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;

function createApp({
  db,
  config = {},
  logger = null,
  metrics = null,
  apiTokenStore
} = {}) {
  if (!db) {
    throw new Error("SQLite database connection is required");
  }

  if (
    !apiTokenStore ||
    typeof apiTokenStore.matches !== "function"
  ) {
    throw new Error("Key Vault API token store is required");
  }

  const app = express();

  app.disable("x-powered-by");

  // --------------------------------------------------
  // LOGGING
  // --------------------------------------------------

  function writeLog(level, message, metadata = {}) {
    if (logger && typeof logger[level] === "function") {
      logger[level](message, metadata);
      return;
    }

    console.log(JSON.stringify({
      level: level.toUpperCase(),
      service: "safegateway.platform",
      message,
      ...metadata
    }));
  }

  // --------------------------------------------------
  // ERROR RESPONSE
  // --------------------------------------------------

  function sendError(res, status, code, message, requestId) {
    const safeMessage = String(message || "Request failed");

    res.locals.apiError = {
      code: String(code || "REQUEST_FAILED"),
      message: safeMessage
    };

    return res.status(status).json({
      error: {
        code,
        message: safeMessage,
        requestId
      }
    });
  }

  // --------------------------------------------------
  // VALIDATION HELPERS
  // --------------------------------------------------

  function isValidId(value) {
    return typeof value === "string" && VALID_ID.test(value);
  }

  function parseReasons(value) {
    if (!Array.isArray(value) || value.length > 20) {
      return null;
    }

    for (const reason of value) {
      if (
        typeof reason !== "string" ||
        !VALID_REASON.test(reason)
      ) {
        return null;
      }
    }

    return [...new Set(value)];
  }

  // --------------------------------------------------
  // EVENT FORMATTER
  // --------------------------------------------------

  function formatEvent(row) {
    let reasons = [];

    try {
      reasons = JSON.parse(row.reasons_json);

      if (!Array.isArray(reasons)) {
        reasons = [];
      }
    } catch {
      reasons = [];
    }

    return {
      requestId: row.request_id,
      deviceId: row.device_id,
      eventTime: row.event_time,
      decision: row.decision,
      score: row.score,
      reasons,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at
    };
  }

  // --------------------------------------------------
  // DEVICE REGISTRATION
  // --------------------------------------------------

  function upsertDevice(deviceId, timestamp) {
    db.prepare(`
      INSERT INTO devices (
        device_id,
        status,
        first_seen_at,
        last_seen_at
      )
      VALUES (?, 'ACTIVE', ?, ?)
      ON CONFLICT(device_id)
      DO UPDATE SET
        status = 'ACTIVE',
        last_seen_at = excluded.last_seen_at
    `).run(
      deviceId,
      timestamp,
      timestamp
    );
  }

  // --------------------------------------------------
  // HTTP REQUEST AUDIT HELPERS
  // --------------------------------------------------

  function safeAuditEndpoint(req) {
    const matchedRoute = req.route && req.route.path;

    if (typeof matchedRoute === "string") {
      return `${req.baseUrl || ""}${matchedRoute}`.slice(0, 256);
    }

    const pathname = req.path || "/";

    if (pathname === "/health") {
      return "/health";
    }

    if (pathname === "/ready") {
      return "/ready";
    }

    if (pathname === "/api/v1/events") {
      return "/api/v1/events";
    }

    if (/^\/api\/v1\/events\/[^/]+$/.test(pathname)) {
      return "/api/v1/events/:requestId";
    }

    if (pathname === "/api/v1/admin/db/query") {
      return "/api/v1/admin/db/query";
    }

    return String(pathname).slice(0, 256);
  }

  function resolveOperation(method, endpoint) {
    if (endpoint === "/api/v1/admin/db/query") {
      return "READ";
    }

    switch (method) {
      case "GET":
      case "HEAD":
        return "READ";

      case "POST":
        return "CREATE";

      case "PUT":
      case "PATCH":
        return "UPDATE";

      case "DELETE":
        return "DELETE";

      default:
        return "OTHER";
    }
  }

  // --------------------------------------------------
  // PERSISTENT HTTP AUDIT TABLE
  // Created by database.js.
  // --------------------------------------------------

  const insertApiAudit = db.prepare(`
    INSERT INTO api_request_logs (
      request_id,
      method,
      endpoint,
      status_code,
      error_code,
      duration_ms,
      occurred_at,
      auth_outcome,
      operation
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  // --------------------------------------------------
  // HTTP REQUEST AUDIT MIDDLEWARE
  // --------------------------------------------------

  // This runs before authentication, routing and JSON parsing.
  // Therefore failed authentication and invalid JSON are recorded too.

  app.use((req, res, next) => {
    const startedAt = process.hrtime.bigint();

    // Always generate our own request ID.
    req.requestId = crypto.randomUUID();

    res.setHeader("X-Request-ID", req.requestId);

    const initialPath = String(req.path || "/");

    const isApiRequest =
      initialPath === "/api/v1" ||
      initialPath.startsWith("/api/v1/");

    req.authOutcome = isApiRequest
      ? "NOT_CHECKED"
      : "NOT_REQUIRED";

    if (isApiRequest && metrics) {
      metrics.requestsSinceHeartbeat =
        (metrics.requestsSinceHeartbeat || 0) + 1;
    }

    let recorded = false;

    function persistAudit(aborted = false) {
      if (recorded) return;

      recorded = true;

      const statusCode = aborted ? 499 : res.statusCode;

      const method = String(req.method || "UNKNOWN")
        .toUpperCase()
        .slice(0, 20);

      const endpoint = safeAuditEndpoint(req);

      const elapsedNanoseconds =
        process.hrtime.bigint() - startedAt;

      const durationMs =
        Number(elapsedNanoseconds) / 1e6;

      const apiError = res.locals?.apiError || null;
      const internalError = res.locals?.internalError || null;

      let errorCode = null;

      if (statusCode >= 400) {
        errorCode =
          internalError?.errorCode ||
          apiError?.code ||
          (aborted
            ? "REQUEST_ABORTED"
            : `HTTP_${statusCode}`);

        if (
          typeof errorCode !== "string" ||
          !/^[A-Z0-9_.:-]{1,64}$/.test(errorCode)
        ) {
          errorCode = `HTTP_${statusCode}`;
        }
      }

      const allowedAuthOutcomes = [
        "NOT_REQUIRED",
        "NOT_CHECKED",
        "SUCCESS",
        "FAILED"
      ];

      const authOutcome = allowedAuthOutcomes.includes(
        req.authOutcome
      )
        ? req.authOutcome
        : "NOT_CHECKED";

      const operation = res.locals?.auditOperation || resolveOperation(method, endpoint);

      const occurredAt = new Date().toISOString();

      try {
        insertApiAudit.run(
          req.requestId,
          method,
          endpoint,
          statusCode,
          errorCode,
          Math.max(0, durationMs),
          occurredAt,
          authOutcome,
          operation
        );
      } catch (error) {
        const safeErrorCode =
          typeof error?.code === "string" &&
          /^[A-Z0-9_]+$/.test(error.code)
            ? error.code
            : "AUDIT_WRITE_FAILED";

        writeLog("error", "API audit persistence failed", {
          requestId: req.requestId,
          errorCode: safeErrorCode
        });
      }

      const logLevel =
        statusCode >= 500
          ? "error"
          : statusCode >= 400
            ? "warn"
            : "info";

      writeLog(logLevel, "API request completed", {
        requestId: req.requestId,
        method,
        endpoint,
        statusCode,
        errorCode,
        durationMs: Math.round(durationMs * 1000) / 1000,
        authOutcome,
        operation
      });
    }

    res.once("finish", () => {
      persistAudit(false);
    });

    res.once("close", () => {
      if (!res.writableFinished) {
        persistAudit(true);
      }
    });

    next();
  });

  // --------------------------------------------------
  // SECURITY MIDDLEWARE
  // --------------------------------------------------

  app.use(helmet({
    frameguard: {
      action: "deny"
    }
  }));

  app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  });

  // --------------------------------------------------
  // HEALTH CHECK
  // --------------------------------------------------

  app.get("/health", (req, res) => {
    return res.status(200).json({
      status: "ok",
      application: "safegate-platform"
    });
  });

  // --------------------------------------------------
  // DATABASE READINESS
  // --------------------------------------------------

  app.get("/ready", (req, res) => {
    try {
      const integrity = db.pragma("quick_check");

      if (
        !integrity.length ||
        integrity[0].quick_check !== "ok"
      ) {
        return res.status(503).json({
          status: "not-ready"
        });
      }

      return res.status(200).json({
        status: "ready",
        database: "connected"
      });
    } catch {
      return res.status(503).json({
        status: "not-ready"
      });
    }
  });

  // --------------------------------------------------
  // API RATE LIMITING
  // --------------------------------------------------

  const apiRateBuckets = new Map();

  const API_RATE_WINDOW_MS = 60 * 1000;
  const API_RATE_MAX_REQUESTS = 1200;
  const API_RATE_MAX_BUCKETS = 10000;

  function resolveRateLimitKey(req) {
    const forwardedAddress = req.get("x-real-ip") || "";

    if (
      forwardedAddress.length > 0 &&
      forwardedAddress.length <= 64 &&
      /^[0-9a-fA-F:.]+$/.test(forwardedAddress)
    ) {
      return forwardedAddress;
    }

    return req.socket?.remoteAddress || "internal";
  }

  function pruneRateBuckets(now) {
    for (const [key, bucket] of apiRateBuckets) {
      if (bucket.resetAt <= now) {
        apiRateBuckets.delete(key);
      }
    }
  }

  function rateLimitApiRequests(req, res, next) {
    const now = Date.now();

    const key = resolveRateLimitKey(req);

    let bucket = apiRateBuckets.get(key);

    if (!bucket || bucket.resetAt <= now) {
      if (apiRateBuckets.size >= API_RATE_MAX_BUCKETS) {
        pruneRateBuckets(now);
      }

      if (
        apiRateBuckets.size >= API_RATE_MAX_BUCKETS &&
        !apiRateBuckets.has(key)
      ) {
        res.setHeader("Retry-After", "60");

        return sendError(
          res,
          429,
          "RATE_LIMITED",
          "Request rate is temporarily limited",
          req.requestId
        );
      }

      bucket = {
        count: 0,
        resetAt: now + API_RATE_WINDOW_MS
      };

      apiRateBuckets.set(key, bucket);
    }

    bucket.count += 1;

    if (bucket.count > API_RATE_MAX_REQUESTS) {
      const retryAfter = Math.max(
        1,
        Math.ceil((bucket.resetAt - now) / 1000)
      );

      res.setHeader("Retry-After", String(retryAfter));

      return sendError(
        res,
        429,
        "RATE_LIMITED",
        "Request rate is temporarily limited",
        req.requestId
      );
    }

    next();
  }

  // --------------------------------------------------
  // COMMON KEY VAULT TOKEN AUTHENTICATION
  // --------------------------------------------------

  // Every /api/v1 endpoint uses the same rotating token store.
  // The store is populated by server.js using the Vault rotator.
  // No separate SQL administrator credential is used.

  function authenticate(req, res, next) {
    req.authOutcome = "FAILED";

    const authorization = req.get("authorization") || "";

    const match = authorization.match(
      /^Bearer ([a-fA-F0-9]{64})$/i
    );

    if (!match || !apiTokenStore.matches(match[1])) {
      writeLog("warn", "API authentication rejected", {
        requestId: req.requestId
      });

      return sendError(
        res,
        401,
        "UNAUTHORIZED",
        "Valid authentication is required",
        req.requestId
      );
    }

    req.authOutcome = "SUCCESS";

    res.setHeader("Cache-Control", "no-store");

    next();
  }

  // --------------------------------------------------
  // API MIDDLEWARE ORDER
  // --------------------------------------------------

  // 1. Rate limiting
  // 2. Common Key Vault token authentication
  // 3. JSON parsing
  // 4. API routes

  app.use("/api/v1", rateLimitApiRequests);

  app.use("/api/v1", authenticate);

  app.use("/api/v1", express.json({
    limit: "16kb",
    strict: true
  }));

  // --------------------------------------------------
  
  // --------------------------------------------------
  // SQLITE ADMINISTRATION API
  // Common rotating Key Vault authentication applies.
  // --------------------------------------------------

  function classifySqlOperation(sql, readOnly = false) {
    if (readOnly === true) return "READ";

    const cleaned = String(sql || "")
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/--[^\r\n]*/g, " ")
      .trim();

    const first = cleaned.match(/^([A-Za-z]+)/)?.[1]?.toUpperCase();

    if (first === "WITH") {
      const matches = [
        ...cleaned.matchAll(/\b(INSERT|REPLACE|UPDATE|DELETE)\b/gi)
      ];

      if (matches.length) {
        return classifySqlOperation(matches[matches.length - 1][1]);
      }

      return "READ";
    }

    switch (first) {
      case "SELECT":
      case "EXPLAIN":
      case "SHOW":
        return "READ";

      case "INSERT":
      case "REPLACE":
        return "CREATE";

      case "UPDATE":
        return "UPDATE";

      case "DELETE":
        return "DELETE";

      case "CREATE":
      case "ALTER":
      case "DROP":
      case "VACUUM":
      case "REINDEX":
      case "ANALYZE":
        return "SCHEMA";

      case "PRAGMA":
        return "SCHEMA";

      default:
        return "OTHER";
    }
  }

  app.post("/api/v1/admin/db/query", (req, res) => {
    let sql = "";

    try {
      const body = req.body;

      if (
        !body ||
        typeof body !== "object" ||
        Array.isArray(body)
      ) {
        return sendError(
          res, 400, "INVALID_BODY",
          "A JSON object is required", req.requestId
        );
      }

      if (
        Object.keys(body).some(
          key => !["query", "params"].includes(key)
        )
      ) {
        return sendError(
          res, 400, "INVALID_FIELDS",
          "Only query and params fields are accepted", req.requestId
        );
      }

      if (
        typeof body.query !== "string" ||
        body.query.trim().length === 0 ||
        Buffer.byteLength(body.query, "utf8") > 12000
      ) {
        return sendError(
          res, 400, "INVALID_QUERY",
          "A valid SQL query is required", req.requestId
        );
      }

      sql = body.query.trim();

      // MySQL-style SHOW TABLES compatibility.
      if (/^SHOW\s+TABLES\s*;?$/i.test(sql)) {
        sql = `
          SELECT name
          FROM sqlite_master
          WHERE type = 'table'
          ORDER BY name
        `;
      }

      const policySql = sql
        .replace(/\/\*[\s\S]*?\*\//g, " ")
        .replace(/--[^\r\n]*/g, " ")
        .trim();

      res.locals.auditOperation = classifySqlOperation(sql);

      // Protect the shared application connection and filesystem.
      if (
        /^(ATTACH|DETACH|BEGIN|COMMIT|END|ROLLBACK|SAVEPOINT|RELEASE)\b/i.test(policySql) ||
        /^VACUUM\b[\s\S]*\bINTO\b/i.test(policySql)
      ) {
        return sendError(
          res, 403, "SQL_OPERATION_RESTRICTED",
          "This database operation is restricted", req.requestId
        );
      }

      // Do not let an API request alter important connection settings.
      if (
        /^PRAGMA\s+(writable_schema|journal_mode|synchronous|foreign_keys|locking_mode|temp_store_directory|data_store_directory|query_only)\s*(?:=|\()/i.test(policySql)
      ) {
        return sendError(
          res, 403, "PRAGMA_OPERATION_RESTRICTED",
          "Modification of this SQLite setting is restricted", req.requestId
        );
      }

      const suppliedParams =
        body.params === undefined ? [] : body.params;

      let bindArgs;

      if (Array.isArray(suppliedParams)) {
        if (suppliedParams.length > 100) {
          return sendError(
            res, 400, "INVALID_PARAMETERS",
            "Too many SQL parameters", req.requestId
          );
        }

        const normalized = [];

        for (const value of suppliedParams) {
          if (value === null) {
            normalized.push(null);
          } else if (typeof value === "boolean") {
            normalized.push(value ? 1 : 0);
          } else if (
            typeof value === "number" &&
            Number.isFinite(value)
          ) {
            normalized.push(value);
          } else if (
            typeof value === "string" &&
            Buffer.byteLength(value, "utf8") <= 4096
          ) {
            normalized.push(value);
          } else {
            return sendError(
              res, 400, "INVALID_PARAMETERS",
              "Unsupported SQL parameter value", req.requestId
            );
          }
        }

        bindArgs = normalized;
      } else if (
        suppliedParams !== null &&
        typeof suppliedParams === "object"
      ) {
        const entries = Object.entries(suppliedParams);

        if (entries.length > 100) {
          return sendError(
            res, 400, "INVALID_PARAMETERS",
            "Too many SQL parameters", req.requestId
          );
        }

        const normalized = {};

        for (const [key, value] of entries) {
          if (
            !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ||
            ["__proto__", "constructor", "prototype"].includes(key)
          ) {
            return sendError(
              res, 400, "INVALID_PARAMETERS",
              "Invalid named SQL parameter", req.requestId
            );
          }

          if (value === null) {
            normalized[key] = null;
          } else if (typeof value === "boolean") {
            normalized[key] = value ? 1 : 0;
          } else if (
            typeof value === "number" &&
            Number.isFinite(value)
          ) {
            normalized[key] = value;
          } else if (
            typeof value === "string" &&
            Buffer.byteLength(value, "utf8") <= 4096
          ) {
            normalized[key] = value;
          } else {
            return sendError(
              res, 400, "INVALID_PARAMETERS",
              "Unsupported SQL parameter value", req.requestId
            );
          }
        }

        bindArgs = entries.length ? [normalized] : [];
      } else {
        return sendError(
          res, 400, "INVALID_PARAMETERS",
          "Params must be an array or named parameter object", req.requestId
        );
      }

      // better-sqlite3 prepares one statement per prepare() call.
      const statement = db.prepare(sql);

      const readOnly = statement.readonly === true;
      const returnsRows = statement.reader === true;

      res.locals.auditOperation = classifySqlOperation(
        sql,
        readOnly
      );

      // SELECT, PRAGMA reads and DML with RETURNING.
      if (returnsRows) {
        const rows = [];
        let totalBytes = 0;
        let truncated = false;

        for (const rawRow of statement.raw().iterate(...bindArgs)) {
          if (rows.length >= 100) {
            truncated = true;
            break;
          }

          const row = rawRow.map(value => {
            if (Buffer.isBuffer(value)) {
              return {
                type: "BLOB",
                bytes: value.length
              };
            }

            if (typeof value === "bigint") {
              return value.toString();
            }

            if (
              typeof value === "string" &&
              Buffer.byteLength(value, "utf8") > 16384
            ) {
              return `${value.slice(0, 16384)}[TRUNCATED]`;
            }

            return value;
          });

          const rowBytes = Buffer.byteLength(
            JSON.stringify(row),
            "utf8"
          );

          if (
            rowBytes > 65536 ||
            totalBytes + rowBytes > 262144
          ) {
            truncated = true;
            break;
          }

          rows.push(row);
          totalBytes += rowBytes;
        }

        const columns = statement.columns().map(
          column => column.name
        );

        return res.status(200).json({
          requestId: req.requestId,
          success: true,
          statementType: classifySqlOperation(sql, readOnly),
          readOnly,
          columns,
          rows,
          rowCount: rows.length,
          truncated
        });
      }

      // INSERT, UPDATE, DELETE, CREATE, ALTER, DROP and other
      // non-row-returning SQLite statements.
      const result = statement.run(...bindArgs);

      const lastInsertRowid =
        typeof result.lastInsertRowid === "bigint"
          ? result.lastInsertRowid.toString()
          : result.lastInsertRowid;

      return res.status(200).json({
        requestId: req.requestId,
        success: true,
        statementType: classifySqlOperation(sql, readOnly),
        readOnly,
        changes: result.changes,
        lastInsertRowid,
        columns: [],
        rows: [],
        rowCount: 0
      });

    } catch (error) {
      const multipleStatements =
        error instanceof RangeError &&
        /more than one statement/i.test(error.message || "");

      return sendError(
        res,
        400,
        multipleStatements
          ? "MULTIPLE_STATEMENTS_NOT_ALLOWED"
          : "QUERY_EXECUTION_FAILED",
        multipleStatements
          ? "Only one SQL statement is allowed per request"
          : "The SQL statement could not be executed",
        req.requestId
      );
    }
  });

  app.all("/api/v1/admin/db/query", (req, res) => {
    res.setHeader("Allow", "POST");

    return sendError(
      res,
      405,
      "METHOD_NOT_ALLOWED",
      "Only POST is permitted",
      req.requestId
    );
  });


  // CREATE EVENT
  // POST /api/v1/events
  // --------------------------------------------------

  app.post("/api/v1/events", (req, res, next) => {
    try {
      const body = req.body;

      if (
        !body ||
        typeof body !== "object" ||
        Array.isArray(body)
      ) {
        return sendError(
          res,
          400,
          "INVALID_BODY",
          "A JSON object is required",
          req.requestId
        );
      }

      const allowedFields = [
        "requestId",
        "deviceId",
        "eventTime",
        "decision",
        "score",
        "reasons"
      ];

      if (
        Object.keys(body).some(
          key => !allowedFields.includes(key)
        )
      ) {
        return sendError(
          res,
          400,
          "INVALID_FIELDS",
          "Unsupported fields are not accepted",
          req.requestId
        );
      }

      const {
        requestId,
        deviceId,
        eventTime,
        decision,
        score,
        reasons = []
      } = body;

      if (!isValidId(requestId)) {
        return sendError(
          res,
          400,
          "INVALID_REQUEST_ID",
          "A valid requestId is required",
          req.requestId
        );
      }

      if (!isValidId(deviceId)) {
        return sendError(
          res,
          400,
          "INVALID_DEVICE_ID",
          "A valid deviceId is required",
          req.requestId
        );
      }

      if (!VALID_DECISIONS.includes(decision)) {
        return sendError(
          res,
          400,
          "INVALID_DECISION",
          "Invalid security decision",
          req.requestId
        );
      }

      if (
        !Number.isInteger(score) ||
        score < 0 ||
        score > 100
      ) {
        return sendError(
          res,
          400,
          "INVALID_SCORE",
          "Score must be between 0 and 100",
          req.requestId
        );
      }

      const parsedReasons = parseReasons(reasons);

      if (parsedReasons === null) {
        return sendError(
          res,
          400,
          "INVALID_REASONS",
          "Invalid reason codes",
          req.requestId
        );
      }

      let normalizedEventTime = new Date().toISOString();

      if (eventTime !== undefined) {
        if (typeof eventTime !== "string") {
          return sendError(
            res,
            400,
            "INVALID_EVENT_TIME",
            "eventTime must be a date string",
            req.requestId
          );
        }

        const parsedDate = new Date(eventTime);

        if (Number.isNaN(parsedDate.getTime())) {
          return sendError(
            res,
            400,
            "INVALID_EVENT_TIME",
            "Invalid event timestamp",
            req.requestId
          );
        }

        normalizedEventTime = parsedDate.toISOString();
      }

      const now = new Date().toISOString();

      const insertEvent = db.prepare(`
        INSERT INTO security_events (
          request_id,
          device_id,
          event_time,
          decision,
          score,
          reasons_json,
          status,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)
      `);

      const transaction = db.transaction(() => {
        upsertDevice(deviceId, now);

        insertEvent.run(
          requestId,
          deviceId,
          normalizedEventTime,
          decision,
          score,
          JSON.stringify(parsedReasons),
          now,
          now
        );
      });

      transaction();

      writeLog("info", "Security event stored", {
        requestId,
        deviceId,
        decision
      });

      return res.status(201).json({
        message: "Event stored successfully",
        requestId,
        status: "OPEN"
      });
    } catch (error) {
      if (
        error.code &&
        error.code.startsWith("SQLITE_CONSTRAINT")
      ) {
        return sendError(
          res,
          409,
          "RECORD_CONFLICT",
          "Record already exists or violates database constraints",
          req.requestId
        );
      }

      next(error);
    }
  });

  // --------------------------------------------------
  // READ EVENTS
  // GET /api/v1/events
  // --------------------------------------------------

  app.get("/api/v1/events", (req, res, next) => {
    try {
      const deviceId = req.query.deviceId;
      const status = req.query.status;

      if (
        deviceId !== undefined &&
        !isValidId(deviceId)
      ) {
        return sendError(
          res,
          400,
          "INVALID_DEVICE_ID",
          "Invalid deviceId",
          req.requestId
        );
      }

      if (
        status !== undefined &&
        !VALID_STATUSES.includes(status)
      ) {
        return sendError(
          res,
          400,
          "INVALID_STATUS",
          "Invalid status filter",
          req.requestId
        );
      }

      const limit = Number(req.query.limit ?? 50);
      const offset = Number(req.query.offset ?? 0);

      if (
        !Number.isSafeInteger(limit) ||
        limit < 1 ||
        limit > 100 ||
        !Number.isSafeInteger(offset) ||
        offset < 0
      ) {
        return sendError(
          res,
          400,
          "INVALID_PAGINATION",
          "Invalid limit or offset",
          req.requestId
        );
      }

      const conditions = [];
      const parameters = [];

      if (deviceId !== undefined) {
        conditions.push("device_id = ?");
        parameters.push(deviceId);
      }

      if (status !== undefined) {
        conditions.push("status = ?");
        parameters.push(status);
      }

      const whereClause = conditions.length
        ? `WHERE ${conditions.join(" AND ")}`
        : "";

      const rows = db.prepare(`
        SELECT
          request_id,
          device_id,
          event_time,
          decision,
          score,
          reasons_json,
          status,
          created_at,
          updated_at
        FROM security_events
        ${whereClause}
        ORDER BY event_time DESC
        LIMIT ? OFFSET ?
      `).all(
        ...parameters,
        limit,
        offset
      );

      return res.status(200).json({
        count: rows.length,
        limit,
        offset,
        events: rows.map(formatEvent)
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // READ ONE EVENT
  // GET /api/v1/events/:requestId
  // --------------------------------------------------

  app.get("/api/v1/events/:requestId", (req, res, next) => {
    try {
      const { requestId } = req.params;

      if (!isValidId(requestId)) {
        return sendError(
          res,
          400,
          "INVALID_REQUEST_ID",
          "Invalid requestId",
          req.requestId
        );
      }

      const row = db.prepare(`
        SELECT
          request_id,
          device_id,
          event_time,
          decision,
          score,
          reasons_json,
          status,
          created_at,
          updated_at
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!row) {
        return sendError(
          res,
          404,
          "EVENT_NOT_FOUND",
          "Event not found",
          req.requestId
        );
      }

      return res.status(200).json({
        event: formatEvent(row)
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // UPDATE EVENT STATUS
  // PATCH /api/v1/events/:requestId
  // --------------------------------------------------

  app.patch("/api/v1/events/:requestId", (req, res, next) => {
    try {
      const { requestId } = req.params;
      const body = req.body;

      if (!isValidId(requestId)) {
        return sendError(
          res,
          400,
          "INVALID_REQUEST_ID",
          "Invalid requestId",
          req.requestId
        );
      }

      if (
        !body ||
        typeof body !== "object" ||
        Array.isArray(body) ||
        Object.keys(body).length !== 1 ||
        !["REVIEWED", "RESOLVED"].includes(body.status)
      ) {
        return sendError(
          res,
          400,
          "INVALID_UPDATE",
          "Only REVIEWED or RESOLVED status updates are allowed",
          req.requestId
        );
      }

      const existing = db.prepare(`
        SELECT status
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!existing) {
        return sendError(
          res,
          404,
          "EVENT_NOT_FOUND",
          "Event not found",
          req.requestId
        );
      }

      if (existing.status === "ARCHIVED") {
        return sendError(
          res,
          409,
          "EVENT_ARCHIVED",
          "Archived events cannot be updated",
          req.requestId
        );
      }

      db.prepare(`
        UPDATE security_events
        SET status = ?, updated_at = ?
        WHERE request_id = ?
      `).run(
        body.status,
        new Date().toISOString(),
        requestId
      );

      writeLog("info", "Security event updated", {
        requestId,
        status: body.status
      });

      return res.status(200).json({
        message: "Event updated successfully",
        requestId,
        status: body.status
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // DELETE EVENT
  // DELETE /api/v1/events/:requestId
  // Soft delete: archives the record.
  // --------------------------------------------------

  app.delete("/api/v1/events/:requestId", (req, res, next) => {
    try {
      const { requestId } = req.params;

      if (!isValidId(requestId)) {
        return sendError(
          res,
          400,
          "INVALID_REQUEST_ID",
          "Invalid requestId",
          req.requestId
        );
      }

      const existing = db.prepare(`
        SELECT status
        FROM security_events
        WHERE request_id = ?
      `).get(requestId);

      if (!existing) {
        return sendError(
          res,
          404,
          "EVENT_NOT_FOUND",
          "Event not found",
          req.requestId
        );
      }

      if (existing.status !== "ARCHIVED") {
        db.prepare(`
          UPDATE security_events
          SET status = 'ARCHIVED', updated_at = ?
          WHERE request_id = ?
        `).run(
          new Date().toISOString(),
          requestId
        );
      }

      writeLog("info", "Security event archived", {
        requestId
      });

      return res.status(200).json({
        message: "Event archived successfully",
        requestId,
        status: "ARCHIVED"
      });
    } catch (error) {
      next(error);
    }
  });

  // --------------------------------------------------
  // UNSUPPORTED EVENT METHODS
  // --------------------------------------------------

  app.all("/api/v1/events", (req, res) => {
    res.setHeader("Allow", "GET, POST");

    return sendError(
      res,
      405,
      "METHOD_NOT_ALLOWED",
      "Method not allowed for this endpoint",
      req.requestId
    );
  });

  app.all("/api/v1/events/:requestId", (req, res) => {
    res.setHeader("Allow", "GET, PATCH, DELETE");

    return sendError(
      res,
      405,
      "METHOD_NOT_ALLOWED",
      "Method not allowed for this endpoint",
      req.requestId
    );
  });

  // --------------------------------------------------
  // UNKNOWN API ROUTES
  // --------------------------------------------------

  app.use((req, res) => {
    return sendError(
      res,
      404,
      "ROUTE_NOT_FOUND",
      "API endpoint not found",
      req.requestId
    );
  });

  // --------------------------------------------------
  // CENTRAL ERROR HANDLER
  // --------------------------------------------------

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }

    if (error.type === "entity.too.large") {
      return sendError(
        res,
        413,
        "PAYLOAD_TOO_LARGE",
        "Request body exceeds the allowed size",
        req.requestId
      );
    }

    if (
      error instanceof SyntaxError &&
      error.status === 400
    ) {
      return sendError(
        res,
        400,
        "INVALID_JSON",
        "Invalid JSON request body",
        req.requestId
      );
    }

    // Never expose internal messages or stack traces.
    res.locals.internalError = {
      errorName: error?.name || "Error",
      errorCode: error?.code || "INTERNAL_ERROR"
    };

    return sendError(
      res,
      500,
      "INTERNAL_SERVER_ERROR",
      "An internal server error occurred",
      req.requestId
    );
  });

  return app;
}

module.exports = createApp;
module.exports.createApp = createApp;

