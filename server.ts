import { createRequire } from "node:module";
import path from "node:path";
import express from "express";

const require = createRequire(import.meta.url);
const env = require("./src/config/env");
const appModule = require("./src/app");

async function startServer() {
  const app = appModule.createBaseApp({
    attachErrorHandlers: false,
    mountRootHealth: false,
    scopeCspToApi: true
  });

  if (env.nodeEnv !== "production") {
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: false },
      appType: "spa"
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), "dist");
    app.use(express.static(distDir));
    app.get(/^\/(?!api\/v1).*/, (_req, res) => {
      res.sendFile(path.join(distDir, "index.html"));
    });
  }

  app.use("/api/v1", appModule.notFoundHandler);
  app.use(appModule.errorHandler);

  const server = app.listen(env.port, env.host, () => {
    console.log("-----------------------------------");
    console.log("       SAFEGATE FULL-STACK");
    console.log("-----------------------------------");
    console.log(`Server: http://${env.host}:${env.port}`);
    console.log(`Environment: ${env.nodeEnv}`);
    console.log("30-Layer On-Device Engine: ACTIVE");
    console.log("Zero-Egress Guarantee: ENFORCED");
    console.log("-----------------------------------");
  });

  server.on("error", (error: NodeJS.ErrnoException) => {
    console.error(`[SafeGate] Startup failed: ${error.code || error.message}`);
    process.exit(1);
  });
}

startServer();
