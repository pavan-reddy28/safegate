const app = require("./app");
const env = require("./config/env");

const server = app.listen(
    env.port,
    env.host,
    () => {
        console.log("-----------------------------------");
        console.log("       SAFEGATE LOCAL API");
        console.log("-----------------------------------");
        console.log(`Server: http://${env.host}:${env.port}`);
        console.log(`Environment: ${env.nodeEnv}`);
        console.log("Protection engine: INITIALIZED");
        console.log("-----------------------------------");
    }
);

server.on("error", (error) => {
    console.error(`[SafeGate] Startup failed: ${error.code}`);
    process.exit(1);
});