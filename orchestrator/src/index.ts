import Fastify from "fastify";
import fastifyWebsocket from "@fastify/websocket";
import fastifyCors from "@fastify/cors";
import { CONFIG } from "./config.js";
import { ScopeValidator } from "./scope/scope-validator.js";
import { ScopeConfigSchema } from "./scope/scope-config.js";
import { AuditLogger } from "./scope/audit-logger.js";
import { JobManager } from "./tools/job-manager.js";
import { WsHandler } from "./api/ws-handler.js";

const logger =
  process.env.NODE_ENV === "production"
    ? { level: "info" }
    : {
        transport: {
          target: "pino-pretty",
          options: { translateTime: "HH:MM:ss Z", ignore: "pid,hostname" },
        },
      };

const server = Fastify({ logger });

async function start() {
  await server.register(fastifyCors, { origin: true });
  await server.register(fastifyWebsocket);

  // --- Initialize scope configuration ---
  const scopeConfig = ScopeConfigSchema.parse({
    allowedCidrs: CONFIG.DEFAULT_SCOPE,
    restrictions: {
      allowActiveScanning: true,
      allowExploitation: false,
      allowBruteForce: false,
    },
  });

  const scopeValidator = new ScopeValidator(scopeConfig);
  const auditLogger = new AuditLogger(CONFIG.AUDIT_LOG_PATH);
  await auditLogger.init();

  const jobManager = new JobManager(scopeValidator, auditLogger);

  const wsHandler = new WsHandler({
    jobManager,
    scopeValidator,
    scopeConfig,
    logger: server.log,
  });

  // --- Routes ---

  server.get("/health", async () => ({
    status: "ok",
    service: "cyberdeck-orchestrator",
    scope: scopeConfig.allowedCidrs,
    activeJobs: jobManager.listJobs().filter((j) => j.status === "running").length,
    queuedJobs: jobManager.getQueueLength(),
  }));

  server.register(async function (fastify) {
    fastify.get("/ws", { websocket: true }, (socket) => {
      wsHandler.handleConnection(socket);
    });
  });

  // --- Audit: log server start ---
  await auditLogger.log({
    sessionId: "system",
    action: "server_start",
    details: `Orchestrator started on port ${CONFIG.PORT}, scope: ${scopeConfig.allowedCidrs.join(", ")}`,
  });

  await server.listen({ port: CONFIG.PORT, host: CONFIG.HOST });
  server.log.info(`Cyberdeck orchestrator listening on port ${CONFIG.PORT}`);
  server.log.info(`Scope: ${scopeConfig.allowedCidrs.join(", ")}`);
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
