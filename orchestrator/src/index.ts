import Fastify from "fastify";
import fastifyWebsocket from "@fastify/websocket";
import fastifyCors from "@fastify/cors";
import { CONFIG } from "./config.js";

const server = Fastify({
  logger: {
    transport: {
      target: "pino-pretty",
      options: { translateTime: "HH:MM:ss Z", ignore: "pid,hostname" },
    },
  },
});

async function start() {
  await server.register(fastifyCors, { origin: true });
  await server.register(fastifyWebsocket);

  server.get("/health", async () => ({
    status: "ok",
    service: "cyberdeck-orchestrator",
  }));

  server.register(async function (fastify) {
    fastify.get("/ws", { websocket: true }, (socket, req) => {
      server.log.info("WebSocket client connected");
      socket.on("message", (msg: Buffer) => {
        // Message routing will be added in Task 2.5
        server.log.info(`Received: ${msg.toString().slice(0, 100)}`);
      });
      socket.on("close", () => {
        server.log.info("WebSocket client disconnected");
      });
    });
  });

  await server.listen({ port: CONFIG.PORT, host: CONFIG.HOST });
  server.log.info(`Cyberdeck orchestrator listening on port ${CONFIG.PORT}`);
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
