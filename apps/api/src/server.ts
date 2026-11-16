import "dotenv/config";

import cors from "cors";
import express from "express";
import helmet from "helmet";
import { createServer } from "node:http";
import { Server as SocketServer } from "socket.io";
import { z } from "zod";

const environmentSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  WEB_ORIGIN: z.string().url().default("http://localhost:5173"),
});

const environment = environmentSchema.parse(process.env);
const app = express();
const httpServer = createServer(app);

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: environment.WEB_ORIGIN, credentials: true }));
app.use(express.json({ limit: "256kb" }));

app.get("/api/v1/health/live", (_request, response) => {
  response.status(200).json({
    data: { status: "ok", service: "soc-api" },
    meta: { timestamp: new Date().toISOString() },
  });
});

app.get("/api/v1/health/ready", (_request, response) => {
  // Dependency readiness checks will be added when MongoDB/Redis connections are wired.
  response.status(503).json({
    data: { status: "not_ready", dependencies: { database: "not_configured" } },
    meta: { timestamp: new Date().toISOString() },
  });
});

const io = new SocketServer(httpServer, {
  cors: { origin: environment.WEB_ORIGIN, credentials: true },
});

// Authentication and tenant-room authorization must be added before exposing
// any application event subscriptions. No tenant rooms are joined at this stage.
io.on("connection", (socket) => {
  socket.disconnect(true);
});

httpServer.listen(environment.API_PORT, () => {
  console.info(`SOC API listening on port ${environment.API_PORT}`);
});

const shutdown = (signal: string) => {
  console.info(`Received ${signal}; shutting down gracefully.`);
  io.close();
  httpServer.close(() => process.exit(0));
};

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
