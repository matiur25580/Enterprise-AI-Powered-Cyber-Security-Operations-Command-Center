import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import { createServer } from "node:http";
import { Server as SocketServer } from "socket.io";

import { connectDatabase, disconnectDatabase, isDatabaseReady } from "./config/database.js";
import { env } from "./config/env.js";
import { authRouter } from "./modules/identity/auth.routes.js";

const app = express();
const httpServer = createServer(app);

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: env.WEB_ORIGIN, credentials: true }));
app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());

app.get("/api/v1/health/live", (_request, response) => {
  response.status(200).json({
    data: { status: "ok", service: "soc-api" },
    meta: { timestamp: new Date().toISOString() },
  });
});

app.get("/api/v1/health/ready", (_request, response) => {
  const ready = isDatabaseReady();
  response.status(ready ? 200 : 503).json({
    data: {
      status: ready ? "ready" : "not_ready",
      dependencies: { database: ready ? "connected" : "disconnected" },
    },
    meta: { timestamp: new Date().toISOString() },
  });
});

app.use("/api/v1/auth", authRouter);

const io = new SocketServer(httpServer, {
  cors: { origin: env.WEB_ORIGIN, credentials: true },
});

// Until tenant-room authorization is implemented, reject realtime sessions.
io.on("connection", (socket) => socket.disconnect(true));

let shuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.info(`Received ${signal}; shutting down gracefully.`);
  io.close();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
  await disconnectDatabase();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));

async function start(): Promise<void> {
  await connectDatabase();
  httpServer.listen(env.API_PORT, env.API_HOST, () => {
    console.info(`SOC API listening on ${env.API_HOST}:${env.API_PORT}`);
  });
}

start().catch(async (error: unknown) => {
  console.error("API startup failed:", error instanceof Error ? error.message : "Unknown error");
  await disconnectDatabase();
  process.exit(1);
});
