import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
import { createServer } from "node:http";
import { Types } from "mongoose";
import { Server as SocketServer } from "socket.io";

import { connectDatabase, disconnectDatabase, isDatabaseReady } from "./config/database.js";
import { env } from "./config/env.js";
import { authRouter } from "./modules/identity/auth.routes.js";
import { attachRequestContext } from "./modules/identity/request-context.js";
import { Membership } from "./modules/identity/models/Membership.js";
import { authorizeSocketTenantSubscription } from "./modules/identity/socket-tenant.js";
import { verifyAccessToken } from "./modules/identity/token.js";
import { auditRouter } from "./modules/audit/audit.routes.js";
import { eventRouter } from "./modules/events/event.routes.js";
import { detectionRouter } from "./modules/detection/detection.routes.js";
import { DetectionFinding } from "./modules/detection/models/DetectionFinding.js";
import { dashboardRouter } from "./modules/dashboard/dashboard.routes.js";
import { AuditHead } from "./modules/audit/models/AuditHead.js";
import { AuditLog } from "./modules/audit/models/AuditLog.js";
import { SecurityEvent } from "./modules/events/models/SecurityEvent.js";

const app = express();
const httpServer = createServer(app);

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: env.WEB_ORIGIN, credentials: true }));
app.use(attachRequestContext);
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
app.use("/api/v1/audit", auditRouter);
app.use("/api/v1/events", eventRouter);
app.use("/api/v1/detections", detectionRouter);
app.use("/api/v1/dashboard", dashboardRouter);

app.use((error: unknown, request: express.Request, response: express.Response, _next: express.NextFunction) => {
  const bodyError = error as { type?: string } | null;
  if (bodyError?.type === "entity.too.large") {
    response.status(413).json({
      error: { code: "PAYLOAD_TOO_LARGE", message: "The request body exceeds the allowed size.", requestId: request.requestId },
    });
    return;
  }
  console.error("Unhandled API error:", error instanceof Error ? error.name : "UnknownError");
  response.status(500).json({
    error: { code: "INTERNAL_SERVER_ERROR", message: "An unexpected server error occurred.", requestId: request.requestId },
  });
});

const io = new SocketServer(httpServer, {
  cors: { origin: env.WEB_ORIGIN, credentials: true },
});

io.use(async (socket, next) => {
  const authHeader = socket.handshake.headers.authorization;
  const suppliedToken = typeof authHeader === "string"
    ? authHeader.replace(/^Bearer\s+/i, "")
    : typeof socket.handshake.auth?.token === "string"
      ? socket.handshake.auth.token.replace(/^Bearer\s+/i, "")
      : undefined;

  if (!suppliedToken) {
    next(new Error("UNAUTHENTICATED"));
    return;
  }

  try {
    const principal = await verifyAccessToken(suppliedToken);
    const membership = await Membership.findOne({
    userId: new Types.ObjectId(principal.userId),
    tenantId: new Types.ObjectId(principal.tenantId),
      status: "active",
    }).lean();

    if (!membership) {
      next(new Error("TENANT_ACCESS_DENIED"));
      return;
    }

    socket.data.principal = principal;
    next();
  } catch {
    next(new Error("UNAUTHENTICATED"));
  }
});

io.on("connection", (socket) => {
  socket.on("tenant:subscribe", (payload: unknown, callback?: (result: { ok: boolean; code?: string; tenantId?: string }) => void) => {
    const tenantId = typeof payload === "object" && payload !== null && "tenantId" in payload
      ? (payload as { tenantId?: unknown }).tenantId
      : undefined;
    const result = authorizeSocketTenantSubscription(socket.data.principal, tenantId);

    if (!result.ok) {
      callback?.({ ok: false, code: result.code ?? "UNAUTHORIZED_TENANT" });
      socket.emit("error", { code: result.code ?? "UNAUTHORIZED_TENANT" });
      socket.disconnect(true);
      return;
    }

    const tenantRoom = `tenant:${result.tenantId ?? ""}`;
    socket.join(tenantRoom);
    callback?.({ ok: true, tenantId: result.tenantId ?? "" });
  });

  socket.on("tenant:unsubscribe", (payload: unknown, callback?: (result: { ok: boolean; code?: string }) => void) => {
    const tenantId = typeof payload === "object" && payload !== null && "tenantId" in payload
      ? (payload as { tenantId?: unknown }).tenantId
      : undefined;
    const result = authorizeSocketTenantSubscription(socket.data.principal, tenantId);

    if (!result.ok) {
      callback?.({ ok: false, code: result.code ?? "UNAUTHORIZED_TENANT" });
      socket.emit("error", { code: result.code ?? "UNAUTHORIZED_TENANT" });
      socket.disconnect(true);
      return;
    }

    socket.leave(`tenant:${result.tenantId ?? ""}`);
    callback?.({ ok: true, code: "OK" });
  });
});

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
  const legacyAuditRecords = await AuditLog.collection.countDocuments({
    tenantId: { $exists: true },
    organizationId: { $exists: false },
  });
  if (legacyAuditRecords > 0) {
    const error = new Error("Legacy AuditLog records require an explicit migration before startup.");
    error.name = "LegacyAuditMigrationRequiredError";
    throw error;
  }
  await Promise.all([
    AuditHead.createIndexes(),
    AuditLog.createIndexes(),
    SecurityEvent.createIndexes(),
    DetectionFinding.createIndexes(),
  ]);
  httpServer.listen(env.API_PORT, env.API_HOST, () => {
    console.info(`SOC API listening on ${env.API_HOST}:${env.API_PORT}`);
  });
}

start().catch(async (error: unknown) => {
  console.error("API startup failed:", error instanceof Error ? error.name : "UnknownError");
  await disconnectDatabase();
  process.exit(1);
});
