import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import express from "express";
import mongoose, { Types } from "mongoose";

import { AuditService } from "./audit/audit-service.js";
import { AuditLog } from "./audit/models/AuditLog.js";
import { AuditHead } from "./audit/models/AuditHead.js";
import { auditRouter } from "./audit/audit.routes.js";
import { attachRequestContext } from "./identity/request-context.js";
import { Membership } from "./identity/models/Membership.js";
import { createAccessToken } from "./identity/token.js";
import { eventRouter } from "./events/event.routes.js";
import { SecurityEvent } from "./events/models/SecurityEvent.js";
import { validateLocalTestMongoUri } from "../testing/test-mongo-uri.js";

const mongoUri = validateLocalTestMongoUri(process.env.API_TEST_MONGODB_URI);

const validEvent = {
  eventId: "integration-event-1",
  timestamp: "2026-01-01T00:00:00.000Z",
  source: "integration-agent",
  sourceType: "endpoint",
  sourceIp: "192.0.2.1",
  destinationIp: "198.51.100.2",
  username: "test-user",
  hostname: "test-host",
  eventType: "authentication",
  category: "identity",
  severity: "high",
  action: "login",
  outcome: "failure",
  rawEvent: { message: "login failed", password: "must-be-redacted" },
  normalizedData: { status: "denied" },
  tags: ["integration"],
};

test("MongoDB audit and event API integration", { skip: !mongoUri }, async (t) => {
  const dbName = `soc_api_test_phase3_${process.pid}_${randomUUID().replace(/-/g, "")}`;
  await mongoose.connect(mongoUri!, { dbName, serverSelectionTimeoutMS: 5_000 });
  let server: ReturnType<typeof createServer> | undefined;
  try {

  const tenantA = new Types.ObjectId();
  const tenantB = new Types.ObjectId();
  const managerId = new Types.ObjectId();
  const viewerId = new Types.ObjectId();
  const tenantBManagerId = new Types.ObjectId();
  await Membership.create([
    { tenantId: tenantA, userId: managerId, roles: ["soc_manager"], status: "active" },
    { tenantId: tenantA, userId: viewerId, roles: ["viewer"], status: "active" },
    { tenantId: tenantB, userId: tenantBManagerId, roles: ["soc_manager"], status: "active" },
  ]);
  await Promise.all([AuditLog.init(), AuditHead.init(), SecurityEvent.init(), Membership.init()]);

  const app = express();
  app.use(attachRequestContext);
  app.use(express.json({ limit: "256kb" }));
  app.use("/api/v1/audit", auditRouter);
  app.use("/api/v1/events", eventRouter);
  app.use((error: unknown, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
    response.status(500).json({ error: error instanceof Error ? error.name : "UnknownError" });
  });
  const testServer = createServer(app);
  server = testServer;
  await new Promise<void>((resolve) => testServer.listen(0, "127.0.0.1", resolve));
  const address = testServer.address();
  assert.ok(address && typeof address !== "string");
  const baseUrl = `http://127.0.0.1:${address.port}/api/v1`;

  const managerToken = await createAccessToken({
    userId: managerId.toHexString(),
    tenantId: tenantA.toHexString(),
    roles: ["soc_manager"],
  });
  const viewerToken = await createAccessToken({
    userId: viewerId.toHexString(),
    tenantId: tenantA.toHexString(),
    roles: ["viewer"],
  });
  const tenantBToken = await createAccessToken({
    userId: tenantBManagerId.toHexString(),
    tenantId: tenantB.toHexString(),
    roles: ["soc_manager"],
  });

    await t.test("audit creation serializes concurrent tenant writes and verifies integrity", async () => {
      await Promise.all(Array.from({ length: 5 }, (_, index) => AuditService.append({
        organizationId: tenantA.toHexString(),
        actorUserId: managerId.toHexString(),
        actorRole: "soc_manager",
        action: "test.concurrent",
        resourceType: "test",
        requestId: `integration-${index}`,
        outcome: "success",
        severity: "info",
        metadata: {
          index,
          accessToken: "redact-this",
          organizationId: tenantB.toHexString(),
          action: "spoofed.action",
        },
      })));

      const entries = await AuditLog.find({ organizationId: tenantA }).sort({ chainIndex: 1 }).lean();
      assert.equal(entries.length, 5);
      assert.deepEqual(entries.map((entry) => entry.chainIndex), [1, 2, 3, 4, 5]);
      assert.equal(entries.every((entry) => entry.action === "test.concurrent"), true);
      assert.equal(entries.every((entry) => entry.organizationId.equals(tenantA)), true);
      assert.equal(entries.every((entry) => (entry.metadata as Record<string, unknown>).accessToken === "[REDACTED]"), true);
      assert.deepEqual(await AuditService.verify(tenantA.toHexString()), { valid: true, checkedEntries: 5 });
    });

    await AuditService.append({
      organizationId: tenantB.toHexString(),
      action: "test.tenant_b",
      resourceType: "test",
      requestId: "tenant-b",
      outcome: "success",
      severity: "info",
    });

    await t.test("audit API scopes tenant reads and rejects unauthorized access", async () => {
      const listResponse = await fetch(`${baseUrl}/audit?limit=100`, {
        headers: { authorization: `Bearer ${managerToken}` },
      });
      assert.equal(listResponse.status, 200);
      const list = await listResponse.json() as { data: Array<{ organizationId: string; id: string }> };
      assert.equal(list.data.length, 5);
      assert.equal(list.data.every((entry) => entry.organizationId === tenantA.toHexString()), true);

      const crossTenant = await fetch(`${baseUrl}/audit/${(await AuditLog.findOne({ organizationId: tenantB }))!.id}`, {
        headers: { authorization: `Bearer ${managerToken}` },
      });
      assert.equal(crossTenant.status, 404);

      const denied = await fetch(`${baseUrl}/audit`, {
        headers: { authorization: `Bearer ${viewerToken}` },
      });
      assert.equal(denied.status, 403);

      const startDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const endDate = new Date(Date.now() + 1_000).toISOString();
      const exported = await fetch(
        `${baseUrl}/audit/export?startDate=${encodeURIComponent(startDate)}&endDate=${encodeURIComponent(endDate)}`,
        { headers: { authorization: `Bearer ${managerToken}` } },
      );
      assert.equal(exported.status, 200);
      const exportBody = await exported.json() as { data: Array<{ organizationId: string }> };
      assert.equal(exportBody.data.length > 0, true);
      assert.equal(exportBody.data.every((entry) => entry.organizationId === tenantA.toHexString()), true);
    });

    await t.test("every audit/event route authenticates and enforces its permission", async () => {
      const eventId = new Types.ObjectId().toHexString();
      const requests: Array<{ path: string; method: string; body?: unknown }> = [
        { path: "/audit", method: "GET" },
        { path: `/audit/${eventId}`, method: "GET" },
        { path: "/audit/verify", method: "GET" },
        { path: "/audit/export?startDate=2026-01-01T00:00:00.000Z&endDate=2026-01-02T00:00:00.000Z", method: "GET" },
        { path: "/events/ingest", method: "POST", body: validEvent },
        { path: "/events/bulk-ingest", method: "POST", body: { events: [validEvent] } },
        { path: "/events?startDate=2026-01-01T00:00:00.000Z&endDate=2026-01-02T00:00:00.000Z", method: "GET" },
        { path: `/events/${eventId}`, method: "GET" },
      ];

      for (const request of requests) {
        const init: RequestInit = { method: request.method };
        if (request.body !== undefined) {
          init.headers = { "content-type": "application/json" };
          init.body = JSON.stringify(request.body);
        }
        const response = await fetch(`${baseUrl}${request.path}`, init);
        assert.equal(response.status, 401, `${request.method} ${request.path} must require authentication`);
      }

      for (const path of ["/events/ingest", "/events/bulk-ingest"]) {
        const body = path.endsWith("bulk-ingest") ? { events: [validEvent] } : validEvent;
        const response = await fetch(`${baseUrl}${path}`, {
          method: "POST",
          headers: { authorization: `Bearer ${viewerToken}`, "content-type": "application/json" },
          body: JSON.stringify(body),
        });
        assert.equal(response.status, 403, `${path} must require events:ingest`);
      }

      const viewerEventRead = await fetch(
        `${baseUrl}/events?startDate=2026-01-01T00:00:00.000Z&endDate=2026-01-02T00:00:00.000Z`,
        { headers: { authorization: `Bearer ${viewerToken}` } },
      );
      assert.equal(viewerEventRead.status, 200);

      const clientSelectedOrganization = await fetch(`${baseUrl}/events/ingest`, {
        method: "POST",
        headers: { authorization: `Bearer ${managerToken}`, "content-type": "application/json" },
        body: JSON.stringify({ ...validEvent, organizationId: tenantB.toHexString() }),
      });
      assert.equal(clientSelectedOrganization.status, 403);

      const querySelectedOrganization = await fetch(`${baseUrl}/audit?organizationId=${tenantB.toHexString()}`, {
        headers: { authorization: `Bearer ${managerToken}` },
      });
      assert.equal(querySelectedOrganization.status, 403);

      const chainVerification = await fetch(`${baseUrl}/audit/verify`, {
        headers: { authorization: `Bearer ${managerToken}` },
      });
      assert.equal(chainVerification.status, 200);
    });

    await t.test("audit verification detects persisted tampering", async () => {
      const record = await AuditLog.findOne({ organizationId: tenantA }).sort({ chainIndex: 1 });
      assert.ok(record);
      await AuditLog.updateOne({ _id: record._id }, { $set: { action: "tampered.action" } });
      assert.equal((await AuditService.verify(tenantA.toHexString())).valid, false);
    });

    await t.test("event ingestion is idempotent, redacted, bounded, and tenant-scoped", async () => {
      const first = await fetch(`${baseUrl}/events/ingest`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${managerToken}`,
          "content-type": "application/json",
          "idempotency-key": "integration-idempotency-001",
        },
        body: JSON.stringify(validEvent),
      });
      assert.equal(first.status, 201);
      const created = await first.json() as { data: { id: string; rawEvent: { password: string } } };
      assert.equal(created.data.rawEvent.password, "[REDACTED]");

      const retry = await fetch(`${baseUrl}/events/ingest`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${managerToken}`,
          "content-type": "application/json",
          "idempotency-key": "integration-idempotency-001",
        },
        body: JSON.stringify({ ...validEvent, eventId: "different-event-id" }),
      });
      assert.equal(retry.status, 200);
      const retried = await retry.json() as { data: { id: string }; meta: { duplicate: boolean } };
      assert.equal(retried.meta.duplicate, true);
      assert.equal(retried.data.id, created.data.id);

      const duplicateBySource = await fetch(`${baseUrl}/events/ingest`, {
        method: "POST",
        headers: { authorization: `Bearer ${managerToken}`, "content-type": "application/json" },
        body: JSON.stringify(validEvent),
      });
      assert.equal(duplicateBySource.status, 200);

      const crossTenant = await fetch(`${baseUrl}/events/${created.data.id}`, {
        headers: { authorization: `Bearer ${tenantBToken}` },
      });
      assert.equal(crossTenant.status, 404);
    });

    await t.test("event API handles malformed payloads and bulk limits", async () => {
      const malformed = await fetch(`${baseUrl}/events/ingest`, {
        method: "POST",
        headers: { authorization: `Bearer ${managerToken}`, "content-type": "application/json" },
        body: JSON.stringify({ ...validEvent, severity: "urgent" }),
      });
      assert.equal(malformed.status, 400);

      const tooMany = await fetch(`${baseUrl}/events/bulk-ingest`, {
        method: "POST",
        headers: { authorization: `Bearer ${managerToken}`, "content-type": "application/json" },
        body: JSON.stringify({ events: Array.from({ length: 101 }, (_, index) => ({ ...validEvent, eventId: `bulk-${index}` })) }),
      });
      assert.equal(tooMany.status, 400);

      const partiallyMalformed = await fetch(`${baseUrl}/events/bulk-ingest`, {
        method: "POST",
        headers: { authorization: `Bearer ${managerToken}`, "content-type": "application/json" },
        body: JSON.stringify({ events: [{ ...validEvent, eventId: "bulk-valid-event" }, { ...validEvent, severity: "urgent" }] }),
      });
      assert.equal(partiallyMalformed.status, 207);
      const result = await partiallyMalformed.json() as { meta: { createdCount: number; rejectedCount: number } };
      assert.equal(result.meta.createdCount, 1);
      assert.equal(result.meta.rejectedCount, 1);
      assert.equal(await SecurityEvent.countDocuments({ organizationId: tenantA }), 2);
    });
  } finally {
    const runningServer = server;
    if (runningServer?.listening) {
      await new Promise<void>((resolve, reject) => runningServer.close((error) => error ? reject(error) : resolve()));
    }
    if (mongoose.connection.readyState === 1) {
      await mongoose.connection.dropDatabase();
    }
    await mongoose.disconnect();
  }
});
