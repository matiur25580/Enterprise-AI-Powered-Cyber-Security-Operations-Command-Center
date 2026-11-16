import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import express from "express";
import mongoose, { Types } from "mongoose";

import { validateLocalTestMongoUri } from "../../testing/test-mongo-uri.js";
import { AuditHead } from "../audit/models/AuditHead.js";
import { AuditLog } from "../audit/models/AuditLog.js";
import { attachRequestContext } from "../identity/request-context.js";
import { Membership } from "../identity/models/Membership.js";
import { createAccessToken } from "../identity/token.js";
import { incidentRouter } from "./incident.routes.js";
import { Incident } from "./models/Incident.js";

const mongoUri = validateLocalTestMongoUri(process.env.API_TEST_MONGODB_URI);

test("incident API enforces tenant isolation and audited workflow transitions", { skip: !mongoUri }, async () => {
  const dbName = `soc_incident_test_${process.pid}_${randomUUID().replace(/-/g, "")}`;
  await mongoose.connect(mongoUri!, { dbName, serverSelectionTimeoutMS: 5_000 });
  let server: ReturnType<typeof createServer> | undefined;
  try {
    const tenantA = new Types.ObjectId();
    const tenantB = new Types.ObjectId();
    const managerA = new Types.ObjectId();
    const managerB = new Types.ObjectId();
    await Membership.create([
      { tenantId: tenantA, userId: managerA, roles: ["soc_manager"], status: "active" },
      { tenantId: tenantB, userId: managerB, roles: ["soc_manager"], status: "active" },
    ]);
    await Promise.all([Membership.init(), Incident.init(), AuditLog.init(), AuditHead.init()]);

    const app = express();
    app.use(attachRequestContext);
    app.use(express.json({ limit: "256kb" }));
    app.use("/api/v1/incidents", incidentRouter);
    const httpServer = createServer(app);
    server = httpServer;
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    const address = httpServer.address();
    assert.ok(address && typeof address !== "string");
    const baseUrl = `http://127.0.0.1:${address.port}/api/v1/incidents`;
    const tokenA = await createAccessToken({ userId: managerA.toHexString(), tenantId: tenantA.toHexString(), roles: ["soc_manager"] });
    const tokenB = await createAccessToken({ userId: managerB.toHexString(), tenantId: tenantB.toHexString(), roles: ["soc_manager"] });

    const created = await fetch(baseUrl, {
      method: "POST",
      headers: { authorization: `Bearer ${tokenA}`, "content-type": "application/json" },
      body: JSON.stringify({ title: "Suspicious login campaign", description: "Repeated failed authentication attempts from a single source.", severity: "high" }),
    });
    assert.equal(created.status, 201);
    const createdBody = await created.json() as { data: { id: string; status: string } };
    assert.equal(createdBody.data.status, "open");

    const hidden = await fetch(baseUrl, { headers: { authorization: `Bearer ${tokenB}` } });
    assert.equal(hidden.status, 200);
    const hiddenBody = await hidden.json() as { data: unknown[] };
    assert.equal(hiddenBody.data.length, 0);

    const crossTenantUpdate = await fetch(`${baseUrl}/${createdBody.data.id}/status`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${tokenB}`, "content-type": "application/json" },
      body: JSON.stringify({ status: "investigating" }),
    });
    assert.equal(crossTenantUpdate.status, 404);

    const invalidTransition = await fetch(`${baseUrl}/${createdBody.data.id}/status`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${tokenA}`, "content-type": "application/json" },
      body: JSON.stringify({ status: "resolved" }),
    });
    assert.equal(invalidTransition.status, 409);

    const transition = await fetch(`${baseUrl}/${createdBody.data.id}/status`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${tokenA}`, "content-type": "application/json" },
      body: JSON.stringify({ status: "investigating", detail: "Analyst started triage." }),
    });
    assert.equal(transition.status, 200);

    const note = await fetch(`${baseUrl}/${createdBody.data.id}/notes`, {
      method: "POST",
      headers: { authorization: `Bearer ${tokenA}`, "content-type": "application/json" },
      body: JSON.stringify({ body: "Source IP and account activity are under investigation." }),
    });
    assert.equal(note.status, 201);

    const stored = await Incident.findById(createdBody.data.id).lean();
    assert.equal(stored?.status, "investigating");
    assert.equal(stored?.notes.length, 1);
    assert.equal(stored?.timeline.length, 3);
    assert.equal(await AuditLog.countDocuments({ organizationId: tenantA }), 3);
  } finally {
    if (server?.listening) {
      await new Promise<void>((resolve, reject) => server!.close((error) => error ? reject(error) : resolve()));
    }
    if (mongoose.connection.readyState === 1) await mongoose.connection.dropDatabase();
    await mongoose.disconnect();
  }
});
