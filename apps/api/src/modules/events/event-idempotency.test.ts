import assert from "node:assert/strict";
import test from "node:test";

import { hashEventPayload } from "./event-idempotency.js";

test("event payload hash is stable regardless of object key order", () => {
  assert.equal(
    hashEventPayload({ source: "agent", details: { host: "one", result: "denied" } }),
    hashEventPayload({ details: { result: "denied", host: "one" }, source: "agent" }),
  );
});

test("event payload hash changes when event content changes", () => {
  assert.notEqual(
    hashEventPayload({ eventId: "evt-1", severity: "low" }),
    hashEventPayload({ eventId: "evt-1", severity: "critical" }),
  );
  assert.notEqual(hashEventPayload({ tags: ["a", "b"] }), hashEventPayload({ tags: ["b", "a"] }));
});
