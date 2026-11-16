import assert from "node:assert/strict";
import test from "node:test";

import { canTransitionIncident } from "./incident-workflow.js";

test("incident workflow allows documented forward transitions", () => {
  assert.equal(canTransitionIncident("open", "acknowledged"), true);
  assert.equal(canTransitionIncident("acknowledged", "investigating"), true);
  assert.equal(canTransitionIncident("investigating", "contained"), true);
  assert.equal(canTransitionIncident("contained", "resolved"), true);
  assert.equal(canTransitionIncident("resolved", "reopened"), true);
});

test("incident workflow rejects invalid and skipped transitions", () => {
  assert.equal(canTransitionIncident("open", "resolved"), false);
  assert.equal(canTransitionIncident("resolved", "contained"), false);
  assert.equal(canTransitionIncident("acknowledged", "open"), false);
});
