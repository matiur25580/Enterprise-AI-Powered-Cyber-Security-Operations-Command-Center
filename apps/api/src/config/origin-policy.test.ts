import assert from "node:assert/strict";
import test from "node:test";

import { isAllowedOrigin } from "./origin-policy.js";

test("allows the configured browser origin", () => {
  assert.equal(isAllowedOrigin("https://soc.example.com", "https://soc.example.com"), true);
});

test("rejects untrusted, null and empty browser origins", () => {
  assert.equal(isAllowedOrigin("https://attacker.example", "https://soc.example.com"), false);
  assert.equal(isAllowedOrigin("null", "https://soc.example.com"), false);
  assert.equal(isAllowedOrigin("", "https://soc.example.com"), false);
});

test("allows non-browser clients that omit the Origin header", () => {
  assert.equal(isAllowedOrigin(undefined, "https://soc.example.com"), true);
});
