import assert from "node:assert/strict";
import test from "node:test";

import { validateLocalTestMongoUri } from "./test-mongo-uri.js";

test("isolated MongoDB integration URIs require loopback and a test database name", () => {
  assert.equal(
    validateLocalTestMongoUri("mongodb://127.0.0.1:27018/soc_api_test"),
    "mongodb://127.0.0.1:27018/soc_api_test",
  );
  assert.equal(
    validateLocalTestMongoUri("mongodb://localhost:27018/soc_api_test_run"),
    "mongodb://localhost:27018/soc_api_test_run",
  );
  assert.equal(validateLocalTestMongoUri(undefined), undefined);

  assert.throws(
    () => validateLocalTestMongoUri("mongodb://db.example.com/soc_api_test"),
    /loopback MongoDB URI/,
  );
  assert.throws(
    () => validateLocalTestMongoUri("mongodb://127.0.0.1:27017/soc_command_center"),
    /loopback MongoDB URI/,
  );
});
