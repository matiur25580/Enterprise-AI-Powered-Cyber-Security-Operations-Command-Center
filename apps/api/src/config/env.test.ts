import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

const accessSecret = "a".repeat(32);
const refreshSecret = "b".repeat(32);
const shortSecret = "s".repeat(31);

function loadEnvironment(overrides: Record<string, string | undefined>, expression = "await import('./src/config/env.ts')") {
  const environment = { ...process.env, ...overrides };
  delete environment.JWT_ACCESS_SECRET;
  delete environment.JWT_REFRESH_SECRET;
  environment.DOTENV_CONFIG_PATH = "__env_test_no_dotenv__";
  Object.assign(environment, overrides);

  return spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", expression],
    {
      cwd: process.cwd(),
      encoding: "utf8",
      env: environment,
    },
  );
}

test("development and test environments use distinct development-only fallback secrets", () => {
  for (const nodeEnv of ["development", "test"]) {
    const result = loadEnvironment(
      { NODE_ENV: nodeEnv },
      "const { env } = await import('./src/config/env.ts'); " +
        "if (!env.JWT_ACCESS_SECRET.startsWith('development-only-') || " +
        "!env.JWT_REFRESH_SECRET.startsWith('development-only-') || " +
        "env.JWT_ACCESS_SECRET === env.JWT_REFRESH_SECRET) process.exit(1);",
    );

    assert.equal(result.status, 0, result.stderr);
  }
});

test("production requires both JWT secrets", () => {
  for (const missingSecret of ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET"]) {
    const result = loadEnvironment({
      NODE_ENV: "production",
      [missingSecret]: undefined,
      [missingSecret === "JWT_ACCESS_SECRET" ? "JWT_REFRESH_SECRET" : "JWT_ACCESS_SECRET"]: refreshSecret,
    });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, new RegExp(`${missingSecret} is required in production`));
  }
});

test("production rejects empty or shorter-than-32-character secrets without exposing them", () => {
  for (const name of ["JWT_ACCESS_SECRET", "JWT_REFRESH_SECRET"] as const) {
    for (const secret of ["", shortSecret]) {
      const result = loadEnvironment({
        NODE_ENV: "production",
        JWT_ACCESS_SECRET: name === "JWT_ACCESS_SECRET" ? secret : accessSecret,
        JWT_REFRESH_SECRET: name === "JWT_REFRESH_SECRET" ? secret : refreshSecret,
      });

      assert.notEqual(result.status, 0);
      assert.match(result.stderr, new RegExp(name));
      assert.doesNotMatch(result.stderr, new RegExp(secret || "unused-secret"));
    }
  }
});

test("production accepts two distinct secrets of at least 32 characters", () => {
  const result = loadEnvironment({
    NODE_ENV: "production",
    JWT_ACCESS_SECRET: accessSecret,
    JWT_REFRESH_SECRET: refreshSecret,
  });

  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stderr, new RegExp(accessSecret));
  assert.doesNotMatch(result.stderr, new RegExp(refreshSecret));
});

test("identical access and refresh secrets are rejected", () => {
  const result = loadEnvironment({
    NODE_ENV: "test",
    JWT_ACCESS_SECRET: accessSecret,
    JWT_REFRESH_SECRET: accessSecret,
  });

  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Access and refresh token secrets must be different/);
  assert.doesNotMatch(result.stderr, new RegExp(accessSecret));
});
