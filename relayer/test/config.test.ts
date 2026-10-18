import { test } from "node:test";
// SPDX-License-Identifier: MIT
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";
import { REQUIRED_CONFIG_VARS, validConfigEnv } from "./fixtures.js";

test("loadConfig succeeds with valid required fields and applies defaults", () => {
  const config = loadConfig(validConfigEnv());
  assert.ok(config);
});

test("loadConfig requires the complete set of required variables", () => {
  const env = validConfigEnv();
  for (const key of REQUIRED_CONFIG_VARS) {
    assert.ok(
      key in env,
      `fixture is missing required variable ${key}; update relayer/test/fixtures.ts`,
    );
  }
  assert.deepEqual(
    Object.keys(env).sort(),
    [...REQUIRED_CONFIG_VARS].sort(),
    "fixture must define exactly the required variables; update relayer/test/fixtures.ts",
  );
});

test("loadConfig rejects a missing required variable", () => {
  const { PERIHELION_EVM_RPC_URL: _omit, ...rest } = validConfigEnv();
  assert.throws(() => loadConfig(rest), /PERIHELION_EVM_RPC_URL/);
});