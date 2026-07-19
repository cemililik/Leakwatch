/**
 * Unit tests for the platform-aware path helpers.
 *
 * Uses only the built-in Node test runner (no VS Code host) since `paths.ts`
 * has no `vscode` imports.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { resolveFindingPath, findingMatchesFile } from "../paths";

const root = path.resolve("/", "workspace", "proj");

test("resolveFindingPath joins a relative finding path against the scan root", () => {
  const resolved = resolveFindingPath(root, path.join("src", "app.ts"));
  assert.equal(resolved, path.join(root, "src", "app.ts"));
});

test("resolveFindingPath normalizes '.' and '..' segments", () => {
  const resolved = resolveFindingPath(root, path.join("src", "..", "lib", "x.ts"));
  assert.equal(resolved, path.join(root, "lib", "x.ts"));
});

test("resolveFindingPath returns an already-absolute finding path as-is (normalized)", () => {
  const abs = path.resolve("/", "etc", "config.yaml");
  assert.equal(resolveFindingPath(root, abs), path.normalize(abs));
});

test("findingMatchesFile matches the exact resolved file", () => {
  const target = path.join(root, "src", "config.js");
  assert.equal(findingMatchesFile(root, path.join("src", "config.js"), target), true);
});

test("findingMatchesFile rejects a suffix-only near-miss (config.js vs other_config.js)", () => {
  // The old suffix-match bug reported config.js findings on other_config.js.
  const target = path.join(root, "src", "other_config.js");
  assert.equal(findingMatchesFile(root, path.join("src", "config.js"), target), false);
});

test("findingMatchesFile rejects a same-basename file in a different directory", () => {
  const target = path.join(root, "a", "config.js");
  assert.equal(findingMatchesFile(root, path.join("b", "config.js"), target), false);
});
