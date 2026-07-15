/**
 * Unit tests for the leakwatch JSON parsing helpers.
 *
 * Uses only the built-in Node test runner (no VS Code host) since `parse.ts`
 * has no `vscode` imports. All secret material here is SYNTHETIC.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseFindings,
  normalizeSeverity,
  normalizeVerificationStatus,
} from "../parse";

test("parseFindings returns [] for empty, whitespace, or null output", () => {
  assert.deepEqual(parseFindings(""), []);
  assert.deepEqual(parseFindings("   \n "), []);
  assert.deepEqual(parseFindings("null"), []);
});

test("parseFindings returns [] for malformed JSON", () => {
  assert.deepEqual(parseFindings("{not json"), []);
});

test("parseFindings returns [] when the top level is not an array", () => {
  assert.deepEqual(parseFindings('{"id":"x"}'), []);
});

test("parseFindings maps a well-formed finding into a typed Finding", () => {
  const json = JSON.stringify([
    {
      id: "abc123",
      detector_id: "aws-access-key",
      description: "AWS Access Key",
      severity: "HIGH",
      redacted: "AKIA****************",
      verification_status: "verified_active",
      source_metadata: {
        file_path: "config/app.yaml",
        line_number: 12,
        source_type: "filesystem",
      },
      extra_data: { region: "us-east-1", dropped: 5 },
    },
  ]);

  const findings = parseFindings(json);
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.id, "abc123");
  assert.equal(f.detectorId, "aws-access-key");
  assert.equal(f.description, "AWS Access Key");
  assert.equal(f.severity, "high");
  assert.equal(f.redacted, "AKIA****************");
  assert.equal(f.verificationStatus, "verified_active");
  assert.equal(f.sourceMetadata.filePath, "config/app.yaml");
  assert.equal(f.sourceMetadata.lineNumber, 12);
  assert.equal(f.sourceMetadata.sourceType, "filesystem");
  // Non-string map values are dropped.
  assert.deepEqual(f.extraData, { region: "us-east-1" });
});

test("parseFindings tolerates missing fields with safe defaults", () => {
  const findings = parseFindings("[{}]");
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.id, "");
  assert.equal(f.detectorId, "");
  assert.equal(f.severity, "medium");
  assert.equal(f.verificationStatus, "unverified");
  assert.equal(f.sourceMetadata.filePath, "");
  assert.equal(f.sourceMetadata.lineNumber, 0);
  assert.equal(f.extraData, undefined);
});

test("parseFindings skips non-object array entries", () => {
  const findings = parseFindings('[1, "x", null, {"id":"keep"}]');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "keep");
});

test("parseFindings ignores a non-finite line number", () => {
  const json = '[{"source_metadata":{"line_number":"nope"}}]';
  assert.equal(parseFindings(json)[0].sourceMetadata.lineNumber, 0);
});

test("normalizeSeverity accepts known values case-insensitively", () => {
  assert.equal(normalizeSeverity("LOW"), "low");
  assert.equal(normalizeSeverity("Critical"), "critical");
  assert.equal(normalizeSeverity("high"), "high");
});

test("normalizeSeverity defaults unknown values to medium", () => {
  assert.equal(normalizeSeverity("bogus"), "medium");
  assert.equal(normalizeSeverity(undefined), "medium");
  assert.equal(normalizeSeverity(42), "medium");
});

test("normalizeVerificationStatus defaults unknown values to unverified", () => {
  assert.equal(normalizeVerificationStatus("verified_active"), "verified_active");
  assert.equal(normalizeVerificationStatus("verify_error"), "verify_error");
  assert.equal(normalizeVerificationStatus("bogus"), "unverified");
  assert.equal(normalizeVerificationStatus(undefined), "unverified");
});
