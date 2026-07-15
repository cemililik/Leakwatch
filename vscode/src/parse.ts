/**
 * Parsing helpers — convert leakwatch JSON output into typed Finding objects.
 *
 * This module deliberately contains no `vscode` imports so its logic can be
 * unit-tested with the plain Node test runner (no VS Code host required).
 */

import { Finding } from "./types";

/** Narrows an unknown value to a plain object with string keys. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Reads a string field from an unknown record, falling back to a default. */
function readString(
  record: Record<string, unknown>,
  key: string,
  fallback = ""
): string {
  const value = record[key];
  return typeof value === "string" ? value : fallback;
}

/** Reads a numeric field from an unknown record, falling back to a default. */
function readNumber(
  record: Record<string, unknown>,
  key: string,
  fallback = 0
): number {
  const value = record[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

/** Reads a string-valued map, returning undefined when absent or malformed. */
function readStringMap(
  record: Record<string, unknown>,
  key: string
): Record<string, string> | undefined {
  const value = record[key];
  if (!isRecord(value)) {
    return undefined;
  }
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(value)) {
    if (typeof v === "string") {
      out[k] = v;
    }
  }
  return out;
}

/**
 * Parses leakwatch JSON output into Finding objects.
 * Returns an empty array if the output cannot be parsed or is not an array.
 */
export function parseFindings(output: string): Finding[] {
  const trimmed = output.trim();
  if (!trimmed || trimmed === "null") {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) {
    return [];
  }

  const findings: Finding[] = [];
  for (const entry of parsed) {
    if (!isRecord(entry)) {
      continue;
    }

    const metadata = isRecord(entry.source_metadata)
      ? entry.source_metadata
      : {};

    findings.push({
      id: readString(entry, "id"),
      detectorId: readString(entry, "detector_id"),
      description: readString(entry, "description"),
      severity: normalizeSeverity(entry.severity),
      redacted: readString(entry, "redacted"),
      verificationStatus: normalizeVerificationStatus(
        entry.verification_status
      ),
      sourceMetadata: {
        filePath: readString(metadata, "file_path"),
        lineNumber: readNumber(metadata, "line_number"),
        sourceType: readString(metadata, "source_type"),
      },
      extraData: readStringMap(entry, "extra_data"),
    });
  }

  return findings;
}

/** Normalizes an unknown severity value to a valid Severity, defaulting to medium. */
export function normalizeSeverity(value: unknown): Finding["severity"] {
  const s = String(value).toLowerCase();
  if (s === "low" || s === "medium" || s === "high" || s === "critical") {
    return s;
  }
  return "medium";
}

/** Normalizes an unknown verification-status value, defaulting to unverified. */
export function normalizeVerificationStatus(
  value: unknown
): Finding["verificationStatus"] {
  const s = String(value);
  if (
    s === "unverified" ||
    s === "verified_active" ||
    s === "verified_inactive" ||
    s === "verify_error"
  ) {
    return s;
  }
  return "unverified";
}
