/**
 * Diagnostics module — converts Leakwatch findings to VS Code diagnostics.
 */

import * as vscode from "vscode";
import { Finding, Severity } from "./types";
import { resolveFindingPath } from "./paths";

/** Maps Leakwatch severity to VS Code diagnostic severity. */
function toVSCodeSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
      return vscode.DiagnosticSeverity.Error;
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}

/** Creates a VS Code diagnostic from a Leakwatch finding. */
function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const line = Math.max(0, finding.sourceMetadata.lineNumber - 1);
  const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

  const severity = toVSCodeSeverity(finding.severity);
  const message = `[${finding.severity.toUpperCase()}] ${finding.description}: ${finding.redacted}`;

  const diagnostic = new vscode.Diagnostic(range, message, severity);
  diagnostic.source = "Leakwatch";
  diagnostic.code = finding.detectorId;

  return diagnostic;
}

/** Groups findings by their resolved absolute file URI. */
function groupByUri(
  findings: Finding[],
  scanRoot: string
): Map<string, vscode.Diagnostic[]> {
  const grouped = new Map<string, vscode.Diagnostic[]>();

  for (const finding of findings) {
    const filePath = finding.sourceMetadata.filePath;
    if (!filePath) {
      continue;
    }

    const absolutePath = resolveFindingPath(scanRoot, filePath);
    const uri = vscode.Uri.file(absolutePath);
    const key = uri.toString();

    const existing = grouped.get(key);
    if (existing) {
      existing.push(toDiagnostic(finding));
    } else {
      grouped.set(key, [toDiagnostic(finding)]);
    }
  }

  return grouped;
}

/**
 * Sets diagnostics for the given findings without clearing the collection,
 * resolving each finding's path against `scanRoot`. Used to aggregate the
 * results of several roots (multi-root workspaces) into one collection.
 */
export function addDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  scanRoot: string
): void {
  for (const [uriString, diagnostics] of groupByUri(findings, scanRoot)) {
    collection.set(vscode.Uri.parse(uriString), diagnostics);
  }
}

/**
 * Replaces the entire diagnostic collection with the given findings.
 * Used for whole-workspace scans where every previous entry is superseded.
 */
export function replaceAllDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  scanRoot: string
): void {
  collection.clear();
  addDiagnostics(collection, findings, scanRoot);
}

/**
 * Replaces the diagnostics for a single target file only, leaving every other
 * file's diagnostics in the collection untouched. Used for save-triggered and
 * single-file scans so they don't wipe the rest of the Problems panel.
 */
export function setFileDiagnostics(
  collection: vscode.DiagnosticCollection,
  targetUri: vscode.Uri,
  findings: Finding[],
  scanRoot: string
): void {
  const diagnostics: vscode.Diagnostic[] = [];
  for (const [uriString, group] of groupByUri(findings, scanRoot)) {
    if (vscode.Uri.parse(uriString).toString() === targetUri.toString()) {
      diagnostics.push(...group);
    }
  }
  // collection.set on a single URI atomically replaces just that file's
  // entries — no blanket clear needed.
  collection.set(targetUri, diagnostics);
}
