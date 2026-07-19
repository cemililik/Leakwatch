/**
 * Leakwatch VS Code Extension
 *
 * Integrates the Leakwatch secret scanner with VS Code, providing:
 * - Real-time diagnostics (Problems panel) for detected secrets
 * - Scan on save (configurable)
 * - Manual workspace and file scanning via commands
 * - Status bar indicator showing scan state and finding count
 */

import * as vscode from "vscode";
import * as path from "path";
import { scan } from "./scanner";
import { addDiagnostics, setFileDiagnostics } from "./diagnostics";
import { findingMatchesFile } from "./paths";
import { Finding } from "./types";
import * as statusbar from "./statusbar";

let diagnosticCollection: vscode.DiagnosticCollection;

/** Debounce timer for scan-on-save. */
let saveTimer: ReturnType<typeof setTimeout> | undefined;
const SAVE_DEBOUNCE_MS = 1000;

/**
 * The single in-flight scan, if any. Starting a new scan cancels the previous
 * one so overlapping scans never race to stomp diagnostics/status-bar state.
 */
let activeScan: vscode.CancellationTokenSource | undefined;

/** Cancels any in-flight scan and returns a fresh token for the new scan. */
function beginScan(): vscode.CancellationToken {
  if (activeScan) {
    activeScan.cancel();
    activeScan.dispose();
  }
  activeScan = new vscode.CancellationTokenSource();
  return activeScan.token;
}

/** Cancels any in-flight scan without starting a new one. */
function cancelActiveScan(): void {
  if (activeScan) {
    activeScan.cancel();
    activeScan.dispose();
    activeScan = undefined;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("leakwatch");
  context.subscriptions.push(diagnosticCollection);

  const bar = statusbar.createStatusBar();
  context.subscriptions.push(bar);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand("leakwatch.scanWorkspace", () =>
      scanWorkspace()
    ),
    vscode.commands.registerCommand("leakwatch.scanCurrentFile", () =>
      scanCurrentFile()
    ),
    vscode.commands.registerCommand("leakwatch.clearDiagnostics", () => {
      cancelActiveScan();
      diagnosticCollection.clear();
      statusbar.setIdle();
    })
  );

  // Scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      const config = vscode.workspace.getConfiguration("leakwatch");
      if (!config.get<boolean>("scanOnSave", true)) {
        return;
      }
      // Never auto-run the binary against an untrusted workspace.
      if (!vscode.workspace.isTrusted) {
        return;
      }

      // Debounce rapid saves
      if (saveTimer) {
        clearTimeout(saveTimer);
      }
      saveTimer = setTimeout(() => {
        scanFile(document.uri);
      }, SAVE_DEBOUNCE_MS);
    })
  );
}

export function deactivate(): void {
  if (saveTimer) {
    clearTimeout(saveTimer);
  }
  cancelActiveScan();
}

/** Returns false (and warns) when the workspace is not trusted. */
function requireTrust(): boolean {
  if (!vscode.workspace.isTrusted) {
    vscode.window.showWarningMessage(
      "Leakwatch: Scanning is disabled in untrusted workspaces. Trust this workspace to scan."
    );
    return false;
  }
  return true;
}

/**
 * Scans every folder of the (possibly multi-root) workspace and aggregates
 * the results into the Problems panel.
 */
async function scanWorkspace(): Promise<void> {
  if (!requireTrust()) {
    return;
  }

  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders || workspaceFolders.length === 0) {
    vscode.window.showWarningMessage("Leakwatch: No workspace folder open.");
    return;
  }

  statusbar.setScanning();
  const token = beginScan();

  const perFolder: { scanRoot: string; findings: Finding[] }[] = [];
  let totalFindings = 0;

  for (const folder of workspaceFolders) {
    const scanRoot = folder.uri.fsPath;
    const result = await scan(scanRoot, token);

    if (token.isCancellationRequested) {
      return; // A newer scan superseded us; let it own the UI.
    }
    if (result.error) {
      statusbar.setError(result.error);
      vscode.window.showErrorMessage(`Leakwatch: ${result.error}`);
      return;
    }

    perFolder.push({ scanRoot, findings: result.findings });
    totalFindings += result.findings.length;
  }

  diagnosticCollection.clear();
  for (const { scanRoot, findings } of perFolder) {
    addDiagnostics(diagnosticCollection, findings, scanRoot);
  }
  statusbar.setResults(totalFindings);

  if (totalFindings > 0) {
    vscode.window.showWarningMessage(
      `Leakwatch: Found ${totalFindings} secret${totalFindings === 1 ? "" : "s"}. Check the Problems panel.`
    );
  }
}

/**
 * Scans the currently active file.
 */
async function scanCurrentFile(): Promise<void> {
  if (!requireTrust()) {
    return;
  }

  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Leakwatch: No active file.");
    return;
  }

  await scanFile(editor.document.uri);
}

/**
 * Scans just the given file. The CLI's filesystem source accepts a single file
 * target and reports its path relative to the file's parent directory, so the
 * findings are resolved against that directory as the scan root.
 */
async function scanFile(fileUri: vscode.Uri): Promise<void> {
  const filePath = fileUri.fsPath;
  // The CLI reports the finding path relative to the file's parent directory.
  const scanRoot = path.dirname(filePath);

  statusbar.setScanning();
  const token = beginScan();

  // Scan only this file rather than its whole containing directory.
  const result = await scan(filePath, token);

  if (token.isCancellationRequested) {
    return; // Superseded by a newer scan.
  }
  if (result.error) {
    statusbar.setError(result.error);
    return;
  }

  // Keep only findings whose resolved path matches this exact file.
  const fileFindings = result.findings.filter((f) =>
    findingMatchesFile(scanRoot, f.sourceMetadata.filePath, filePath)
  );

  setFileDiagnostics(diagnosticCollection, fileUri, fileFindings, scanRoot);
  statusbar.setResults(fileFindings.length);
}
