/**
 * Status bar module — shows scan status and finding count.
 */

import * as vscode from "vscode";

let statusBarItem: vscode.StatusBarItem;

/** Creates and returns the status bar item. */
export function createStatusBar(): vscode.StatusBarItem {
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "leakwatch.scanWorkspace";
  setIdle();
  statusBarItem.show();
  return statusBarItem;
}

/** Shows idle state with shield icon. */
export function setIdle(): void {
  statusBarItem.text = "$(shield) Leakwatch";
  statusBarItem.tooltip = "Click to scan workspace";
  statusBarItem.backgroundColor = undefined;
}

/** Shows scanning in progress. */
export function setScanning(): void {
  statusBarItem.text = "$(loading~spin) Leakwatch: Scanning...";
  statusBarItem.tooltip = "Scan in progress";
  // Reset any stale error/warning tint from a previous scan.
  statusBarItem.backgroundColor = undefined;
}

/** Shows scan results. */
export function setResults(findingCount: number): void {
  if (findingCount === 0) {
    statusBarItem.text = "$(shield) Leakwatch: Clean";
    statusBarItem.tooltip = "No secrets detected";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(warning) Leakwatch: ${findingCount} secret${findingCount === 1 ? "" : "s"}`;
    statusBarItem.tooltip = `${findingCount} secret${findingCount === 1 ? "" : "s"} detected — click to scan again`;
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  }
}

/** Shows error state. */
export function setError(message: string): void {
  statusBarItem.text = "$(error) Leakwatch: Error";
  statusBarItem.tooltip = message;
  statusBarItem.backgroundColor = new vscode.ThemeColor(
    "statusBarItem.errorBackground"
  );
}
