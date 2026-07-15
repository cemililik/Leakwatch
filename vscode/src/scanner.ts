/**
 * Scanner module — executes the leakwatch binary and parses results.
 */

import * as vscode from "vscode";
import { execFile } from "child_process";
import { Finding } from "./types";
import { parseFindings } from "./parse";

/** Result of a scan operation. */
export interface ScanResult {
  findings: Finding[];
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BUFFER_MB = 10;

/**
 * Runs leakwatch scan on the given path and returns parsed findings.
 * Uses JSON output format for reliable parsing.
 *
 * Refuses to execute in an untrusted workspace: the executable path and
 * config path can be influenced by workspace settings, so running the binary
 * against an untrusted repository is a code-execution vector we do not take.
 */
export function scan(
  targetPath: string,
  token: vscode.CancellationToken
): Promise<ScanResult> {
  return new Promise((resolve) => {
    if (!vscode.workspace.isTrusted) {
      resolve({
        findings: [],
        error:
          "Leakwatch is disabled in untrusted workspaces. Trust this workspace to run scans.",
      });
      return;
    }

    const config = vscode.workspace.getConfiguration("leakwatch");
    const executable = config.get<string>("executablePath", "leakwatch");
    const minSeverity = config.get<string>("minSeverity", "low");
    const customRulesPath = config.get<string>("customRulesPath", "");
    const timeout = Math.max(
      1_000,
      config.get<number>("scanTimeoutMs", DEFAULT_TIMEOUT_MS)
    );
    const maxBuffer =
      Math.max(1, config.get<number>("maxBufferMb", DEFAULT_MAX_BUFFER_MB)) *
      1024 *
      1024;

    const args = [
      "scan",
      "fs",
      targetPath,
      "--format",
      "json",
      "--min-severity",
      minSeverity,
      "--no-verify",
    ];

    if (customRulesPath) {
      args.push("--config", customRulesPath);
    }

    const child = execFile(
      executable,
      args,
      { maxBuffer, timeout },
      (error, stdout, stderr) => {
        if (token.isCancellationRequested) {
          resolve({ findings: [] });
          return;
        }

        // Exit code 1 means findings were detected (not an error).
        const execError = error as (Error & {
          code?: number | string;
          killed?: boolean;
        }) | null;
        if (execError && execError.code !== 1) {
          resolve({ findings: [], error: describeError(execError, executable, timeout, stderr) });
          return;
        }

        const findings = parseFindings(stdout);
        resolve({ findings });
      }
    );

    token.onCancellationRequested(() => {
      child.kill();
    });
  });
}

/** Produces a user-actionable message for common execFile failure modes. */
function describeError(
  error: Error & { code?: number | string; killed?: boolean },
  executable: string,
  timeout: number,
  stderr: string
): string {
  if (error.code === "ENOENT") {
    return `Leakwatch executable not found ("${executable}"). Install it (see the extension README) or set "leakwatch.executablePath".`;
  }
  if (error.killed || error.code === "ETIMEDOUT") {
    return `Leakwatch scan timed out after ${Math.round(
      timeout / 1000
    )}s. Increase "leakwatch.scanTimeoutMs" for large repositories.`;
  }
  if (error.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") {
    return 'Leakwatch produced more output than the buffer allows. Increase "leakwatch.maxBufferMb".';
  }
  return stderr.trim() || error.message;
}
