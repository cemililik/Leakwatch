/**
 * Path helpers — platform-aware resolution and matching of finding paths.
 *
 * The leakwatch filesystem source emits paths relative to the scan root
 * (via Go's `filepath.Rel`), so these helpers join them against the scan
 * root using Node's `path` module rather than hand-concatenating separators.
 *
 * This module contains no `vscode` imports so it can be unit-tested directly.
 */

import * as path from "path";

/**
 * Resolves a finding's (possibly relative) path against the scan root into an
 * absolute, normalized path. Absolute finding paths are returned as-is.
 */
export function resolveFindingPath(
  scanRoot: string,
  findingPath: string
): string {
  if (path.isAbsolute(findingPath)) {
    return path.normalize(findingPath);
  }
  return path.resolve(scanRoot, findingPath);
}

/**
 * Reports whether a finding (identified by its scan-root-relative path)
 * refers to the given absolute file path. Uses normalized absolute-path
 * comparison rather than fragile suffix matching.
 */
export function findingMatchesFile(
  scanRoot: string,
  findingPath: string,
  absoluteFilePath: string
): boolean {
  const resolvedFinding = resolveFindingPath(scanRoot, findingPath);
  const resolvedTarget = path.resolve(absoluteFilePath);
  if (process.platform === "win32") {
    return resolvedFinding.toLowerCase() === resolvedTarget.toLowerCase();
  }
  return resolvedFinding === resolvedTarget;
}
