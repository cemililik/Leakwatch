# Changelog

All notable changes to the Leakwatch VS Code extension are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- Refuse to run the `leakwatch` binary in untrusted workspaces and mark
  `leakwatch.executablePath` / `leakwatch.customRulesPath` as
  `machine-overridable` so a repository's own settings can no longer repoint the
  executable. Declares `capabilities.untrustedWorkspaces` explicitly.

### Fixed

- Save-triggered and single-file scans no longer wipe every other file's
  diagnostics from the Problems panel; only the scanned file's entries are
  replaced.
- File attribution now compares normalized absolute paths instead of a fragile
  suffix match, so findings are no longer mis-assigned to same-suffix files.
- Path resolution uses Node's `path` module instead of manual `/` concatenation
  for cross-platform correctness.
- Overlapping scans cancel their predecessor instead of racing to overwrite
  diagnostics and status-bar state; clearing diagnostics also cancels any
  in-flight scan.
- "Scan Workspace" now scans every folder of a multi-root workspace and
  aggregates the results.
- Status bar no longer keeps a stale error/warning tint while a new scan runs.

### Added

- Configurable scan timeout (`leakwatch.scanTimeoutMs`) and output buffer size
  (`leakwatch.maxBufferMb`).
- Actionable error messages for a missing executable (ENOENT), scan timeout, and
  output-buffer overflow.
- ESLint flat config, unit tests (Node test runner) for the parsing and
  path-resolution helpers, and a committed `package-lock.json`.
- A 256×256 Marketplace icon, lockfile-pinned VSIX packaging command, CI package
  artifact, and a protected manual Marketplace publishing workflow.

## [0.1.0]

- Initial release: diagnostics, scan-on-save, workspace/file scan commands, and
  a status bar indicator wrapping the `leakwatch` CLI.
