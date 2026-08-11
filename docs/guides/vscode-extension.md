# Leakwatch - VS Code Extension Guide

> **Document Version:** 1.1
> **Date:** 2026-08-11
> **Status:** Approved

---

> **Documentation role:** Supplemental extension deep dive. The [user manual](../user-manuals/en/getting-started/introduction.md) is authoritative for Leakwatch CLI behavior; this guide owns only extension-specific workflows.

## 1. Overview

The Leakwatch VS Code extension brings secret detection directly into your editor. It runs the Leakwatch CLI under the hood and surfaces findings as native VS Code diagnostics, so you can catch leaked secrets without leaving your workflow.

**Key capabilities:**

- **Scan on save** -- automatically scans files each time you save
- **Manual commands** -- scan the entire workspace or a single file on demand
- **Problems panel integration** -- findings appear as errors, warnings, or informational diagnostics
- **Status bar indicator** -- shows scanning state and finding count at a glance

---

## 2. Installation

### 2.1 Prerequisites

The Leakwatch CLI must be installed and accessible from your system `PATH`. See the [Getting Started Guide](./getting-started.md) for installation instructions.

Verify the CLI is available:

```bash
leakwatch version
```

### 2.2 Install from Marketplace / GitHub Releases (Not Yet Available)

The extension is not yet published to the VS Code Marketplace, and no CI workflow packages or uploads a `.vsix` to GitHub Releases today — `.github/workflows/vscode-ci.yml` only lints, compiles, and tests `vscode/` on every push/PR; it does not run `vsce package` or attach an artifact. Until one of those ships, build the `.vsix` yourself with [§2.3 Build from Source](#23-build-from-source) below.

### 2.3 Build from Source

```bash
# Clone the repository
git clone https://github.com/HodeTech/Leakwatch.git
cd Leakwatch/vscode

# Install dependencies
npm install

# Build for production
npm run compile

# Package as VSIX
npx @vscode/vsce package

# Install the generated VSIX
code --install-extension leakwatch-0.1.0.vsix
```

For development with live reload:

```bash
npm run watch
# Press F5 in VS Code to launch the Extension Development Host
```

---

## 3. Configuration

All settings are under the `leakwatch.*` namespace. Open **Settings** (`Ctrl+,`) and search for "Leakwatch", or edit `settings.json` directly.

### 3.1 Settings Reference

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `leakwatch.executablePath` | `string` | `"leakwatch"` | Path to the Leakwatch binary. Set this if the binary is not on your `PATH`. |
| `leakwatch.scanOnSave` | `boolean` | `true` | Automatically scan files when saved. |
| `leakwatch.minSeverity` | `string` | `"low"` | Minimum severity level to report. Options: `low`, `medium`, `high`, `critical`. |
| `leakwatch.showInlineHints` | `boolean` | `true` | Show inline hints next to detected secrets in the editor. |
| `leakwatch.customRulesPath` | `string` | `""` | Absolute or workspace-relative path to a custom rules YAML file. |

### 3.2 Example `settings.json`

```json
{
  "leakwatch.executablePath": "/usr/local/bin/leakwatch",
  "leakwatch.scanOnSave": true,
  "leakwatch.minSeverity": "medium",
  "leakwatch.showInlineHints": true,
  "leakwatch.customRulesPath": "${workspaceFolder}/.leakwatch-rules.yaml"
}
```

### 3.3 Setting Details

**`leakwatch.executablePath`** -- If you installed Leakwatch via `go install`, the binary is typically at `$HOME/go/bin/leakwatch`. If VS Code cannot find it, set the full path here.

**`leakwatch.minSeverity`** -- Controls the noise level. Setting this to `high` hides medium and low findings, which is useful in large projects where generic API key detections may be noisy.

**`leakwatch.customRulesPath`** -- Points to a YAML file containing custom detection rules. See [Custom Rules Integration](#8-custom-rules-integration) below.

---

## 4. Usage

### 4.1 Scan on Save

When `leakwatch.scanOnSave` is enabled (the default), the extension automatically scans each file after you save it. A 1-second debounce prevents excessive scans during rapid successive saves.

The scan-on-save flow:

```mermaid
sequenceDiagram
    participant User
    participant VSCode as VS Code
    participant Ext as Leakwatch Extension
    participant CLI as Leakwatch CLI
    participant Panel as Problems Panel

    User->>VSCode: Save file (Ctrl+S)
    VSCode->>Ext: onDidSaveTextDocument event
    Ext->>Ext: Debounce (1 second)
    Ext->>Ext: Update status bar → "Scanning..."
    Ext->>CLI: leakwatch scan fs <directory>
    CLI-->>Ext: JSON findings
    Ext->>Ext: Filter findings to saved file
    Ext->>Panel: Update diagnostics
    Ext->>Ext: Update status bar → result count
    Panel-->>User: Findings visible in Problems panel
```

### 4.2 Manual Scan Commands

Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and choose one of the following:

| Command | Description |
|---------|-------------|
| **Leakwatch: Scan Workspace** | Scans all files in the first workspace folder. Results appear in the Problems panel. |
| **Leakwatch: Scan Current File** | Scans only the active editor file. Previous diagnostics for that file are cleared first. |
| **Leakwatch: Clear Diagnostics** | Removes all Leakwatch diagnostics from the Problems panel and resets the status bar. |

### 4.3 Reading Diagnostics in the Problems Panel

Findings appear in the **Problems** panel (`Ctrl+Shift+M`). Each diagnostic includes:

- **Severity icon** -- error (red), warning (yellow), or information (blue)
- **Message** -- the detector name and a description of the finding
- **File path and line number** -- click to navigate directly to the location
- **Source label** -- always shows "leakwatch" so you can filter by source

You can filter the Problems panel to show only Leakwatch findings by typing `leakwatch` in the filter box.

---

## 5. Status Bar

The Leakwatch status bar item appears in the bottom-left area of VS Code. It reflects the current scan state:

| State | Icon/Text | Meaning |
|-------|-----------|---------|
| **Idle** | `Leakwatch` | Extension is active, no scan in progress. |
| **Scanning** | `Leakwatch: Scanning...` | A scan is currently running. |
| **Clean** | `Leakwatch: 0 findings` | Last scan completed with no secrets detected. |
| **Warnings** | `Leakwatch: N finding(s)` | Last scan found N potential secrets. Click to open the Problems panel. |
| **Error** | `Leakwatch: Error` | The scan failed (e.g., binary not found, invalid configuration). |

---

## 6. Severity Mapping

Leakwatch severity levels are mapped to VS Code diagnostic severities as follows:

| Leakwatch Severity | VS Code Diagnostic Severity | Problems Panel Icon |
|--------------------|-----------------------------|---------------------|
| **Critical** | Error | Red circle |
| **High** | Error | Red circle |
| **Medium** | Warning | Yellow triangle |
| **Low** | Information | Blue circle |

This mapping ensures that critical and high-severity secrets (e.g., AWS Secret Keys, private keys) are immediately visible as errors, while lower-severity findings appear as warnings or informational messages.

---

## 7. Screenshots

> **Note:** The following sections are placeholders for future screenshots.

### 7.1 Scan on Save in Action

*[Screenshot: Editor showing a file with an inline hint highlighting a detected AWS key, with the Problems panel open below.]*

### 7.2 Problems Panel with Findings

*[Screenshot: Problems panel showing multiple findings with different severity levels, filtered by "leakwatch" source.]*

### 7.3 Status Bar States

*[Screenshot: Status bar showing the "Leakwatch: 3 finding(s)" state with a warning indicator.]*

### 7.4 Workspace Scan Results

*[Screenshot: Command Palette with "Leakwatch: Scan Workspace" selected, followed by results in the Problems panel.]*

---

## 8. Working with `.leakwatchignore`

The Leakwatch CLI respects `.leakwatchignore` files, and this behavior carries over to the VS Code extension. Place a `.leakwatchignore` file in your workspace root to exclude files or directories from scanning.

Example `.leakwatchignore`:

```text
# Test fixtures containing fake secrets
testdata/
*_test.go

# Generated files
dist/
node_modules/

# Vendored dependencies
vendor/
```

The extension passes the workspace directory to the CLI, which automatically discovers and applies `.leakwatchignore` rules. No additional VS Code configuration is needed.

You can also use inline ignore comments to suppress specific findings:

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # leakwatch:ignore
```

---

## 9. Custom Rules Integration

Custom detection rules are defined inside a `.leakwatch.yaml` configuration file under the `custom-rules:` key (not in a separate standalone file). The Leakwatch CLI loads them when you pass that config file via `--config`.

### Step 1 — Define custom rules in `.leakwatch.yaml`

Add a `custom-rules:` block to your project's `.leakwatch.yaml` (or create a dedicated config file):

```yaml
# .leakwatch.yaml (or a dedicated config such as .leakwatch-dev.yaml)
custom-rules:
  - id: internal-service-token
    description: "Internal service authentication token"
    regex: 'X-Internal-Token:\s*[A-Za-z0-9]{32,}'
    keywords:
      - "X-Internal-Token"
    severity: high
    entropy: 3.5   # float64 minimum entropy threshold; set to 0 to disable
```

Each rule requires an `id`, a `regex` pattern, and `keywords` for the Aho-Corasick pre-filter. The `entropy` field is a `float64` minimum threshold (0–8.0); set it to `0` to skip entropy filtering for this rule.

### Step 2 — Point the extension at the config file

Set `leakwatch.customRulesPath` to the **full `.leakwatch.yaml` path**. The extension passes this path to the CLI as `--config`:

```json
{
  "leakwatch.customRulesPath": "${workspaceFolder}/.leakwatch.yaml"
}
```

The CLI is then invoked as:

```
leakwatch scan fs <workspace> --config <leakwatch.customRulesPath>
```

Custom rules in that file are registered before the scan and applied alongside all built-in detectors during every scan (both scan-on-save and manual scans).

> **Note:** The `leakwatch.customRulesPath` setting must point to a complete `.leakwatch.yaml` file — not a standalone rules-only file. All other config keys in that file (scan, output, filter, etc.) also take effect when the file is loaded.

For the full custom-rules specification and field reference, see the [Configuration Guide](./configuration.md).

---

## 10. Troubleshooting

### 10.1 Binary Not Found

**Symptom:** Status bar shows "Leakwatch: Error" immediately after activation, or scans fail silently.

**Solution:**
1. Verify the CLI is installed: `leakwatch version`
2. If installed but not on `PATH`, set the full path in settings:
   ```json
   { "leakwatch.executablePath": "/usr/local/bin/leakwatch" }
   ```
3. On macOS, if installed via `go install`, the default path is `$HOME/go/bin/leakwatch`.
4. Restart VS Code after changing the executable path.

### 10.2 No Findings Shown

**Symptom:** You expect findings but the Problems panel is empty.

**Possible causes:**
- **`minSeverity` is set too high** -- lower it to `low` to see all findings.
- **`.leakwatchignore` is excluding the file** -- check your ignore rules.
- **Scan-on-save is disabled** -- verify `leakwatch.scanOnSave` is `true`, or run a manual scan.
- **File was not saved** -- scan-on-save triggers only after the file is persisted to disk.

### 10.3 Performance Tips

For large workspaces where scans feel slow:

- **Increase `minSeverity`** to `medium` or `high` to reduce the number of findings processed.
- **Use `.leakwatchignore`** to exclude large directories like `node_modules/`, `vendor/`, or `dist/`.
- **Disable scan-on-save** and use manual workspace scans instead:
  ```json
  { "leakwatch.scanOnSave": false }
  ```
- **Avoid scanning generated or binary-heavy directories** -- the CLI skips binary files, but directory traversal still takes time.

### 10.4 Extension Logs

To view extension logs for debugging:

1. Open the Output panel (`Ctrl+Shift+U`)
2. Select **Leakwatch** from the dropdown
3. Set `--log-level debug` in the CLI for verbose output

---

## 11. Next Steps

| Topic | Document |
|-------|----------|
| Getting started with Leakwatch | [Getting Started Guide](./getting-started.md) |
| Configuration file and options | [Configuration Guide](./configuration.md) |
| Git repository scanning | [Git Scanning Guide](./git-scanning.md) |
| Custom detection rules | [Configuration Guide](./configuration.md) |
| Architecture overview | [Architecture Document](../architecture/03-ARCHITECTURE.md) |
