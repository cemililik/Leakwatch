---
title: "Remediation Guidance"
description: "Use --remediation to enrich findings with provider-specific rotation and revocation steps, urgency ratings, and official documentation links."
---

# Remediation Guidance

Knowing a secret is leaked is only half the work — you also need to know what to do about it. Passing `--remediation` to any scan command enriches each finding with structured, provider-specific guidance: the steps to rotate or revoke the credential, a link to the provider's documentation, a link to the management console, an urgency rating, and a verification checklist.

## How to enable it

Add `--remediation` to any scan command:

```bash
leakwatch scan fs . --remediation
leakwatch scan git . --remediation --format json
leakwatch scan image myapp:latest --remediation --format sarif
```

Remediation enrichment is disabled by default. When the flag is absent, the `remediation` field in each finding is `null` and no extra data is fetched or computed.

## What it contains

Each remediation entry includes the following fields:

| Field | Description |
|---|---|
| `title` | Short name of the remediation action (e.g. `"Rotate AWS Access Key"`) |
| `steps` | Ordered list of steps to rotate or revoke the secret |
| `doc_url` | Link to the provider's official credential-management documentation |
| `console_url` | Direct link to the provider's management console page |
| `urgency` | How quickly to act: `"immediate"`, `"high"`, or `"medium"` |
| `checklist` | Post-rotation verification steps (e.g. review audit logs, notify the security team) |

Leakwatch ships 64 remediation entries — one for every built-in detector. All 64 entries are included in the binary; no network calls are made to fetch guidance.

## How it appears in each format

Enrichment adds the guidance to the finding object in memory. How it surfaces depends on the output format:

**JSON** — the full structured `remediation` object is nested inside each finding:

```bash
leakwatch scan fs . --remediation --format json
```

```json
{
  "id": "447b5d2846d08ce25dd3d638cfe911ad",
  "detector_id": "github-token",
  "severity": "critical",
  "redacted": "ghp_****************************Xk9R",
  "source": {
    "source_type": "filesystem",
    "file_path": "scripts/deploy.sh",
    "line": 14
  },
  "verification": {
    "status": "verified_active"
  },
  "remediation": {
    "title": "Revoke GitHub Token",
    "steps": [
      "Go to GitHub Settings > Developer settings > Personal access tokens.",
      "Revoke the compromised token immediately.",
      "Create a new token with the minimum required scopes.",
      "Update all integrations and CI/CD pipelines with the new token."
    ],
    "doc_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    "console_url": "https://github.com/settings/tokens",
    "urgency": "immediate",
    "checklist": [
      "Review the GitHub audit log for unauthorized actions performed with the token.",
      "Check repository and organization settings for unexpected changes.",
      "Notify the security team about the exposure.",
      "Scan for other repositories that may contain the same token."
    ]
  },
  "entropy": 5.82,
  "detected_at": "2026-05-23T10:15:30Z"
}
```

**SARIF** — the `steps` are embedded in the rule's `help.text` field, and `doc_url` is set as the rule's `helpUri`. This surfaces directly in GitHub Code Scanning's alert details panel.

**CSV** — only the remediation `title` is written to the `remediation` column. The full structured guidance is not included in the CSV output.

**Table** — only the remediation `title` is shown in the `REMEDIATION` column.

```bash
leakwatch scan fs . --remediation --format table
```

```text
SEVERITY  DETECTOR      FILE                LINE  REDACTED      STATUS           REMEDIATION
--------  --------      ----                ----  --------      ------           -----------
CRITICAL  github-token  scripts/deploy.sh   14    ghp_****Xk9R  verified_active  Revoke GitHub Token

Found 1 secret (1 critical).
```

:::tip
Use `--remediation --format json` when you need the full structured guidance for automated incident-response workflows. Use `--remediation --format table` for a quick human-readable triage session in the terminal.
:::

:::note
Enrichment runs only when `--remediation` is set. Without the flag, the `remediation` field is absent from JSON and SARIF output, the CSV `remediation` column is empty, and the table `REMEDIATION` column shows `-`. The flag does not modify the original scan results — it adds a layer on top.
:::

## See also

- [Output Formats](#/output/output-formats)
- [How Verification Works](#/verification/how-verification-works)
