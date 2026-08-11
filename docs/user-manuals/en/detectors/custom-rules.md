---
title: "Custom Rules"
description: "How to define your own secret detection patterns in YAML and add them to a Leakwatch scan alongside the 65 built-in detectors."
---

# Custom Rules

The 65 built-in detectors cover widely used credential formats, but every organisation has internal tokens, proprietary service keys, or environment-specific patterns that no generic tool can anticipate. Custom rules let you extend Leakwatch with your own patterns — defined in plain YAML, loaded at runtime — without modifying source code or rebuilding the binary.

## Where custom rules live

Custom rules are defined under a top-level `custom-rules:` list in your `.leakwatch.yaml` configuration file:

```yaml
custom-rules:
  - id: acme-internal-token
    description: "ACME Corp internal service token"
    regex: 'acme_[a-z0-9]{32}'
    keywords:
      - acme_
    severity: critical
    entropy: 3.5
```

The rules are registered at runtime when Leakwatch starts. They run alongside the built-in detectors using the same Aho-Corasick pre-filter pipeline.

## Rule fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | Yes | string | Unique detector ID. Used in output and in `filter.exclude-detectors`. Must not collide with a built-in detector ID or another custom rule ID. |
| `description` | No | string | Human-readable description shown in output. |
| `regex` | Yes | string | RE2-compatible regular expression. Maximum 4096 characters. |
| `keywords` | No | list of strings | Aho-Corasick pre-filter keywords. The regex only runs on chunks that contain at least one of these strings. Omitting this field causes the regex to run on every chunk. |
| `severity` | No | string | `critical`, `high`, `medium`, or `low`. Defaults to `medium`. |
| `entropy` | No | float | Shannon entropy threshold (0–8). Matches whose entropy is **below** this value are discarded. Useful for filtering low-randomness false positives. |

:::tip
Always supply `keywords`. Even a single short keyword (like a token prefix) dramatically reduces the number of chunks the regex engine processes, keeping scans fast on large repositories. For example, if all your internal tokens begin with `acme_`, set `keywords: [acme_]`.

Use `entropy` to suppress matches on placeholder values like `acme_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` that satisfy the pattern but are clearly not real secrets. A threshold around 3.0–3.5 is a good starting point.
:::

## Collision handling

If a custom rule's `id` matches an already-registered detector — either a built-in detector or a previously loaded custom rule — the duplicate is **skipped** and an error is logged. Leakwatch does not crash; the rest of the rules load normally. Check the log output if a custom rule appears to have no effect.

## Verification

Custom rules have no paired verifier. Findings from custom rules are always reported with status `unverified` — they never become `verified_active` or `verified_inactive`.

## Complete example

The following `.leakwatch.yaml` defines two custom rules: one for an internal service token and one for a signing secret used in webhooks.

```yaml
custom-rules:
  - id: acme-internal-token
    description: "ACME Corp internal service token (format: acme_ + 32 hex chars)"
    regex: 'acme_[a-f0-9]{32}'
    keywords:
      - acme_
    severity: critical
    entropy: 3.2

  - id: acme-webhook-signing-secret
    description: "ACME Corp webhook signing secret (format: whsec_ + 40 base64url chars)"
    regex: 'whsec_[A-Za-z0-9_\-]{40}'
    keywords:
      - whsec_
    severity: high
    entropy: 3.5
```

Run a scan with this config:

```bash
leakwatch scan fs . --config .leakwatch.yaml
```

Sample JSON output for a custom-rule finding (secret value redacted) — a custom-rule finding uses exactly the same `Finding` schema as every built-in detector (see [Output Formats](#/output/output-formats)); there is no separate schema for custom rules:

```json
{
  "id": "8a403a46336fc6ffdc847d202b74536c",
  "detector_id": "acme-internal-token",
  "severity": "critical",
  "redacted": "****cdef",
  "source": {
    "source_type": "filesystem",
    "file_path": "config/production.env",
    "line": 14
  },
  "verification": {
    "status": "unverified"
  },
  "detected_at": "2026-05-23T10:15:30Z",
  "entropy": 4.12
}
```

:::note
The `redacted` field always masks the actual secret (by default, `****` followed by at most the last 4 characters). The raw value is never written to output unless you explicitly pass `--show-raw` (not recommended outside controlled environments). Custom rules have no verifier, so `verification.status` is always `unverified`.
:::

## Excluding a custom rule

Custom rules participate in the same filtering as built-in detectors. To disable a custom rule without removing it from config:

```yaml
filter:
  exclude-detectors:
    - acme-internal-token
```

## See also

- [Configuration: Config File](#/configuration/config-file) — full reference for `.leakwatch.yaml`, including where `custom-rules:` sits in the document structure.
- [Detector Catalog](#/detectors/detector-catalog) — the 65 built-in detectors, to check for ID conflicts before naming your custom rule.
- [How It Works](#/getting-started/how-it-works) — the Aho-Corasick pre-filter pipeline that `keywords` plugs into.
