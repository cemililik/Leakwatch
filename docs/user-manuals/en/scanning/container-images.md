---
title: "Container Images"
description: "Scan OCI and Docker image layers for leaked secrets without a Docker daemon."
---

# Container Images

Container images are a common hiding place for secrets: API keys baked into environment variables, credentials embedded in build layers, and configuration files copied into image layers and then forgotten. `leakwatch scan image` inspects every layer of an OCI or Docker image and surfaces those secrets before the image is deployed.

## Basic usage

```bash
leakwatch scan image <image:tag>
```

The command takes exactly one argument: an image reference in standard `name:tag` notation. Leakwatch uses [go-containerregistry](https://github.com/google/go-containerregistry) to pull and inspect images **daemonlessly** — no running Docker daemon is required.

```bash
# Scan a Docker Hub image
leakwatch scan image nginx:latest

# Scan a private GitHub Container Registry image
leakwatch scan image ghcr.io/org/myapp:v1.2.0

# Scan an Amazon ECR image
leakwatch scan image 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

## Supported registries

| Registry | Example reference |
|----------|-------------------|
| Docker Hub | `nginx:latest`, `myorg/myapp:1.0.0` |
| GitHub Container Registry (GHCR) | `ghcr.io/org/myapp:v1.2.0` |
| Amazon ECR | `123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest` |
| Google Container Registry (GCR) | `gcr.io/my-project/myapp:latest` |
| Any OCI-compatible registry | Standard `registry/name:tag` form |

## Authentication

Leakwatch uses the standard credential keychain used by Docker and other OCI tools. If you are already authenticated via `docker login` (or an equivalent tool such as `crane`, `skopeo`, or cloud-provider credential helpers), Leakwatch will use those credentials automatically.

```bash
# Log in to GHCR first
docker login ghcr.io

# Then scan — credentials are picked up automatically
leakwatch scan image ghcr.io/org/private-app:latest
```

For Amazon ECR, configure the ECR credential helper or set `AWS_ACCESS_KEY_ID` and related environment variables before scanning.

## How it scans

Leakwatch pulls the image manifest, iterates over each layer in order, and extracts the files within each layer. Each file's content is run through the same detection pipeline as a filesystem scan. Path exclusions from `filter.exclude-paths` in `.leakwatch.yaml` (or `--exclude`) apply here, limiting which file paths inside layers are examined.

:::note
As a defense against decompression-bomb layers, Leakwatch caps the cumulative decompressed bytes it will read: 2 GiB per layer and 10 GiB across the whole image. If a layer or image exceeds its ceiling, the affected layer's scan is truncated (a warning is logged) rather than let decompression run unbounded.
:::

## Flags

There are no image-specific flags. All common scan flags apply:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip files larger than this value (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--exclude` | — | — | Path pattern to exclude. Repeatable; combined with `filter.exclude-paths`. |
| `--exclude-detectors` | — | — | Detector IDs to exclude for this run. Repeatable; combined with `filter.exclude-detectors`. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Path-based exclusions are configured in `.leakwatch.yaml` under `filter.exclude-paths`, or per-run via `--exclude`. See [Config File](#/configuration/config-file) for details.

Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Examples

Scan a Docker Hub image and print results as a table:

```bash
leakwatch scan image alpine:3.20 --format table
```

Scan a private registry image and save SARIF output:

```bash
leakwatch scan image ghcr.io/org/myapp:v1.2.0 --format sarif -o results.sarif
```

Scan and show only verified active secrets:

```bash
leakwatch scan image myapp:latest --only-verified --format table
```

Include remediation guidance in JSON output:

```bash
leakwatch scan image myapp:latest --remediation --format json -o image-findings.json
```

## Finding metadata

Each finding from an image scan includes layer metadata:

| Field | Description |
|-------|-------------|
| `image` | The image reference that was scanned. |
| `layer` | The layer digest where the finding was detected (`"config"` for a finding in the image config, not a layer). |
| `layer_idx` | The numeric index (0-based) of the layer within the image manifest; `-1` for a finding in the image config. |
| `file_path` | The path of the file within the layer. |

:::tip
Integrate container image scanning into your CI/CD pipeline's build stage to catch secrets before the image is pushed to a registry. Use `--format sarif` to upload results directly to GitHub Code Scanning.
:::

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (image not found, authentication error, etc.). |
| `3` | Scan was interrupted (`Ctrl+C` / `SIGTERM`) before completing, and no findings had been reported. |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Filesystem](#/scanning/filesystem) — scan a local directory tree.
- [Config File](#/configuration/config-file) — configure exclusions and other defaults.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.
