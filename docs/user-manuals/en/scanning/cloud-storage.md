---
title: "Cloud Storage (S3 & GCS)"
description: "Scan AWS S3 and Google Cloud Storage buckets for leaked secrets."
---

# Cloud Storage (S3 & GCS)

Secrets regularly end up in cloud storage — exported database dumps, environment files, CI artefacts, and log archives all flow into buckets that may be readable by more people than intended. Leakwatch can scan AWS S3 and Google Cloud Storage buckets object-by-object and flag any secrets it finds before they become an incident.

## AWS S3

### Usage

```bash
leakwatch scan s3 <bucket>
```

The command takes exactly one argument: the **bucket name** (without the `s3://` prefix). The scan target is displayed as `s3://<bucket>`.

### Authentication

Leakwatch uses the standard [AWS default credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html):

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).
2. Shared credentials file (`~/.aws/credentials`).
3. Shared configuration file (`~/.aws/config`).
4. IAM role attached to the instance or task (EC2, ECS, Lambda).

No additional configuration is required if you are already authenticated with the AWS CLI (`aws configure` or an assumed role).

### S3-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prefix` | string | — | Scan only objects whose key starts with this prefix. |
| `--region` | string | From AWS config | AWS region of the bucket. |

### S3 examples

Scan an entire bucket:

```bash
leakwatch scan s3 my-config-bucket
```

Scan only objects under a specific key prefix in a given region:

```bash
leakwatch scan s3 my-bucket --prefix logs/ --region us-east-1
```

Save results as SARIF:

```bash
leakwatch scan s3 my-bucket --format sarif --output s3-results.sarif
```

:::tip
Use `--prefix` to limit the scan to a relevant sub-path. Scanning a large bucket with millions of objects can be slow and may incur S3 GET request costs. Narrow the prefix to what actually matters — for example `configs/` or `exports/`.
:::

---

## Google Cloud Storage

### Usage

```bash
leakwatch scan gcs <bucket>
```

The command takes exactly one argument: the **bucket name** (without the `gs://` prefix). The scan target is displayed as `gs://<bucket>`.

### Authentication

Leakwatch uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials). The credential search order is:

1. `GOOGLE_APPLICATION_CREDENTIALS` environment variable pointing to a service-account key file.
2. User credentials set up by `gcloud auth application-default login`.
3. Service account attached to a Google Compute Engine instance, Cloud Run service, or GKE workload.

### GCS-specific flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--prefix` | string | — | Scan only objects whose name starts with this prefix. |
| `--project` | string | — | GCP project ID (required by some ADC configurations). |

### GCS examples

Scan an entire bucket with a specific GCP project:

```bash
leakwatch scan gcs my-config-bucket --project my-gcp-project
```

Scan only objects under a specific prefix:

```bash
leakwatch scan gcs my-bucket --project my-gcp-project --prefix exports/
```

Output as CSV:

```bash
leakwatch scan gcs my-bucket --format csv --output gcs-results.csv
```

---

## Common scan flags

Both `s3` and `gcs` support the same common scan flags:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `json` | Output format: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Write results to this file instead of stdout. |
| `--concurrency` | `-c` | CPU count | Number of concurrent workers. |
| `--max-file-size` | — | `10485760` (10 MB) | Skip objects larger than this value (bytes). |
| `--show-raw` | — | `false` | Include the raw secret value in output. |
| `--exclude` | — | — | Object-key pattern to exclude. Repeatable; combined with `filter.exclude-paths`. |
| `--exclude-detectors` | — | — | Detector IDs to exclude for this run. Repeatable; combined with `filter.exclude-detectors`. |
| `--no-verify` | — | `false` | Disable secret verification. |
| `--only-verified` | — | `false` | Report only findings confirmed active by verification. |
| `--min-severity` | — | `low` | Minimum severity to report: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Attach remediation guidance to each finding. |

Path-based exclusions (applied to object keys) are configured in `.leakwatch.yaml` under `filter.exclude-paths`, or per-run via `--exclude`. Root-level flags `--config` and `--log-level` (default `warn`) also apply.

## Finding metadata

An S3 or GCS finding carries only the fields common to every source, plus `file_path` set to `<bucket>/<object-key>` (there is no separate `line` field for cloud-storage findings).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings. |
| `1` | Scan completed, findings reported. |
| `2` | Scan failed (authentication error, bucket not found, etc.). |
| `3` | Scan was interrupted (`Ctrl+C` / `SIGTERM`) before completing, and no findings had been reported. |

A scan summary is printed to stderr after every run. Scans cancel gracefully on SIGINT/SIGTERM.

## See also

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [Config File](#/configuration/config-file) — configure exclusions and other defaults.
- [Ignoring Findings](#/configuration/ignoring-findings) — suppress known false positives.
- [How Verification Works](#/verification/how-verification-works) — understand verification statuses.
- [Filesystem](#/scanning/filesystem) — scan a local directory tree.
- [CLI Reference](#/reference/cli-reference) — full flag reference for all commands.
