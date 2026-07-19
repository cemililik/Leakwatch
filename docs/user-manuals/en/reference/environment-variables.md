---
title: "Environment Variables"
description: "Environment variables that configure Leakwatch behavior without flags."
---

# Environment Variables

Leakwatch reads configuration from three sources in priority order: **command-line flags** override **environment variables**, which override the **config file** (`.leakwatch.yaml`), which falls back to built-in **defaults**. Environment variables are useful in CI environments where you cannot modify a config file or pass flags to every invocation.

## Configuration variable pattern

Any key from `.leakwatch.yaml` can be set as an environment variable by:

1. Uppercasing the key name.
2. Replacing `.` and `-` with `_`.
3. Prepending `LEAKWATCH_`.

For example, the config key `scan.concurrency` becomes `LEAKWATCH_SCAN_CONCURRENCY`.

## Variable reference

### Leakwatch-specific variables

| Variable | Description |
|----------|-------------|
| `LEAKWATCH_SLACK_TOKEN` | Slack bot token for `scan slack`. Equivalent to `--token`. Set this instead of passing the token as a flag to avoid it appearing in shell history or CI logs. |
| `LEAKWATCH_SCAN_CONCURRENCY` | Number of concurrent scan workers. Equivalent to `--concurrency`. |
| `LEAKWATCH_VERIFICATION_ENABLED` | Set to `false` to disable live verification globally. Equivalent to `--no-verify`. |
| `LEAKWATCH_VERIFICATION_RATE_LIMIT` | Maximum verification requests per second across all verifiers. |
| `LEAKWATCH_OUTPUT_FORMAT` | Default output format (`json`, `sarif`, `csv`, `table`, or `github`). Equivalent to `--format`. |
| `LEAKWATCH_DETECTION_ENTROPY_THRESHOLD` | Minimum Shannon entropy for a match to be reported. Float value, e.g. `3.5`. |

### Display variable

| Variable | Description |
|----------|-------------|
| `NO_COLOR` | When set to any non-empty value, disables ANSI color codes in the `table` output formatter. Follows the [no-color.org](https://no-color.org) convention. |

### AWS variables (for `scan s3` and AWS secret verification)

These are standard AWS SDK environment variables. Leakwatch passes them through to the AWS SDK v2 default credential chain.

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID. |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key. |
| `AWS_SESSION_TOKEN` | AWS session token (for temporary credentials). |
| `AWS_REGION` | Default AWS region. |
| `AWS_PROFILE` | Named profile from `~/.aws/credentials` to use. |

### GCS variable (for `scan gcs`)

| Variable | Description |
|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to a Google service-account JSON key file. Used by Application Default Credentials when scanning a GCS bucket. |

## Precedence example

Given this setup:

- `.leakwatch.yaml` sets `output.format: table`
- `LEAKWATCH_OUTPUT_FORMAT=json` is set in the environment
- The command is run as `leakwatch scan fs .` (no `--format` flag)

The effective format is `json` because the environment variable overrides the config file.

If the command is run as `leakwatch scan fs . --format sarif`, the effective format is `sarif` because the flag overrides everything.

## Credentials for verification vs. credentials for scanning

:::note
The AWS and GCP variables above are consumed to **authenticate Leakwatch itself** when it connects to S3 or GCS to retrieve objects for scanning. They are not used to verify found secrets. Verification of a discovered AWS key, for example, uses that discovered key itself to call AWS STS — not the runner's credentials.
:::

## Passing secrets safely in CI

In GitHub Actions, use encrypted secrets:

```yaml
env:
  LEAKWATCH_SLACK_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
```

In GitLab CI, use masked CI/CD variables:

```yaml
variables:
  LEAKWATCH_SLACK_TOKEN: $SLACK_BOT_TOKEN   # defined as a masked variable in project settings
```

Never hard-code token values in workflow files or Dockerfiles.

## See also

- [Configuration File](#/configuration/config-file) — full `.leakwatch.yaml` key reference.
- [Cloud Storage Scanning](#/scanning/cloud-storage) — `scan s3` and `scan gcs` credentials.
- [Slack Scanning](#/scanning/slack) — Slack token scopes and permissions.
- [CLI Reference](#/reference/cli-reference) — equivalent command-line flags.
