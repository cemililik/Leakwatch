---
title: "Docker Usage"
description: "Run Leakwatch scans inside a container using the official Docker image."
---

# Docker Usage

The official Leakwatch container image lets you run scans without installing anything on the host machine. Because the image is statically compiled with `CGO_ENABLED=0` and runs as a non-root user, it is safe to use in locked-down CI environments and on shared machines where you do not want to modify the host system.

## Image reference

```text
ghcr.io/hodetech/leakwatch
```

| Tag | Description |
|-----|-------------|
| `:latest` | Most recent release |
| `:v1.7.0` | Exact current-release pin |
| `:v1.7` | Current minor-version pin (tracks patch releases) |

The image is based on Alpine, runs as the non-root user `leakwatch`, uses `/scan` as the working directory, and has `leakwatch` as its entrypoint.

:::note
Because the entrypoint is `leakwatch`, you append the subcommand and flags directly after the image name — for example, `ghcr.io/hodetech/leakwatch:latest scan fs /scan`. There is no need to repeat the binary name.
:::

## Scanning a local directory

Mount the directory you want to scan to `/scan` inside the container:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

To write results to a file on the host, write the output file into the mounted volume:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --format sarif -o /scan/leakwatch.sarif
```

The file `leakwatch.sarif` appears in the current directory on your host after the container exits.

## Scanning a remote Git repository

```bash
docker run --rm \
  ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git --format json
```

No volume mount is required for remote Git repositories — Leakwatch clones them into a temporary directory inside the container.

## Scanning a container image

Leakwatch is daemonless: it pulls image layers directly from the registry without a Docker daemon. This means you can scan a remote image from within the Leakwatch container without mounting the host Docker socket:

```bash
docker run --rm \
  ghcr.io/hodetech/leakwatch:latest \
  scan image registry.example.com/my-app:v2.3.0
```

For private registries, pass the credentials as environment variables consumed by the registry client (for example, `DOCKER_CONFIG` pointing to a mounted credentials file, or the standard registry environment variables your registry supports).

## Passing a configuration file

Mount `.leakwatch.yaml` into `/scan` so Leakwatch picks it up automatically:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

As long as `.leakwatch.yaml` is in the mounted directory, Leakwatch finds it because `/scan` is both the working directory and the path passed to the scan. If your config file lives elsewhere, mount it explicitly and use `--config`:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v "/path/to/custom-config.yaml:/config/leakwatch.yaml:ro" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --config /config/leakwatch.yaml
```

## Passing environment variables

Environment variables for cloud scanning and token-based authentication can be injected with `-e`:

```bash
# S3 scan with AWS credentials
docker run --rm \
  -e AWS_ACCESS_KEY_ID=AKIA••••••••••••EXAMPLE \
  -e AWS_SECRET_ACCESS_KEY=••••••••••••••••••••••••••••••••••••••• \
  -e AWS_REGION=us-east-1 \
  ghcr.io/hodetech/leakwatch:latest \
  scan s3 my-bucket
```

For CI environments, prefer injecting secrets as masked CI variables rather than embedding them in the command line.

## Output file pattern

A common Docker pattern in CI is to write results into the mounted volume and then upload or archive the file as a pipeline artifact:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan \
    --format json \
    --only-verified \
    -o /scan/leakwatch-results.json
```

## See also

- [Installation](#/getting-started/installation) — install the native binary instead of using Docker.
- [Filesystem Scanning](#/scanning/filesystem) — `scan fs` flags and behavior.
- [Container Images](#/scanning/container-images) — scanning OCI/Docker image layers for secrets.
- [Other CI Systems](#/ci-cd/other-ci) — using the Docker image in GitLab CI and other pipelines.
- [CLI Reference](#/reference/cli-reference) — complete flag reference for all subcommands.
