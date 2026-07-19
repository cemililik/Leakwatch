# Leakwatch - Docker Usage Guide

> **Document Version:** 1.0
> **Date:** 2026-03-24
> **Status:** Approved

---

## 1. Quick Start

Leakwatch is available as a container image from GitHub Container Registry. No installation required -- just `docker run`.

```bash
# Pull the latest image
docker pull ghcr.io/hodetech/leakwatch:latest
```

### Scan a Local Directory (Filesystem)

```bash
docker run --rm -v "$(pwd):/scan" ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

### Scan a Remote Git Repository

```bash
docker run --rm ghcr.io/hodetech/leakwatch:latest scan git https://github.com/org/repo.git
```

### Scan a Local Git Repository

```bash
docker run --rm -v "/path/to/repo:/scan" ghcr.io/hodetech/leakwatch:latest scan git /scan
```

### Scan a Container Image

```bash
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image nginx:latest
```

### Scan an S3 Bucket

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_REGION=us-east-1 \
  ghcr.io/hodetech/leakwatch:latest scan s3 my-bucket --prefix prefix/
```

### Scan a GCS Bucket

```bash
docker run --rm \
  -v "$HOME/.config/gcloud:/home/leakwatch/.config/gcloud:ro" \
  ghcr.io/hodetech/leakwatch:latest scan gcs my-bucket --prefix prefix/
```

### Scan Summary

Every scan prints a summary to stderr showing source, duration, file count, and findings count. When writing output to a file with `--output`, the summary still appears in the terminal:

```bash
docker run --rm -v "$(pwd):/scan:ro" ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

```
── Scan Summary ─────────────────────────────────
  Date:            2026-04-08 14:22:00
  Source:          filesystem
  Target:          /scan
  Files scanned:   934
  Duration:        1.87s
  Findings:        2
─────────────────────────────────────────────────
```

---

## 2. Volume Mounting

When scanning local files or repositories, you must mount the host directory into the container using the `-v` flag.

```mermaid
flowchart LR
    subgraph Host["Host Machine"]
        H1["/path/to/project"]
        H2["Output file"]
    end

    subgraph Container["Docker Container"]
        C1["/scan"]
        C2["/output"]
        LW["leakwatch"]
    end

    H1 -->|"-v /path/to/project:/scan"| C1
    C1 --> LW
    LW --> C2
    C2 -->|"-v /tmp/results:/output"| H2
```

### Read-Only Mount (Recommended)

For filesystem scans, mount the source directory as read-only for an additional layer of security:

```bash
docker run --rm \
  -v "/path/to/project:/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

### Writing Output to Host

To save scan results to a file on the host, mount an output directory:

```bash
docker run --rm \
  -v "$(pwd):/scan:ro" \
  -v "/tmp/results:/output" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan \
    --format sarif --output /output/results.sarif
```

The results file will be available at `/tmp/results/results.sarif` on the host.

---

## 3. Scanning Remote Repositories

When scanning remote Git repositories, no volume mount is needed. Leakwatch clones the repository inside the container:

```bash
# Full history scan
docker run --rm ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git

# Shallow clone for faster scanning
docker run --rm ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git --depth 50

# Specific branch
docker run --rm ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git --branch main
```

For private repositories that require authentication, pass credentials via environment variables or mount an SSH key:

```bash
# HTTPS with token embedded in the URL.
# Leakwatch uses go-git, which reads credentials from the URL's user-info part;
# it does NOT honor git-CLI variables such as GIT_ASKPASS / GIT_PASSWORD.
# The display URL is credential-stripped in logs and output.
docker run --rm \
  ghcr.io/hodetech/leakwatch:latest \
  scan git https://x-access-token:ghp_xxxxxxxxxxxx@github.com/org/private-repo.git

# SSH key mount
docker run --rm \
  -v "$HOME/.ssh:/home/leakwatch/.ssh:ro" \
  ghcr.io/hodetech/leakwatch:latest \
  scan git git@github.com:org/private-repo.git
```

> **Tip:** Embedding the token in the command line can expose it in shell history
> and process listings. In CI, prefer injecting it through a masked secret, e.g.
> `scan git https://x-access-token:${GIT_TOKEN}@github.com/org/private-repo.git`.

---

## 4. Scanning Container Images

Leakwatch scans container images using `go-containerregistry` and does **not** require a running Docker daemon.

### Remote Images (Direct from Registry)

No special configuration needed. Leakwatch pulls and analyzes image layers directly:

```bash
# Docker Hub
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image nginx:latest

# GHCR
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image ghcr.io/org/app:v1.2.3

# ECR
docker run --rm ghcr.io/hodetech/leakwatch:latest scan image \
  123456789.dkr.ecr.eu-west-1.amazonaws.com/my-app:latest
```

### Local Images

The `scan image` command uses `go-containerregistry`'s `remote.Image` to pull images directly from registries. It does **not** interact with a local Docker daemon, so scanning a locally-built image requires pushing it to a registry first (or using a local registry such as `registry:2`):

```bash
# Option 1: push to a local registry and scan from there
docker run -d -p 5000:5000 --name registry registry:2
docker tag my-local-app:dev localhost:5000/my-local-app:dev
docker push localhost:5000/my-local-app:dev
leakwatch scan image localhost:5000/my-local-app:dev

# Option 2: scan directly from GHCR or another remote registry after pushing
docker tag my-local-app:dev ghcr.io/myorg/my-local-app:dev
docker push ghcr.io/myorg/my-local-app:dev
leakwatch scan image ghcr.io/myorg/my-local-app:dev
```

> **Note:** Mounting the Docker socket (`/var/run/docker.sock`) is not needed and not supported by the container source. The daemonless design is intentional — it avoids the privilege escalation risk associated with Docker socket access.

### Private Registry Authentication

For private registries, mount your Docker config:

```bash
docker run --rm \
  -v "$HOME/.docker/config.json:/home/leakwatch/.docker/config.json:ro" \
  ghcr.io/hodetech/leakwatch:latest scan image registry.example.com/team/service:main
```

---

## 5. Environment Variables

### AWS Credentials

Pass AWS credentials for S3 scanning or AWS secret verification:

```bash
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_REGION=us-east-1 \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

Alternatively, mount the AWS credentials file:

```bash
docker run --rm \
  -v "$HOME/.aws:/home/leakwatch/.aws:ro" \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan
```

### GCP Credentials

For GCS scanning, mount the Application Default Credentials or set the service account key:

```bash
# Application Default Credentials
docker run --rm \
  -v "$HOME/.config/gcloud:/home/leakwatch/.config/gcloud:ro" \
  ghcr.io/hodetech/leakwatch:latest scan gcs my-bucket

# Service account key
docker run --rm \
  -e GOOGLE_APPLICATION_CREDENTIALS=/creds/sa-key.json \
  -v "/path/to/sa-key.json:/creds/sa-key.json:ro" \
  ghcr.io/hodetech/leakwatch:latest scan gcs my-bucket
```

### Verification Control

```bash
# Disable verification (no outbound API calls)
docker run --rm \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --no-verify

# Only show verified active secrets
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --only-verified
```

---

## 6. Docker Compose Examples

### Scanning a Project as a Service

```yaml
services:
  leakwatch:
    image: ghcr.io/hodetech/leakwatch:latest
    volumes:
      - ./:/scan:ro
      - ./reports:/output
    command: scan fs /scan --format sarif --output /output/results.sarif
```

Run with:

```bash
docker compose run --rm leakwatch
```

### Scanning with Verification Enabled

```yaml
services:
  leakwatch:
    image: ghcr.io/hodetech/leakwatch:latest
    volumes:
      - ./:/scan:ro
      - ./reports:/output
    environment:
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
      - AWS_REGION=us-east-1
    command: scan git /scan --only-verified --format json --output /output/results.json
```

### Multi-Repository Scanning

```yaml
services:
  scan-api:
    image: ghcr.io/hodetech/leakwatch:latest
    volumes:
      - ../api-service:/scan:ro
      - ./reports:/output
    command: scan fs /scan --format json --output /output/api-results.json

  scan-web:
    image: ghcr.io/hodetech/leakwatch:latest
    volumes:
      - ../web-app:/scan:ro
      - ./reports:/output
    command: scan fs /scan --format json --output /output/web-results.json
```

Run all scans in parallel:

```bash
docker compose up --abort-on-container-exit
```

---

## 7. CI/CD with Docker

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Leakwatch
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/scan:ro" \
            ghcr.io/hodetech/leakwatch:latest \
            scan git /scan --since-commit HEAD~1 \
              --only-verified --min-severity high \
              --format sarif --output /dev/stdout > results.sarif

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
secret-scan:
  stage: test
  image: ghcr.io/hodetech/leakwatch:latest
  script:
    - leakwatch scan git . --since-commit HEAD~1 --min-severity high --format json --output results.json
  artifacts:
    paths:
      - results.json
    when: always
  allow_failure: false
```

### Jenkins (Declarative Pipeline)

```groovy
pipeline {
    agent any
    stages {
        stage('Secret Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v "${WORKSPACE}:/scan:ro" \
                      ghcr.io/hodetech/leakwatch:latest \
                      scan fs /scan --min-severity high --format table
                '''
            }
        }
    }
}
```

---

## 8. Image Details

### Base Image and Build

The Leakwatch Docker image uses a multi-stage build:

| Stage | Image | Purpose |
|-------|-------|---------|
| Builder | `golang:1.25-alpine` | Compiles the Go binary with `CGO_ENABLED=0` |
| Runtime | `alpine:3.20` | Minimal runtime with `ca-certificates` and `git` |

### Security Features

- **Non-root user** -- The container runs as the `leakwatch` user, not root.
- **Minimal attack surface** -- Only `ca-certificates` and `git` are installed in the runtime image.
- **Static binary** -- Built with `CGO_ENABLED=0` and stripped (`-ldflags="-s -w"`), resulting in a small, self-contained binary.
- **Working directory** -- Default working directory is `/scan`.

### Image Size

The runtime image is optimized for size. The Alpine base and stripped binary keep the total image size small (typically under 50 MB).

---

## 9. Building a Custom Image

You can extend the Leakwatch Dockerfile for custom needs.

### Adding Custom Rules

There is no standalone rules file. Custom rules are defined under the
`custom-rules:` key of a `.leakwatch.yaml` config file (see the
[Custom Rules Guide](./custom-rules.md)). Bake them in by copying a config that
contains them to the home directory, which Leakwatch loads as the global config:

```dockerfile
FROM ghcr.io/hodetech/leakwatch:latest

# .leakwatch.yaml here must include the custom rules under `custom-rules:`
COPY .leakwatch.yaml /home/leakwatch/.leakwatch.yaml
```

### Adding a Custom Configuration

Leakwatch searches for `.leakwatch.yaml` in the working directory and then in the
home directory (`~/.leakwatch.yaml`). Copy your config to the home directory so it
applies to every scan regardless of the mounted working directory:

```dockerfile
FROM ghcr.io/hodetech/leakwatch:latest

COPY .leakwatch.yaml /home/leakwatch/.leakwatch.yaml
```

Alternatively, point at a config explicitly with `--config`:

```bash
docker run --rm \
  -v "$(pwd):/scan:ro" \
  -v "$(pwd)/.leakwatch.yaml:/cfg/.leakwatch.yaml:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --config /cfg/.leakwatch.yaml
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/HodeTech/Leakwatch.git
cd Leakwatch

# Build the Docker image
docker build -t leakwatch:custom .

# Run with your custom build
docker run --rm -v "$(pwd):/scan:ro" leakwatch:custom scan fs /scan
```

---

## 10. Docker Scan Workflow

```mermaid
flowchart TD
    subgraph Host["Host Machine"]
        SRC["Source\n(files, repo, credentials)"]
        OUT["Output\n(JSON, SARIF, CSV)"]
    end

    subgraph Docker["Docker Container (alpine)"]
        subgraph LW["Leakwatch Process (non-root)"]
            CMD["CLI Command\n(scan fs/git/image/s3/gcs)"]
            ENG["Detection Engine\n(Aho-Corasick + Regex + Entropy)"]
            VER["Verification Engine\n(54 verifiers (51 packages), 84.4% coverage)"]
            FMT["Output Formatter"]
        end
    end

    subgraph External["External Services"]
        REG["Container Registry\n(Docker Hub, GHCR, ECR)"]
        S3["AWS S3 / GCS"]
        VAPI["Verification APIs\n(STS, GitHub)"]
    end

    SRC -->|"Volume mount (-v)"| CMD
    CMD --> ENG
    ENG -->|Findings| VER
    VER -->|"HTTPS"| VAPI
    VER --> FMT
    FMT -->|"Volume mount"| OUT
    CMD -->|"Network"| REG
    CMD -->|"Network"| S3
```

---

## 11. Performance Tips

### Use tmpfs for Temporary Directories

When scanning remote Git repositories, Leakwatch clones them to a temporary directory. Using `tmpfs` keeps this in memory for faster I/O:

```bash
docker run --rm \
  --tmpfs /tmp:size=1g \
  ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git
```

### Set Resource Limits

Prevent the container from consuming excessive resources:

```bash
docker run --rm \
  --memory=512m \
  --cpus=2 \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --concurrency 2
```

### Match Concurrency to Available CPUs

The `--concurrency` flag should match the CPUs allocated to the container:

```bash
docker run --rm \
  --cpus=4 \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --concurrency 4
```

### Skip Verification for Speed

If you only need detection without verification (e.g., in a pre-commit hook), skip the verification phase:

```bash
docker run --rm \
  -v "$(pwd):/scan:ro" \
  ghcr.io/hodetech/leakwatch:latest scan fs /scan --no-verify
```

---

## 12. Next Steps

| Topic | Document |
|-------|----------|
| Getting started with Leakwatch | [Getting Started Guide](./getting-started.md) |
| Secret verification details | [Secret Verification Guide](./secret-verification.md) |
| Configuration file and options | [Configuration Guide](./configuration.md) |
| Architecture overview | [Architecture Document](../architecture/03-ARCHITECTURE.md) |
