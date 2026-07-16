---
title: "Other CI Systems"
description: "Integrate Leakwatch into GitLab CI, Jenkins, Bitbucket Pipelines, and any other CI system."
---

# Other CI Systems

Because Leakwatch is a single static binary with no runtime dependencies, it runs in any CI environment that can execute a shell command — GitLab CI, Jenkins, Bitbucket Pipelines, CircleCI, Azure DevOps, and others. There is no built-in integration for these systems beyond what is described on this page; the pattern is always: install the binary, run the scan, act on the exit code.

## Installing Leakwatch in CI

Choose the method that best suits your runner environment:

### via `go install` (requires Go on the runner)

```bash
go install github.com/HodeTech/leakwatch@latest
```

Pin to a specific version for reproducible builds:

```bash
go install github.com/HodeTech/leakwatch@v1.5.0
```

### via the Docker image (no Go required)

Use `ghcr.io/hodetech/leakwatch:latest` as a job image or run it with `docker run`. See [Docker Usage](#/ci-cd/docker-usage) for the full pattern.

### via a prebuilt release binary

Download the appropriate tarball from [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases), extract, and place on `PATH`:

```bash
curl -LO https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_amd64.tar.gz
tar -xzf leakwatch_Linux_amd64.tar.gz
sudo mv leakwatch /usr/local/bin/leakwatch
```

## Exit codes

Leakwatch exits with one of four codes, which is the primary mechanism for failing a CI build:

| Code | Meaning | Recommended CI action |
|------|---------|----------------------|
| `0` | No findings | Pass the pipeline stage |
| `1` | Secrets found | Fail the pipeline stage |
| `2` | Hard error (bad config, unreadable path, etc.) | Fail the pipeline stage |
| `3` | Interrupted (`Ctrl+C` / `SIGTERM`) before completing, with no findings reported | Fail the pipeline stage — the scan did not run to completion, so a clean result cannot be trusted |

A generic shell snippet that branches on the exit code:

```bash
set +e
leakwatch scan fs . --format json -o leakwatch.json --no-verify
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "No secrets found."
elif [ "$EXIT_CODE" -eq 1 ]; then
  echo "Secrets found — failing build."
  exit 1
else
  echo "Scan error or interruption (exit $EXIT_CODE) — failing build."
  exit "$EXIT_CODE"
fi
```

## GitLab CI example

The following `.gitlab-ci.yml` job installs Leakwatch, runs a filesystem scan, and stores the JSON report as a pipeline artifact:

```yaml
leakwatch:
  stage: test
  image: golang:1.25-alpine
  script:
    - go install github.com/HodeTech/leakwatch@v1.5.0
    - leakwatch scan fs . --format json -o leakwatch.json --no-verify
  artifacts:
    when: always
    paths:
      - leakwatch.json
    expire_in: 7 days
  allow_failure: false
```

`allow_failure: false` (the default) means exit code `1` fails the pipeline stage. Set `allow_failure: true` if you want the scan to report without blocking the merge.

:::tip
GitLab supports SAST report artifacts. Leakwatch produces SARIF (`--format sarif`), not GitLab's native SAST JSON schema, so use the `paths:` artifact approach rather than the `reports: sast:` key.
:::

## Recommendations for CI runners

**Use `--no-verify` on runners without outbound internet access.** Verification makes live API calls to providers (AWS, GitHub, Stripe, etc.). On air-gapped or firewall-restricted runners, these calls time out and slow the scan. Pass `--no-verify` to skip verification entirely:

```bash
leakwatch scan fs . --no-verify --format sarif -o results.sarif
```

**Save output as an artifact.** Use `--format sarif` or `--format json` with `--output` to write a file that can be stored, uploaded to a vulnerability management platform, or reviewed after the job completes.

**Set `--min-severity`** to focus on the secrets that matter most. In a noisy codebase, start with `--min-severity high` and lower the threshold once you have cleared the backlog.

## Azure DevOps example

```yaml
- script: |
    go install github.com/HodeTech/leakwatch@v1.5.0
    leakwatch scan fs . --format sarif -o $(Build.ArtifactStagingDirectory)/leakwatch.sarif --no-verify
  displayName: "Leakwatch secret scan"

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: "$(Build.ArtifactStagingDirectory)"
    artifactName: "leakwatch-results"
```

## Jenkins example

```groovy
stage('Secret scan') {
    steps {
        sh '''
            go install github.com/HodeTech/leakwatch@v1.5.0
            leakwatch scan fs . --format json -o leakwatch.json --no-verify
        '''
        archiveArtifacts artifacts: 'leakwatch.json', allowEmptyArchive: true
    }
}
```

## See also

- [Exit Codes](#/reference/exit-codes) — full reference for all exit code meanings.
- [Output Formats](#/output/output-formats) — JSON, SARIF, CSV, table, and GitHub annotation output.
- [Docker Usage](#/ci-cd/docker-usage) — use the container image instead of installing the binary.
- [GitHub Action](#/ci-cd/github-action) — the official action for GitHub workflows.
