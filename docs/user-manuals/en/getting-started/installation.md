---
title: "Installation"
description: "Install Leakwatch via Homebrew, go install, Docker, or a prebuilt binary."
---

# Installation

Getting Leakwatch onto your machine takes less than a minute. Choose the method that best fits your workflow: Homebrew is the simplest option on macOS and Linux, `go install` is ideal if you already have a Go toolchain, Docker keeps your host system clean, and prebuilt binaries work everywhere without any toolchain at all.

## Homebrew (macOS and Linux)

The official tap supports macOS and Linux on both amd64 and arm64.

```bash
brew install HodeTech/tap/leakwatch
```

The tap is hosted at [github.com/HodeTech/homebrew-tap](https://github.com/HodeTech/homebrew-tap). Homebrew handles upgrades with `brew upgrade leakwatch`.

## Go install

If you have Go 1.25 or later installed, you can build and install the latest release directly from source:

```bash
go install github.com/HodeTech/leakwatch@latest
```

The binary is placed in `$(go env GOPATH)/bin`. Make sure that directory is on your `PATH`.

:::note
`go install` always fetches the latest tagged release. To pin a specific version, replace `@latest` with the current release tag, `@v1.7.0`.
:::

## Docker

A minimal, multi-stage Alpine image is published to the GitHub Container Registry. The image runs as a non-root user (`leakwatch`), has CGO disabled, and uses `/scan` as its working directory.

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

Available tags:

| Tag | Description |
|-----|-------------|
| `:latest` | Most recent release |
| `:v1.7.0` | Exact current-release pin |
| `:v1.7` | Current minor-version pin (tracks patch releases) |

Mount the directory you want to scan to `/scan` inside the container. Flags and options work identically to the native binary — see [CLI Reference](#/reference/cli-reference) for the full list.

:::tip
For Docker-specific usage patterns, including scanning remote Git repositories and passing credentials securely, see [Using Docker](#/ci-cd/docker-usage).
:::

## Prebuilt binary

Every release publishes tarballs for all supported platforms on the [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases) page. Download the archive for your platform, extract it, and place the binary on your `PATH`.

**Supported platforms:** Linux, macOS, and Windows on amd64 and arm64.

```bash
# Example for Linux amd64 — replace OS and ARCH to match your platform
curl -LO https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_amd64.tar.gz
tar -xzf leakwatch_Linux_amd64.tar.gz
sudo mv leakwatch /usr/local/bin/leakwatch
```

Platform naming follows the pattern `leakwatch_<OS>_<ARCH>.tar.gz` where `<OS>` is `Linux`, `Darwin`, or `Windows` and `<ARCH>` is `amd64` or `arm64`.

:::tip
Every release also publishes a Software Bill of Materials (SBOM) for each archive and a [Sigstore/cosign](https://github.com/sigstore/cosign) keyless signature (`checksums.txt.sig` / `checksums.txt.pem`) over the release's checksums file, so the provenance of a downloaded binary can be verified in supply-chain-sensitive environments.
:::

## Verifying your installation

After any installation method, confirm the binary is reachable and check the version:

```bash
leakwatch version
```

Expected output:

```text
leakwatch v1.7.0 (commit: 1a2b3c4, built: 2026-07-20T19:44:14Z)
```

If the command is not found, check that the install directory is on your `PATH`.

## Next steps

- [Quick Start](#/getting-started/quick-start) — run your first scan in under a minute.
- [How It Works](#/getting-started/how-it-works) — the architecture behind a Leakwatch scan.
- [Configuration File](#/configuration/config-file) — customize scan behavior with `.leakwatch.yaml`.

## See also

- [Quick Start](#/getting-started/quick-start)
- [Using Docker](#/ci-cd/docker-usage)
- [CLI Reference](#/reference/cli-reference)
- [Configuration File](#/configuration/config-file)
