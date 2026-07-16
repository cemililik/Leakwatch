# Leakwatch - Cloud Storage Scanning Guide

> **Document Version:** 1.0
> **Date:** 2026-03-24
> **Status:** Approved

---

## Table of Contents

1. [Why Scan Cloud Storage?](#1-why-scan-cloud-storage)
2. [AWS S3 Scanning](#2-aws-s3-scanning)
3. [Google Cloud Storage Scanning](#3-google-cloud-storage-scanning)
4. [Parallel Repo Scanning](#4-parallel-repo-scanning)
5. [Large-Scale Scanning Strategies](#5-large-scale-scanning-strategies)
6. [Output and Reporting](#6-output-and-reporting)
7. [Security Best Practices](#7-security-best-practices)

---

## 1. Why Scan Cloud Storage?

Cloud storage services (AWS S3, Google Cloud Storage) are fundamental infrastructure components of modern applications. However, due to misconfiguration, careless usage, or automation errors, the risk of secrets leaking into these areas is high.

### Common Leak Scenarios

| Scenario | Description |
|----------|-------------|
| **Configuration files** | API keys in `.env`, `config.yaml`, `application.properties` files |
| **Log files** | Token and password leaks in error logs or debug outputs |
| **Backup archives** | Connection credentials in database backups |
| **CI/CD artifacts** | Embedded secrets in build outputs |
| **Code backups** | Source code uploaded to buckets but not committed to repositories |
| **Terraform state** | Plaintext secrets in `terraform.tfstate` files |

### Cloud Storage Scanning Flow

```mermaid
flowchart LR
    subgraph Sources["Cloud Storage"]
        S3["AWS S3"]
        GCS["Google Cloud Storage"]
    end

    subgraph Leakwatch["Leakwatch Scanning"]
        Auth["Authentication"]
        List["List Objects"]
        Filter["Filter"]
        Download["Download"]
        Scan["Secret Detection"]
    end

    subgraph Output["Reporting"]
        JSON["JSON"]
        SARIF["SARIF"]
        CSV["CSV"]
        Table["Table"]
    end

    Sources --> Auth --> List --> Filter --> Download --> Scan --> Output
```

---

## 2. AWS S3 Scanning

### 2.1 Authentication

Leakwatch uses the AWS SDK's standard credential chain. No additional configuration is required; your existing AWS credentials are used automatically.

```mermaid
flowchart TD
    A["Leakwatch S3 Scanning"] --> B["AWS SDK Credential Chain"]
    B --> C{"1. Environment Variables"}
    C -->|"Found"| G["Connect"]
    C -->|"Not Found"| D{"2. Shared Config<br/>~/.aws/credentials"}
    D -->|"Found"| G
    D -->|"Not Found"| E{"3. IAM Role<br/>(EC2/ECS/Lambda)"}
    E -->|"Found"| G
    E -->|"Not Found"| F["Error: Credentials not found"]

    style F fill:#ffe0e0,stroke:#cc0000
    style G fill:#e0ffe0,stroke:#00cc00
```

**Using environment variables:**

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=eu-west-1

leakwatch scan s3 my-bucket
```

**Using an AWS profile:**

```bash
# Use the profile from the ~/.aws/credentials file
export AWS_PROFILE=my-profile

leakwatch scan s3 my-bucket
```

**Using an IAM role (EC2/ECS/Lambda):**

If you are running on an EC2 instance, ECS task, or Lambda, the IAM role is used automatically. No additional configuration is required:

```bash
leakwatch scan s3 my-bucket
```

### 2.2 Basic Usage

```bash
# Scan all objects in the bucket
leakwatch scan s3 my-bucket

# Filter with a specific prefix
leakwatch scan s3 my-bucket --prefix "config/"

# Specify region
leakwatch scan s3 my-bucket --region eu-west-1

# Prefix and region together
leakwatch scan s3 my-bucket --prefix "deploy/prod/" --region us-east-1
```

### 2.3 Filtering with Prefix

The `--prefix` flag scans only objects that start with a specific prefix. This is a critical feature for targeting and speeding up scans in large buckets.

```bash
# Scan only configuration files
leakwatch scan s3 my-bucket --prefix "config/"

# Scan a specific environment folder
leakwatch scan s3 my-bucket --prefix "environments/production/"

# Scan Terraform state files
leakwatch scan s3 my-bucket --prefix "terraform/"
```

### 2.4 Specifying Region

You can specify the AWS region where the bucket is located using the `--region` flag. If not specified, it is taken from the AWS SDK's default configuration (`~/.aws/config` or `AWS_DEFAULT_REGION`).

```bash
# Bucket in the European region
leakwatch scan s3 eu-data-bucket --region eu-central-1

# Bucket in the US region
leakwatch scan s3 us-data-bucket --region us-west-2
```

### 2.5 IAM Policy Requirements

For Leakwatch to scan an S3 bucket, the IAM identity used must have the following minimum permissions:

| Permission | Description |
|------------|-------------|
| `s3:ListBucket` | To list objects in the bucket (also authorizes the `HeadBucket` access check Leakwatch performs at startup) |
| `s3:GetObject` | To read object contents |

> **Note:** There is no `s3:HeadBucket` IAM action. The `HeadBucket` API call is authorized by `s3:ListBucket`, so no extra permission is required for it.

**Example IAM Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LeakwatchS3ReadAccess",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

**To scan all buckets:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LeakwatchS3ReadAll",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ]
    }
  ]
}
```

> **Security note:** In production environments, keep the `Resource` field as narrow as possible. Using a wildcard (`*`) is only appropriate in organization-wide scanning scenarios.

---

## 3. Google Cloud Storage Scanning

### 3.1 Authentication

Leakwatch uses Google Cloud's Application Default Credentials (ADC) mechanism.

```mermaid
flowchart TD
    A["Leakwatch GCS Scanning"] --> B["Application Default Credentials"]
    B --> C{"1. GOOGLE_APPLICATION_CREDENTIALS<br/>environment variable"}
    C -->|"Found"| H["Connect"]
    C -->|"Not Found"| D{"2. gcloud auth<br/>application-default login"}
    D -->|"Found"| H
    D -->|"Not Found"| E{"3. Compute Engine<br/>Metadata Service"}
    E -->|"Found"| H
    E -->|"Not Found"| F{"4. GKE Workload<br/>Identity"}
    F -->|"Found"| H
    F -->|"Not Found"| G["Error: Credentials not found"]

    style G fill:#ffe0e0,stroke:#cc0000
    style H fill:#e0ffe0,stroke:#00cc00
```

**In a local development environment:**

```bash
# Interactive login
gcloud auth application-default login

# Scan
leakwatch scan gcs my-bucket
```

**Using a service account:**

```bash
# Service account key file
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json

leakwatch scan gcs my-bucket
```

**On GCE/GKE:**

If you are running on Compute Engine or GKE, the attached service account is used automatically:

```bash
leakwatch scan gcs my-bucket
```

### 3.2 Basic Usage

```bash
# Scan all objects in the bucket
leakwatch scan gcs my-bucket

# Filter with a specific prefix
leakwatch scan gcs my-bucket --prefix "secrets/"

# Specify project
leakwatch scan gcs my-bucket --project my-gcp-project

# Prefix and project together
leakwatch scan gcs my-bucket --prefix "config/prod/" --project my-gcp-project
```

### 3.3 Filtering with Prefix

As with S3, you can limit the scan to a specific object prefix using the `--prefix` flag:

```bash
# Scan configuration files
leakwatch scan gcs my-bucket --prefix "config/"

# Scan files for a specific application
leakwatch scan gcs my-bucket --prefix "apps/payment-service/"
```

### 3.4 Specifying Project

The `--project` flag specifies the GCP quota project. This is useful for service accounts that have access to multiple projects:

```bash
leakwatch scan gcs my-bucket --project my-billing-project
```

### 3.5 IAM Role Requirements

For Leakwatch to scan a GCS bucket, the IAM identity used must have the following permissions:

| Permission | Description |
|------------|-------------|
| `storage.buckets.get` | To access bucket metadata |
| `storage.objects.list` | To list objects in the bucket |
| `storage.objects.get` | To read object contents |

**Recommendation:** The predefined IAM role that includes these permissions is `roles/storage.objectViewer`. Additionally, `storage.buckets.get` permission is required for bucket metadata access; you can use `roles/storage.legacyBucketReader` or a custom role for this.

**Custom IAM role example:**

```yaml
title: Leakwatch Scanner
description: GCS bucket scanning with minimum permissions
stage: GA
includedPermissions:
  - storage.buckets.get
  - storage.objects.list
  - storage.objects.get
```

**Bucket-level IAM binding:**

```bash
# Grant objectViewer role to the service account on the bucket
gcloud storage buckets add-iam-policy-binding gs://my-bucket \
  --member="serviceAccount:leakwatch@my-project.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

---

## 4. Parallel Repo Scanning

### 4.1 The scan repos Command

The `scan repos` command scans multiple Git repositories concurrently. Each repository is independently cloned, scanned, and the results are merged into a single output.

```bash
# Scan two repositories in parallel
leakwatch scan repos \
  https://github.com/myorg/api-service.git \
  https://github.com/myorg/web-app.git

# Scan three repositories with 5 parallel workers
leakwatch scan repos \
  https://github.com/myorg/service-a.git \
  https://github.com/myorg/service-b.git \
  https://github.com/myorg/service-c.git \
  --parallel 5
```

### 4.2 The --parallel Flag

The `--parallel` flag determines the number of repositories to scan simultaneously. The default value is 3.

```bash
# Scan 10 repositories simultaneously
leakwatch scan repos repo1.git repo2.git ... repo10.git --parallel 10
```

> **Note:** `--parallel` controls concurrency at the repository level. `--concurrency` determines the number of workers within each repository. The total number of concurrent goroutines will be approximately `parallel * concurrency`.

```mermaid
flowchart TD
    A["leakwatch scan repos<br/>--parallel 3 --concurrency 4"] --> B["Semaphore (3 slots)"]

    B --> C["Repo 1"]
    B --> D["Repo 2"]
    B --> E["Repo 3"]
    B -.->|"Waiting"| F["Repo 4"]

    subgraph R1["Repo 1 Scanning"]
        C --> C1["Worker 1"]
        C --> C2["Worker 2"]
        C --> C3["Worker 3"]
        C --> C4["Worker 4"]
    end

    subgraph R2["Repo 2 Scanning"]
        D --> D1["Worker 1"]
        D --> D2["Worker 2"]
        D --> D3["Worker 3"]
        D --> D4["Worker 4"]
    end

    subgraph R3["Repo 3 Scanning"]
        E --> E1["Worker 1"]
        E --> E2["Worker 2"]
        E --> E3["Worker 3"]
        E --> E4["Worker 4"]
    end

    C1 --> G["Merge Results"]
    D1 --> G
    E1 --> G
    G --> H["Single Output"]

    style B fill:#f0f4ff,stroke:#4a6fa5
```

### 4.3 Usage Scenarios

**Organization-wide scanning:**

```bash
# List all repos in the organization using GitHub CLI and scan them
gh repo list myorg --limit 100 --json url -q '.[].url' | \
  xargs leakwatch scan repos --parallel 5 --format sarif --output org-scan.sarif
```

**Scanning a specific team's repositories:**

```bash
leakwatch scan repos \
  https://github.com/myorg/payment-api.git \
  https://github.com/myorg/payment-web.git \
  https://github.com/myorg/payment-worker.git \
  --parallel 3 \
  --only-verified \
  --format json \
  --output payment-team-scan.json
```

---

## 5. Large-Scale Scanning Strategies

### 5.1 Prefix-Based Partitioning

When scanning large buckets, use prefix-based partitioning to divide the scan into manageable chunks:

```bash
# Environment-based partitioning
leakwatch scan s3 my-bucket --prefix "prod/" --output prod-results.json
leakwatch scan s3 my-bucket --prefix "staging/" --output staging-results.json
leakwatch scan s3 my-bucket --prefix "dev/" --output dev-results.json
```

```bash
# Letter-based partitioning (for very large buckets)
for prefix in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
  leakwatch scan s3 my-bucket --prefix "${prefix}" --output "results-${prefix}.json"
done
```

### 5.2 File Size Optimization

Speed up scanning by skipping large files using the `--max-file-size` flag:

```bash
# Maximum 1 MB (log files and large configs will be skipped)
leakwatch scan s3 my-bucket --max-file-size 1048576

# Maximum 5 MB (lower than the default 10 MB)
leakwatch scan gcs my-bucket --max-file-size 5242880
```

### 5.3 Severity Filter

Reduce noise by filtering out low-severity findings using the `--min-severity` flag:

```bash
# Show only high and critical findings
leakwatch scan s3 my-bucket --min-severity high

# Show only critical findings
leakwatch scan gcs my-bucket --min-severity critical
```

### 5.4 Scanning Strategy Table

| Scenario | Recommendation |
|----------|----------------|
| **Small bucket (<1000 objects)** | Scan directly, no additional optimization needed |
| **Medium bucket (1000-100K objects)** | Targeted scanning with `--prefix`, set `--max-file-size` |
| **Large bucket (>100K objects)** | Prefix-based partitioning, parallel jobs, severity filter |
| **Multiple buckets** | Loop with shell script, collect results in separate files |
| **Organization-wide** | CI/CD pipeline, scheduled tasks, SARIF integration |

---

## 6. Output and Reporting

### 6.1 Supported Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| **JSON** | `--format json` | Automation, scripts, API integration |
| **SARIF** | `--format sarif` | GitHub Security, IDE integration |
| **CSV** | `--format csv` | Spreadsheet tools, Excel |
| **Table** | `--format table` | Human-readable output in the terminal |
| **GitHub** | `--format github` | Inline pull-request annotations in GitHub Actions |

### 6.2 Results in SARIF Format

SARIF (Static Analysis Results Interchange Format) is an industry-standard format for security scan results. It integrates directly with the GitHub Security tab.

```bash
# Generate SARIF output
leakwatch scan s3 my-bucket --format sarif --output s3-results.sarif

# Upload to GitHub (within GitHub Actions)
# uses: github/codeql-action/upload-sarif@v3
# with:
#   sarif_file: s3-results.sarif
```

**Example SARIF output (abbreviated):**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Leakwatch",
        "rules": [
          {
            "id": "aws-access-key-id",
            "shortDescription": { "text": "Secret detected by aws-access-key-id" },
            "defaultConfiguration": { "level": "error" }
          }
        ]
      }
    },
    "results": [{
      "ruleId": "aws-access-key-id",
      "ruleIndex": 0,
      "level": "error",
      "message": {
        "text": "Secret found: AKIA****XMPL"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "my-bucket/config/app.env"
          },
          "region": { "startLine": 12 }
        }
      }],
      "partialFingerprints": {
        "leakwatch/v1": "a1b2c3d4e5f6a7b8"
      }
    }]
  }]
}
```

### 6.3 Automated Processing with JSON

You can create custom reports by processing JSON output with tools like `jq`:

```bash
# Run the scan
leakwatch scan s3 my-bucket --format json --output results.json

# Filter high-severity findings
jq '[.[] | select(.severity == "high" or .severity == "critical")]' results.json

# Group by detector
jq 'group_by(.detector_id) | map({detector_id: .[0].detector_id, count: length})' results.json

# List file paths
jq -r '.[].source.file_path' results.json | sort -u
```

### 6.4 Periodic Scanning and Reporting

```mermaid
flowchart LR
    A["Scheduled Task<br/>(cron / CloudWatch)"] --> B["Leakwatch Scan"]
    B --> C["SARIF / JSON Output"]
    C --> D{"Findings Found?"}
    D -->|"Yes"| E["Send Notification<br/>(Slack / Email)"]
    D -->|"No"| F["Success Log"]
    E --> G["Archive Results"]
    F --> G
```

---

## 7. Security Best Practices

### 7.1 Principle of Least Privilege

- Create dedicated, read-only IAM roles/policies for Leakwatch.
- Restrict the `Resource` field to only the buckets to be scanned.
- Never grant write permissions (`s3:PutObject`, `storage.objects.create`).

### 7.2 Credential Security

| Practice | Description |
|----------|-------------|
| **Prefer environment variables** | Use temporary credentials instead of key files |
| **Use IAM roles** | Instance roles on EC2/GCE, task/workload identity on ECS/GKE |
| **Temporary credentials** | AWS STS `AssumeRole`, GCP service account impersonation |
| **Protect key files** | Do not add service account key files to version control |

### 7.3 Network Security

- Cloud storage scanning occurs over the network. If possible, run the scan **from within the same cloud provider** (inside a VPC/VPN).
- Use VPC endpoints (AWS) or Private Google Access to avoid routing traffic over the public internet.
- Consider bandwidth costs for large scans.

### 7.4 What to Do When a Secret Is Found

1. **Revoke the secret immediately:** Invalidate the key from the relevant provider (AWS IAM, GCP Console, etc.).
2. **Perform an impact analysis:** Determine how long the secret has been exposed and who had access.
3. **Update or delete the object:** Remove the file containing the secret from the bucket or update its contents.
4. **Versioning check:** If S3 versioning or GCS object versioning is enabled, clean up old versions as well.
5. **Root cause analysis:** Determine how the secret ended up in cloud storage and improve the process.
6. **Create an incident report:** Document the incident in accordance with your organization's security policy.

### 7.5 Preventive Measures

```mermaid
flowchart TD
    A["Preventive Measures"] --> B["Bucket Policy"]
    A --> C["CI/CD Integration"]
    A --> D["Monitoring"]

    B --> B1["Block sensitive file extensions<br/>with upload policies"]
    B --> B2["Restrict bucket access<br/>with least privilege"]

    C --> C1["Leakwatch scan<br/>before deployment"]
    C --> C2["Local checks with<br/>pre-commit hooks"]

    D --> D1["Periodic bucket scanning"]
    D --> D2["CloudTrail / Audit Log<br/>monitoring"]
```

---

## Related Documents

- [Architecture Design](../architecture/03-ARCHITECTURE.md)
- [Container Image Scanning Guide](container-scanning.md)
- [ADR-0003: Git Library](../decisions/ADR-0003-git-library.md)
- [Development Standards](../standards/04-DEVELOPMENT-STANDARDS.md)
- [Roadmap](../05-ROADMAP.md)
