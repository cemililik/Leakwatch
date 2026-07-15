---
title: "Dedektör Kataloğu"
description: "Kategorilere göre gruplanmış tüm 63 yerleşik dedektör; ID'leri, ne tespit ettikleri ve varsayılan şiddet seviyeleri ile."
---

# Dedektör Kataloğu

Leakwatch, bulut sağlayıcısı erişim anahtarlarından ve yapay zekâ API token'larından veritabanı bağlantı dizelerine ve özel kriptografik anahtarlara kadar geniş bir kimlik bilgisi türü yelpazesini kapsayan **63 yerleşik dedektör** ile gelir. Her dedektörün kararlı bir ID'si, varsayılan bir şiddet seviyesi ve (çoğu için) bulunan sırrın hâlâ canlı olup olmadığını teyit edebilen eşleştirilmiş bir doğrulayıcısı vardır.

Bu sayfa her yerleşik dedektörü listeler. Doğrulama kapsamı ayrıntıları için [Doğrulama Kapsamı](#/verification/verification-coverage) bölümüne bakın. Kendi kalıplarınızı eklemek için [Özel Kurallar](#/detectors/custom-rules) bölümüne bakın.

## Bu katalogu nasıl okuyacaksınız

- **ID** — yapılandırma ve çıktıda kullanılan kararlı dize tanımlayıcısı. Bir dedektörü atlamak için `filter.exclude-detectors` listesine ekleyin veya `--min-severity` filtrelemesiyle birlikte kullanın ([Şiddet ve Filtreleme](#/configuration/severity-and-filtering)).
- **Tespit eder** — dedektörün ne aradığı.
- **Şiddet** — `Critical` (Kritik), `High` (Yüksek) veya `Medium` (Orta). Bu varsayılandır; `--min-severity` bayrağını ve `output.severity-threshold` yapılandırma anahtarını besler.

---

## Bulut ve Altyapı

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `aws-access-key-id` | AWS Access Key ID | Critical |
| `gcp-service-account` | GCP Servis Hesabı Anahtarı | Critical |
| `azure-storage-key` | Azure Storage Bağlantı Dizesi | Critical |
| `azure-entra-secret` | Azure Entra ID İstemci Sırrı | Critical |
| `digitalocean-token` | DigitalOcean Kişisel Erişim Token'ı | Critical |
| `cloudflare-api-token` | Cloudflare API Token'ı | Critical |
| `heroku-api-key` | Heroku API Anahtarı | Critical |
| `vercel-token` | Vercel API Token'ı | High |
| `terraform-cloud-token` | Terraform Cloud/Enterprise API Token'ı | Critical |
| `hashicorp-vault-token` | HashiCorp Vault Token'ı | Critical |
| `doppler-token` | Doppler Servis Token'ı | Critical |

## Yapay Zekâ / Makine Öğrenimi

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `openai-api-key` | OpenAI API Anahtarı | Critical |
| `anthropic-api-key` | Anthropic API Anahtarı | Critical |
| `deepseek-api-key` | DeepSeek API Anahtarı | Critical |
| `huggingface-token` | Hugging Face API Token'ı | Critical |

## Ödemeler ve Ticaret

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `stripe-api-key-live` | Stripe Canlı API Anahtarı | Critical |
| `stripe-api-key-test` | Stripe Test API Anahtarı | High |
| `coinbase-api-key` | Coinbase API Anahtarı | Critical |
| `shopify-access-token` | Shopify Erişim Token'ı | Critical |

## Geliştirme Araçları, CI ve Paketler

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `github-token` | GitHub Kişisel Erişim Token'ı | Critical |
| `github-oauth-token` | GitHub OAuth2 ve kurulum (installation) token'ı — `gho_`/`ghu_`/`ghr_`/`ghs_`, yeni durumsuz (JWT biçimli) `ghs_` kurulum token'ları dâhil | Critical |
| `gitlab-pat` | GitLab Kişisel Erişim Token'ı | Critical |
| `bitbucket-app-password` | Bitbucket Uygulama Parolası | Critical |
| `circleci-token` | CircleCI Kişisel API Token'ı | High |
| `npm-token` | NPM Erişim Token'ı | High |
| `pypi-api-token` | PyPI API Token'ı | High |
| `rubygems-api-key` | RubyGems API Anahtarı | High |
| `dockerhub-pat` | Docker Hub Kişisel Erişim Token'ı | Critical |
| `sonarcloud-token` | SonarCloud/SonarQube Token'ı | High |
| `snyk-api-key` | Snyk API Anahtarı | High |
| `databricks-token` | Databricks Kişisel Erişim Token'ı | Critical |
| `launchdarkly-sdk-key` | LaunchDarkly SDK Anahtarı | High |

## İletişim ve İşbirliği

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `slack-token` | Slack Bot/Kullanıcı Token'ı | Critical |
| `slack-webhook` | Slack Webhook URL'si | High |
| `teams-webhook` | Microsoft Teams Gelen Webhook URL'si | High |
| `discord-bot-token` | Discord Bot Token'ı | Critical |
| `telegram-bot-token` | Telegram Bot Token'ı | High |
| `notion-token` | Notion Dahili Entegrasyon Token'ı | High |
| `linear-api-key` | Linear API Anahtarı | High |
| `figma-pat` | Figma Kişisel Erişim Token'ı | High |
| `airtable-pat` | Airtable Kişisel Erişim Token'ı | High |

## E-posta ve Mesajlaşma Teslimatı

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `sendgrid-api-key` | SendGrid API Anahtarı | Critical |
| `mailgun-api-key` | Mailgun API Anahtarı | Critical |
| `postmark-server-token` | Postmark Sunucu API Token'ı | High |
| `twilio-api-key` | Twilio API Anahtarı | Critical |

## İzleme ve Gözlemlenebilirlik

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `datadog-api-key` | Datadog API Anahtarı | Critical |
| `newrelic-api-key` | New Relic API Anahtarı | High |
| `grafana-api-key` | Grafana API Anahtarı | High |
| `sentry-token` | Sentry Kimlik Doğrulama Token'ı | High |
| `pagerduty-api-key` | PagerDuty API Anahtarı | High |

## Veritabanları ve Bağlantı Dizeleri

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `database-connection-string` | Veritabanı Bağlantı Dizesi | Critical |
| `redis-connection-string` | Redis Bağlantı Dizesi | Critical |
| `rabbitmq-connection-string` | RabbitMQ Bağlantı Dizesi | Critical |
| `snowflake-credentials` | Snowflake Bağlantı Kimlik Bilgileri | Critical |
| `supabase-service-key` | Supabase Servis Rolü Anahtarı | Critical |

## Kimlik ve Erişim

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `auth0-management-token` | Auth0 Yönetim API Token'ı | Critical |
| `okta-api-token` | Okta API Token'ı | Critical |
| `ldap-credentials` | LDAP/LDAPS Bağlama Kimlik Bilgileri | Critical |

## Web3

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `infura-api-key` | Infura API Anahtarı | High |

## Genel ve Kriptografik

| ID | Tespit eder | Şiddet |
|----|------------|--------|
| `generic-api-key` | Genel API Anahtarı | Medium |
| `jwt` | JSON Web Token | High |
| `private-key` | Özel Anahtar (RSA, SSH, DSA, EC, PGP) | Critical |
| `ftp-credentials` | FTP/SFTP Kimlik Bilgileri | Critical |

---

**Toplam: 63 yerleşik dedektör.**

## Şiddete göre filtreleme

Bulgular, komut satırında `--min-severity` veya yapılandırmada `output.severity-threshold` kullanılarak şiddet seviyesine göre filtrelenebilir. Yalnızca belirtilen seviyede veya üzerindeki bulgular çıktıya dahil edilir. Ayrıntılar için [Şiddet ve Filtreleme](#/configuration/severity-and-filtering) bölümüne bakın.

## Belirli dedektörleri hariç tutma

Bir veya daha fazla dedektörü tamamen atlamak için ID'lerini `.leakwatch.yaml` içindeki `filter.exclude-detectors` listesine ekleyin:

```yaml
filter:
  exclude-detectors:
    - generic-api-key
    - jwt
```

Tam filtreleme referansı için [Şiddet ve Filtreleme](#/configuration/severity-and-filtering) bölümüne bakın.

## Doğrulama kapsamı

Bazı dedektörlerin canlı doğrulayıcısı vardır; bazıları yalnızca format doğrulamasına tabi tutulur; dokuzu ise hiç doğrulayıcıya sahip değildir. Tam döküm için [Doğrulama Kapsamı](#/verification/verification-coverage) bölümüne bakın.

## Ayrıca bakın

- [Özel Kurallar](#/detectors/custom-rules) — YAML ile kendi tespit kalıplarınızı tanımlayın.
- [Doğrulama Kapsamı](#/verification/verification-coverage) — hangi dedektörlerin canlı doğrulanabileceği.
- [Şiddet ve Filtreleme](#/configuration/severity-and-filtering) — bulguları şiddet seviyesine veya dedektöre göre filtreleme.
