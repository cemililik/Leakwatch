---
title: "Doğrulama Kapsamı"
description: "64 yerleşik dedektörün hangilerinin canlı doğrulandığı, yalnızca format doğrulandığı veya doğrulanamaz olduğu ve bunun önceliklendirme açısından ne anlama geldiği."
---

# Doğrulama Kapsamı

Leakwatch 64 yerleşik dedektör ve 54 doğrulayıcı ile gelir; bu, **%84,4** kapsama oranı sağlar (64 dedektör türünden 54'ünde bir tür doğrulama mevcuttur — canlı ya da yalnızca format). Bu sayfa, çıktınızda ne beklemeniz gerektiğini bilmeniz için her dedektörü doğrulama durumuna göre eşler.

## Canlı doğrulanan (48 dedektör türü)

Bu türler için Leakwatch, sağlayıcıya kontrollü, salt-okunur bir API çağrısı yapar ve `verified_active` ya da `verified_inactive` döndürür. Hiçbir veri oluşturulmaz veya değiştirilmez; çağrı, kimliği doğrulamak için gereken minimum uç noktayı kullanır.

| Dedektör türü | Sağlayıcı |
|--------------|----------|
| `aws-access-key-id` | AWS STS (`GetCallerIdentity`) |
| `github-token` | GitHub REST API |
| `github-oauth-token` | GitHub REST API |
| `gitlab-pat` | GitLab REST API (token ile birlikte yakalanan kendi barındırılan bir GitLab sunucusu varsa onu hedefler; yoksa gitlab.com'a geri döner) |
| `slack-token` | Slack Web API |
| `openai-api-key` | OpenAI API |
| `anthropic-api-key` | Anthropic API |
| `deepseek-api-key` | DeepSeek API |
| `huggingface-token` | Hugging Face API |
| `sendgrid-api-key` | SendGrid Web API (kapsamı daraltılmış/kısıtlı bir anahtardan gelen `403` yanıtı, anahtarın kendisi geçerli olduğundan inaktif değil `verified_active` olarak değerlendirilir — yalnızca `401` `verified_inactive` olarak eşlenir) |
| `mailgun-api-key` | Mailgun API (doğru AB veya ABD bölgesel uç noktasını otomatik olarak tespit edip çağırır) |
| `postmark-server-token` | Postmark API |
| `stripe-api-key-live` | Stripe API |
| `stripe-api-key-test` | Stripe API |
| `digitalocean-token` | DigitalOcean API |
| `cloudflare-api-token` | Cloudflare API |
| `heroku-api-key` | Heroku Platform API |
| `vercel-token` | Vercel REST API |
| `npm-token` | npm Registry API |
| `pypi-api-token` | PyPI API |
| `rubygems-api-key` | RubyGems API |
| `dockerhub-pat` | Docker Hub API |
| `circleci-token` | CircleCI API |
| `terraform-cloud-token` | Terraform Cloud API |
| `discord-bot-token` | Discord API |
| `telegram-bot-token` | Telegram Bot API |
| `sentry-token` | Sentry API |
| `pagerduty-api-key` | PagerDuty API |
| `newrelic-api-key` | New Relic API |
| `grafana-api-key` | Grafana API |
| `datadog-api-key` | Datadog API |
| `snyk-api-key` | Snyk API |
| `twilio-api-key` | Twilio API (API Key Secret'ıyla eşleştirilmiş API Key SID ile kimlik doğrular; eşleştirilmiş sır olmadan sonuç, asla yanlış bir `verified_inactive` değil, `unverified` olur) |
| `doppler-token` | Doppler API |
| `launchdarkly-sdk-key` | LaunchDarkly API |
| `sonarcloud-token` | SonarCloud API |
| `shopify-access-token` | Shopify Admin API |
| `notion-token` | Notion API |
| `linear-api-key` | Linear API |
| `figma-pat` | Figma REST API |
| `airtable-pat` | Airtable API |
| `okta-api-token` | Okta API (token ile birlikte yakalanan organizasyon alan adını hedefler) |
| `auth0-management-token` | Auth0 Management API (token'ın kendi JWT `iss` iddiasından çözülen kiracıyı hedefler) |
| `databricks-token` | Databricks REST API (token ile birlikte yakalanan çalışma alanı ana bilgisayarını çağırır) |
| `bitbucket-app-password` | Bitbucket REST API |
| `supabase-service-key` | Supabase API |
| `infura-api-key` | Infura API |
| `teams-webhook` | Microsoft Teams |

## Yalnızca format doğrulaması (6 dedektör türü)

Bu doğrulayıcılar tamamen çevrimdışı çalışır. Hiçbir ağ isteği yapılmaz. Geçerli bir format kimlik bilgisinin aktif olduğunu kanıtlamadığından, altısı da format kontrolünün geçip geçmediğinden bağımsız olarak her zaman `unverified` döndürür.

| Dedektör ID | Doğrulanan özellik | Neden canlı kontrol yok |
|-------------|-------------------|------------------------|
| `gcp-service-account` | JSON yapısı (`type`, `project_id`, `private_key_id`, `client_email`) | Canlı kontrol, yan etkileri olan GCP OAuth2 token değişimi gerektirir |
| `rabbitmq-connection-string` | AMQP URL'nin başarıyla ayrıştırılması | Herkese açık kimlik doğrulamasız sağlık uç noktası yok |
| `snowflake-credentials` | Parola uzunluğu ve host alt dize kontrolü | Canlı kontrol bir JDBC/ODBC veritabanı bağlantısı gerektirir |
| `azure-storage-key` | Format kontrolü | Hesap başına HMAC imzalama gerektirir; genel kimlik uç noktası yok |
| `azure-entra-secret` | Format kontrolü | İstemci kimlik bilgisi akışı oturum oluşturur |
| `coinbase-api-key` | Karakter kümesi ve uzunluk kontrolü | Coinbase'in eski API'si, dedektörün anahtarla güvenilir biçimde ilişkilendiremeyeceği eşleştirilmiş sırrı gerektiren HMAC-SHA256 istek imzalamayla kimlik doğrular; canlı doğrulama denenmez, böylece gerçek bir anahtar hiçbir zaman yanlışlıkla inaktif olarak raporlanmaz |

## Doğrulanamaz (10 dedektör türü)

Bu dedektör türlerinin hiç doğrulayıcısı yoktur. Bunlardan gelen bulgular her zaman `unverified` olur. Bu durum önemsiz oldukları anlamına **gelmez** — tam olarak tespit edilip raporlanırlar — ancak herkese açık bir doğrulama API'si bulunmamakta ya da herhangi bir doğrulama girişimi yan etkiye yol açmaktadır.

| Dedektör ID | Neden |
|-------------|-------|
| `jwt` | JWT herhangi bir tarafça yayınlanabilir; evrensel bir doğrulama uç noktası yoktur |
| `private-key` | Çağrılacak sağlayıcı yok; aktif kullanım uzaktan tespit edilemez |
| `generic-api-key` | Tanım gereği bilinmeyen sağlayıcı |
| `database-connection-string` | Bağlanmak hedef veritabanında oturum oluşturur |
| `redis-connection-string` | Bağlanmak Redis örneğinde canlı bağlantı açar |
| `ftp-credentials` | Güvenli, salt-okunur FTP yoklama yöntemi yok |
| `ldap-credentials` | LDAP bind kimliği doğrulanmış bir oturum oluşturur |
| `slack-webhook` | Webhook'un aktif olduğunu doğrulamak mesaj göndermeyi gerektirir |
| `hashicorp-vault-token` | Vault token doğrulaması, Vault uç noktasının bilinmesini gerektirir |
| `discord-webhook-url` | Bir webhook'un aktif olduğunu doğrulamak, ona bir mesaj göndermeyi gerektirir |

:::note
"Doğrulanamaz" "bulunamaz" anlamına gelmez. Bu 10 türün tamamı yine de tespit edilir ve çıktınızda görünür. Kimlik bilgisinin canlı olup olmadığını ve döndürülmesi gerekip gerekmediğini belirlemek için manuel inceleme gerektirir.
:::

## Kapsam özeti

| Kategori | Sayı |
|----------|------|
| Canlı doğrulanan | 48 |
| Yalnızca format doğrulaması | 6 |
| Doğrulanamaz | 10 |
| **Toplam dedektör** | **64** |
| **Doğrulayıcı (herhangi bir kapsam)** | **54 (%84,4)** |

## Ayrıca bakın

- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — iki doğrulama modu, durumlar ve doğrulama motoru.
- [Dedektör Kataloğu](#/detectors/detector-catalog) — yerleşik dedektörlerin tam listesi ve önem dereceleri.
