---
title: "Doğrulama Kapsamı"
description: "65 yerleşik dedektörün hangilerinin canlı doğrulandığı, bağlam gerektirdiği, yalnızca format doğruladığı veya doğrulanamaz olduğu ve bunun önceliklendirme açısından ne anlama geldiği."
---

# Doğrulama Kapsamı

Leakwatch **65 yerleşik dedektör** ve kayıtlı 54 doğrulayıcı implementasyonuyla gelir. Registry kaydı canlı kabiliyetle aynı şey değildir: **41** dedektör normal üretim yolunda canlı kontrol yapabilir, **7** dedektör güvenilir operatör veya eşlik eden bağlam gerektirir, **6** dedektör yalnızca çevrimdışı format doğrular ve **11** dedektörün doğrulayıcısı yoktur. Bu sayfa her dedektörü gerçek doğrulama sözleşmesine göre eşler.

## Canlı doğrulanan (41 dedektör türü)

Bu türler için Leakwatch normal üretim yolunda kontrollü, yıkıcı olmayan bir sağlayıcı kontrolü yapabilir. Sözleşmeye uygun başarı `verified_active` döndürebilir; yalnızca doğru issuer üzerindeki kesin kimlik doğrulama reddi `verified_inactive` döndürebilir. Belirsiz yanıtlar `verify_error` kalır.

| Dedektör türü | Sağlayıcı |
|--------------|----------|
| `aws-access-key-id` | AWS STS (`GetCallerIdentity`) |
| `gitlab-pat` | GitLab REST API (token ile birlikte yakalanan kendi barındırılan bir GitLab sunucusu varsa onu hedefler; yoksa gitlab.com'a geri döner) |
| `slack-token` | Slack Web API |
| `openai-api-key` | OpenAI API |
| `anthropic-api-key` | Anthropic API |
| `deepseek-api-key` | DeepSeek API |
| `huggingface-token` | Hugging Face API |
| `sendgrid-api-key` | SendGrid Web API (`401` inaktiftir; izin reddi dâhil `403`, `verify_error` olarak kalır) |
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
| `newrelic-api-key` | New Relic NerdGraph (resmî ABD/AB uçlarında sınırlı fallback; yalnızca iki bölge de `401` döndürürse inaktif) |
| `doppler-token` | Doppler API |
| `launchdarkly-sdk-key` | LaunchDarkly API |
| `sonarcloud-token` | SonarCloud API |
| `notion-token` | Notion API |
| `linear-api-key` | Linear API |
| `figma-pat` | Figma REST API |
| `airtable-pat` | Airtable API |
| `okta-api-token` | Okta API (token ile birlikte yakalanan organizasyon alan adını hedefler) |
| `auth0-management-token` | Auth0 Management API (token'ın kendi JWT `iss` iddiasından çözülen kiracıyı hedefler) |
| `databricks-token` | Databricks REST API (token ile birlikte yakalanan çalışma alanı ana bilgisayarını çağırır) |
| `bitbucket-app-password` | Bitbucket REST API |
| `supabase-service-key` | Supabase Management API (`sbp_` kişisel erişim token'ı; `401` inaktiftir, `403` `verify_error` kalır) |
| `infura-api-key` | Infura API |
| `teams-webhook` | Microsoft Teams |

## Güvenilir veya eşlik eden bağlam gerektiren (7 dedektör türü)

Bu implementasyonlar registry'de kayıtlıdır; ancak çıplak bir dedektör bulgusu güvenli issuer seçmek veya doğrulama isteğinde kimlik doğrulamak için yeterli değildir. Gerekli bağlam yoksa Leakwatch güvenli olmayan bir varsayım yapmaz ve `unverified` döndürür.

| Dedektör ID | Gerekli bağlam | Üretim davranışı |
|-------------|----------------|------------------|
| `grafana-api-key` | `--grafana-instance-url` ile verilen güvenilir Grafana instance origin'i | Yalnızca doğrulanmış HTTPS instance'ını çağırır. Repo içeriği veya finding metadata hedef seçemez; `401` yalnızca bu güvenilir issuer üzerinde inaktiftir. |
| `twilio-api-key` | Account SID ve tespit edilen `SK...` Key SID ile eşleşen API Key Secret | Dedektör yakındaki Account SID'yi bulabilir ancak eşleşen API Key Secret'ı üretmez; normal bulgular `unverified` kalır. |
| `shopify-access-token` | Token'ı yayınlayan mağaza domain'i | Mevcut dedektör yalnızca token'ı üretir; güvenilir mağaza domain'i olmadan verifier istek yapmaz ve `unverified` döndürür. |
| `github-token` | Güvenilir GitHub.com veya GitHub Enterprise Server API origin'i | GHES, GitHub.com ile aynı `ghp_` ve `github_pat_` biçimlerini kullanır. Mevcut üretim kaydında güvenilir origin yoktur; istek yapmaz ve `unverified` döndürür. |
| `github-oauth-token` | Güvenilir GitHub.com veya GitHub Enterprise Server API origin'i | GHES ayrıca `gho_`, `ghu_`, `ghs_` ve `ghr_` kimlik bilgileri yayınlar. Mevcut üretim kaydında güvenilir origin yoktur; istek yapmaz ve `unverified` döndürür. |
| `datadog-api-key` | Güvenilir Datadog site/API origin'i | Datadog anahtarları US1/US3/US5/EU/AP1/AP2/UK1/FED sitelerine bağlıdır. Mevcut üretim kaydında güvenilir site yoktur; istek yapmaz ve `unverified` döndürür. |
| `snyk-api-key` | Güvenilir Snyk bölgesel, kamu veya özel API origin'i | Yanlış Snyk bölgesinin anahtarı reddetmesi iptal kanıtı değildir. Mevcut üretim kaydında güvenilir origin yoktur; istek yapmaz ve `unverified` döndürür. |

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

## Doğrulanamaz (11 dedektör türü)

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
| `structured-config-secret` | Bağlamsal fallback bir secret rolünü belirleyebilir ancak credential sağlayıcısını veya issuer'ı belirleyemez |

:::note
"Doğrulanamaz" "bulunamaz" anlamına gelmez. Bu 11 türün tamamı yine de tespit edilir ve çıktınızda görünür. Kimlik bilgisinin canlı olup olmadığını ve döndürülmesi gerekip gerekmediğini belirlemek için manuel inceleme gerektirir.
:::

## Kapsam özeti

| Kategori | Sayı |
|----------|------|
| Canlı doğrulanan | 41 |
| Güvenilir/eşlik eden bağlam gerektiren | 7 |
| Yalnızca format doğrulaması | 6 |
| Doğrulanamaz | 11 |
| **Toplam dedektör** | **65** |
| **Kayıtlı doğrulayıcı implementasyonu** | **54 (%83,1)** |

## Ayrıca bakın

- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — iki doğrulama modu, durumlar ve doğrulama motoru.
- [Dedektör Kataloğu](#/detectors/detector-catalog) — yerleşik dedektörlerin tam listesi ve önem dereceleri.
