---
title: "Doğrulama Nasıl Çalışır"
description: "Leakwatch'ın tespit edilen bir sırrın hâlâ aktif olup olmadığını nasıl teyit ettiği, hangi doğrulama modlarını kullandığı ve doğrulamanın nasıl yapılandırılacağı veya devre dışı bırakılacağı."
---

# Doğrulama Nasıl Çalışır

Bir kod tabanında sır bulmak hikayenin yalnızca yarısıdır. Altı ay önce döndürülen bir anahtar gürültüdür; hâlâ canlı olan bir anahtar ise aktif bir olayı temsil eder. Doğrulama, bu çizgiyi çizen adımdır — tespit edilen her bulguyu alır ve mümkün olan durumlarda sırrın sağlayıcıda hâlâ geçerli olup olmadığını teyit eder.

## Tespiten doğrulamaya

Tarama motoru bulguları topladıktan sonra doğrulayıcı havuzu onları işlemeye alır. Her bulgu bir `detector_id` taşır; Leakwatch bu ID için kayıtlı bir doğrulayıcı olup olmadığını arar:

- Bir doğrulayıcı mevcutsa çalışır ve bir durum döndürür.
- O dedektör türü için kayıtlı bir doğrulayıcı yoksa bulgu değiştirilmeden `unverified` durumuyla geçer.

## Üç doğrulama modu

Tüm sırlar aynı şekilde doğrulanamaz. Leakwatch doğrudan canlı kontrolleri, güvenilir veya eşlik eden bağlam gerektiren kontrolleri ve çevrimdışı format doğrulamasını birbirinden ayırır. Bu nedenle registry kaydı canlı kabiliyetin kanıtı sayılmaz.

### Canlı API doğrulaması

39 dedektör türü için Leakwatch normal üretim yolunda **kontrollü, yıkıcı olmayan bir sağlayıcı kontrolü** yapabilir — örneğin AWS anahtarları için `sts:GetCallerIdentity`, OpenAI anahtarları için sabit sağlayıcı kimlik uç noktası. Çağrı yalnızca kimliği doğrulamak için gereken minimum uç noktayı kullanır; hiçbir zaman veri değiştirmez veya kaynak oluşturmaz, ancak sağlayıcı kotası tüketebilir.

Sağlayıcı sözleşmeye uygun başarılı bir yanıt döndürürse bulgu `verified_active` olarak işaretlenir. Bir bulgu yalnızca sağlayıcı yanıtı ilgili doğrulayıcı sözleşmesine göre kesin olduğunda `verified_inactive` olur. İzin reddi ve belirsiz yanıtlar `verify_error` olarak kalır; örneğin SendGrid yalnız HTTP `401` yanıtını inaktif sayar, `403` ise sonuçsuzdur.

### Güvenilir veya eşlik eden bağlam gerekli

Kayıtlı dokuz implementasyon çıplak dedektör bulgusundan güvenli canlı istek yapamaz. Auth0, GitLab, Grafana, GitHub/GHES, Datadog ve Snyk güvenilir issuer/site/API origin'i gerektirir. Twilio bulgusu açıkça eşleşen API Key Secret ile gizli olmayan Key SID'yi içerir, ancak yine de güvenilir bölgesel origin gerekir. Shopify için operatörce güvenilen mağaza origin'i zorunludur. Bu hedefleri yalnızca tekrarlanabilir `--verifier-origin detector-id=https://host` komut satırı bayrağıyla verin (`--grafana-instance-url` Grafana için korunmuştur). Proje yapılandırması, ortam değişkenleri, repo URL'leri ve token iddiaları doğrulama hedefi seçemez. Açık bağlam olmadan Leakwatch istek göndermez ve `unverified` döndürür.

### Yalnızca format doğrulaması

Altı kimlik bilgisi türü için güvenli bir canlı kontrol mevcut değildir — sağlayıcının anonim bir kimlik uç noktası yoktur, gerçek bir çağrı yan etkiye yol açar ya da (`coinbase-api-key` için) canlı API, anahtarla güvenilir biçimde ilişkilendirilemeyen eşleştirilmiş bir sırla HMAC istek imzalaması gerektirir. Bu durumlar için Leakwatch, herhangi bir ağ isteği yapmadan kimlik bilgisinin yapısını doğrular:

| Dedektör ID | Doğrulanan özellik |
|-------------|-------------------|
| `gcp-service-account` | JSON yapısı — `type`, `project_id`, `private_key_id`, `client_email` alanlarının varlığı |
| `rabbitmq-connection-string` | AMQP URL'nin başarıyla ayrıştırılması |
| `snowflake-credentials` | Yalnızca format kontrolü — geçerli bir format hiçbir şeyi kanıtlamaz, sonuç her zaman `unverified` |
| `azure-storage-key` | Format kontrolü |
| `azure-entra-secret` | Format kontrolü |
| `coinbase-api-key` | Karakter kümesi ve uzunluk kontrolü |

:::note
Format kontrolü geçse bile sonuç `unverified` olarak kalır. Yapısal olarak geçerli bir kimlik bilgisi süresi dolmuş veya iptal edilmiş olabilir. Bu bulgular her zaman manuel inceleme gerektirir.
:::

## Doğrulama durumları

Leakwatch çıktısındaki her bulgu dört durumdan birini taşır:

| Durum | Anlam | Önerilen eylem |
|-------|-------|----------------|
| `verified_active` | Sırrın sağlayıcı tarafından canlı olduğu teyit edildi. | Aktif bir olay olarak ele alın. Hemen döndürün. |
| `verified_inactive` | Sağlayıcı kimlik bilgisini reddetti. | Muhtemelen zaten döndürülmüş. Bağlamı gözden geçirin ve kapatın. |
| `unverified` | Doğrulayıcı yoktur, gerekli bağlam eksiktir, yalnız-format doğrulayıcısı canlılığı kanıtlayamaz veya doğrulama devre dışıdır. | Manuel olarak inceleyin; risk bağlama göre belirlenir. |
| `verify_error` | Doğrulayıcı çalıştı ancak ağ hatası, zaman aşımı veya beklenmedik yanıtla karşılaştı. | Potansiyel olarak aktif kabul edin. Yeniden deneyin veya manuel olarak inceleyin. |

## Doğrulama motoru

Doğrulama, tarama çalışan havuzundan yalıtılmış ayrı bir eşzamanlı çalışan havuzunda çalışır. Sağlayıcı hız sınırlarını tetiklememek için varsayılanlar temkinlidir:

| Ayar | Varsayılan | Yapılandırma anahtarı |
|------|-----------|----------------------|
| Çalışan sayısı | 4 | `verification.concurrency` |
| Global + dedektör başına istek tavanları | Her biri 10 istek/saniye | `verification.rate-limit` |
| İstek başına zaman aşımı | 10 sn | `verification.timeout` |

Her üç değer de `.leakwatch.yaml` içindeki `verification:` bloğu altında ayarlanabilir:

```yaml
verification:
  enabled: true
  concurrency: 4
  rate-limit: 10.0   # global ve dedektör başına, saniye başına istek sayısı
  timeout: 10s
```

:::tip
Yüzlerce bulgu tetikleyen bir depoyu tarıyorsanız `rate-limit` değerini 5'e düşürmeyi veya `--only-verified` etkinleştirmeyi düşünün; bu, doğrulanmış-aktif kümesini küçük ve uygulanabilir tutar.
:::

Admission yalnızca gerçek bir sağlayıcı isteğinin hemen öncesinde yapılır. Yalnız-format ve eksik-bağlam sonuçları sınırlayıcı kapasitesi tüketmez. Dedektör başına kova o dedektörün kendi istek hızını, paylaşılan global kova ise toplam trafiği sınırlar; bu yapı sağlayıcılar arasında adil zamanlama garantisi vermez.

## Komut satırından doğrulamayı kontrol etme

`--no-verify` ile **doğrulamayı tamamen devre dışı bırakın** (ya da yapılandırmada `verification.enabled: false` ayarlayın). Her bulgu `unverified` olarak geçer. Bunu çevrimdışı veya hava boşluklu ortamlar için ya da herhangi bir sağlayıcı API'sine dokunmadan mümkün olan en hızlı taramayı istediğinizde kullanın.

```bash
leakwatch scan fs . --no-verify
```

**Yalnızca canlı olduğu doğrulanan sırları görmek** için `--only-verified` kullanın. `verified_active` olmayan her şey çıktıdan düşürülür. Bu, büyük bir sonuç kümesini önceliklendirmenin en hızlı yoludur — yalnızca hemen harekete geçmeniz gereken anahtarları görürsünüz.

```bash
leakwatch scan git . --only-verified
```

:::warn
`--only-verified`, `unverified` ve `verify_error` bulgularını sessizce düşürür. Bunu uyumluluk bağlamında tek filtreniz olarak kullanmayın — bazı kimlik bilgisi türleri (JWT'ler, genel API anahtarları, özel anahtarlar) hiçbir zaman doğrulanamaz ve her zaman dışarıda kalır.
:::

## Sır güvenliği

Doğrulama, ham sır değerinin süreç sınırını güvensiz biçimde asla terk etmeyecek şekilde tasarlanmıştır:

- Doğrulayıcılar sırrı TLS üzerinden doğrudan sağlayıcının HTTP uç noktasına iletir — diske yazılmaz, bir loga gönderilmez ve çalıştırmalar arasında önbelleğe alınmaz.
- Başlatılamayan veya panikle karşılaşan bir doğrulayıcı motor tarafından yakalanır; motor, bulguyu `verify_error` olarak işaretler ve taramayı çökertmeden devam eder.

## Ayrıca bakın

- [Doğrulama Kapsamı](#/verification/verification-coverage) — hangi dedektör türlerinin canlı doğrulandığı, format doğrulandığı veya hiç doğrulanamadığı.
- [Yapılandırma: Yapılandırma Dosyası](#/configuration/config-file) — `verification:` bloğunun tam referansı.
- [Çıktı Formatları](#/output/output-formats) — doğrulama durumunun JSON, SARIF, CSV ve tablo çıktısında nasıl göründüğü.
