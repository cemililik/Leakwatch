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

## İki doğrulama modu

Tüm sırlar aynı şekilde doğrulanamaz. Leakwatch, her kimlik bilgisi türü için güvenli olan yaklaşıma göre iki farklı yöntem kullanır.

### Canlı API doğrulaması

48 dedektör türü için Leakwatch, sağlayıcıya **kontrollü, salt-okunur bir API çağrısı** yapar — örneğin AWS anahtarları için `sts:GetCallerIdentity`, GitHub token'ları için `GET /user`. Çağrı yalnızca kimliği doğrulamak için gereken minimum uç noktayı kullanır; hiçbir zaman veri değiştirmez, kaynak oluşturmaz veya faturalandırma olayı tetiklemez.

Sağlayıcı başarılı bir yanıt döndürürse bulgu `verified_active` olarak işaretlenir. Sağlayıcı kimlik bilgisini reddederse (örneğin HTTP 401 veya kapsamlı-anahtar hatalarını "inaktif" içinde birleştiren bir sağlayıcı için HTTP 403 ile) bulgu `verified_inactive` olarak işaretlenir. Birkaç doğrulayıcı (örneğin SendGrid), kapsamı daraltılmış ama geçerli bir anahtardan kaynaklanan bir 403'ü gerçek bir reddediliş yanıtından ayırt eder ve bu durumda yine `verified_active` bildirir — sağlayıcıya özgü notlar için [Doğrulama Kapsamı](#/verification/verification-coverage) sayfasına bakın.

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
| `unverified` | Bu tür için doğrulayıcı yok, format doğrulaması sonuç vermedi veya doğrulama devre dışı bırakıldı. | Manuel olarak inceleyin; risk bağlama göre belirlenir. |
| `verify_error` | Doğrulayıcı çalıştı ancak ağ hatası, zaman aşımı veya beklenmedik yanıtla karşılaştı. | Potansiyel olarak aktif kabul edin. Yeniden deneyin veya manuel olarak inceleyin. |

## Doğrulama motoru

Doğrulama, tarama çalışan havuzundan yalıtılmış ayrı bir eşzamanlı çalışan havuzunda çalışır. Sağlayıcı hız sınırlarını tetiklememek için varsayılanlar temkinlidir:

| Ayar | Varsayılan | Yapılandırma anahtarı |
|------|-----------|----------------------|
| Çalışan sayısı | 4 | `verification.concurrency` |
| Global hız sınırı | 10 istek/saniye | `verification.rate-limit` |
| İstek başına zaman aşımı | 10 sn | `verification.timeout` |

Her üç değer de `.leakwatch.yaml` içindeki `verification:` bloğu altında ayarlanabilir:

```yaml
verification:
  enabled: true
  concurrency: 4
  rate-limit: 10.0   # global, saniye başına istek sayısı
  timeout: 10s
```

:::tip
Yüzlerce bulgu tetikleyen bir depoyu tarıyorsanız `rate-limit` değerini 5'e düşürmeyi veya `--only-verified` etkinleştirmeyi düşünün; bu, doğrulanmış-aktif kümesini küçük ve uygulanabilir tutar.
:::

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
