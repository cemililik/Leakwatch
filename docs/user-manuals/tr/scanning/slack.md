---
title: "Slack Çalışma Alanı"
description: "Slack kanal ve DM mesaj metinlerini sızan sırlara karşı tarayın."
---

# Slack Çalışma Alanı

Geliştiriciler çoğu zaman kimlik bilgilerini sohbet üzerinden paylaşır — hızlı bir test için bir kanala yapıştırılan token, DM ile gönderilen parola ya da bir olay başlığında söz edilen API anahtarı. `leakwatch scan slack`, Slack çalışma alanınızdaki mesaj metinlerini okur ve bulduğu sırları işaretler.

:::warn
Leakwatch yalnızca **mesaj metnini** tarar. Yüklenen dosyaların (ekler, snippet'ler) içeriğini taramak uygulanmamıştır. Yalnızca mesajların metin gövdesi analiz edilir.
:::

## Temel kullanım

```bash
leakwatch scan slack
```

Bu komut **konumsal argüman almaz**. Tüm yapılandırma bayraklar veya ortam değişkenleri aracılığıyla sağlanır.

## Kimlik doğrulama

Bir Slack Bot Token gereklidir. `--token` bayrağı veya `LEAKWATCH_SLACK_TOKEN` ortam değişkeni aracılığıyla sağlayın. Ortam değişkeni kullanmak önerilir; böylece token kabuk geçmişinde veya süreç listelerinde asla görünmez.

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

### Gerekli bot token kapsamları

Bot token'ı, aşağıdaki OAuth kapsamlarına sahip bir Slack uygulamasıyla ilişkilendirilmiş olmalıdır:

| Kapsam | Amaç |
|--------|------|
| `channels:history` | Botun katıldığı genel kanallardaki mesajları oku. |
| `groups:history` | Botun katıldığı özel kanallardaki mesajları oku. |
| `im:history` | Doğrudan mesajları oku (yalnızca `--include-dms` ile gerekli). |
| `mpim:history` | Grup doğrudan mesajlarını oku (yalnızca `--include-dms` ile gerekli). |

## Bayraklar

### Slack'e özgü

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--token` | string | — | Slack Bot Token. `LEAKWATCH_SLACK_TOKEN` ortam değişkeni tercih edilir. |
| `--channels` | string | tüm kanallar | Taranacak kanal adlarının virgülle ayrılmış listesi. |
| `--exclude-channels` | string | — | Atlanacak kanal adlarının virgülle ayrılmış listesi. |
| `--since` | string (YYYY-MM-DD) | — | Bu tarihte veya sonrasında gönderilen mesajları tara. |
| `--include-dms` | bool | `false` | Doğrudan mesajları ve grup DM'lerini de tara. |
| `--rate-limit` | float | `1` | Saniye başına maksimum Slack API istek sayısı. |

### Ortak tarama bayrakları

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Dahili parça boyutu sınırı (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri. Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

`--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir. Diğer her tarama alt komutunun aksine, `scan slack` komutunda `--exclude` yol-kalıbı bayrağı yoktur — bunun yerine tüm kanalları atlamak için `--exclude-channels` kullanın.

## Örnekler

Token için ortam değişkeni kullanarak botun erişebildiği tüm kanalları tarayın:

```bash
export LEAKWATCH_SLACK_TOKEN=xoxb-...
leakwatch scan slack
```

Belirli kanalları tarayın ve yılın başından bu yana gönderilen mesajlarla sınırlayın:

```bash
leakwatch scan slack \
  --channels general,engineering,backend \
  --since 2026-01-01
```

Gürültülü kanalları dışlayın ve doğrudan mesajları dahil edin:

```bash
leakwatch scan slack \
  --exclude-channels random,social,giphy \
  --include-dms
```

Büyük çalışma alanlarında Slack hız sınırı hatalarını önlemek için API istek hızını düşürün:

```bash
leakwatch scan slack --rate-limit 10 --format table
```

Yalnızca doğrulanmış aktif bulguları bir JSON dosyasına kaydedin:

```bash
leakwatch scan slack \
  --only-verified \
  --format json \
  --output slack-findings.json
```

## Bulgu meta verisi

Slack taramasından elde edilen her bulgu mesaj ve kanal meta verisi içerir:

| Alan | Açıklama |
|------|----------|
| `channel` | Bulgunun tespit edildiği Slack kanalının **kimliği** (örn. `C0123456`) — okunabilir ad değil. |
| `channel_name` | `channel` alanından ayrı, okunabilir kanal adı (örn. `engineering`). |
| `message_user` | Mesaj yazarının Slack kullanıcı kimliği. Slack bulguları için `author` alanı yoktur. |
| `message_ts` | Slack mesaj zaman damgası (benzersiz mesaj kimliği). |
| `thread_ts` | Yalnızca bulgu bir ileti dizisi yanıtındaysa bulunan, üst mesajın zaman damgası. |

## Performans değerlendirmeleri

Slack API istekleri, Slack tarafından uygulanan hız sınırlarına tabidir. `--rate-limit` bayrağı (varsayılan saniyede `1` istek), Leakwatch'ın istekleri ne kadar agresif yapacağını kontrol eder. Cömert hız sınırlarına sahip bir çalışma alanında daha hızlı bir tarama için dikkatli bir şekilde artırın, ya da `429 Too Many Requests` hatası görüyorsanız daha da düşürün.

Slack `429 Too Many Requests` ile yanıt verdiğinde, Leakwatch `Retry-After` başlığına otomatik olarak uyar ve taramayı tamamen başarısız kılmak yerine isteği yeniden dener.

Her çalıştırmada tüm çalışma alanını taramak yerine belirli kanalları hedeflemek için `--channels` kullanın. Mesajları artımlı biçimde taramak için `--since` ile birleştirin.

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı, bulgu yok. |
| `1` | Tarama tamamlandı, bulgular raporlandı. |
| `2` | Tarama başarısız oldu (eksik token, kimlik doğrulama hatası, vb.). |
| `3` | Tarama tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve hiçbir bulgu raporlanmamıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Yapılandırma Dosyası](#/configuration/config-file) — `.leakwatch.yaml` ile varsayılanları yapılandırın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — bilinen yanlış pozitifleri bastırın.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [Git Geçmişi](#/scanning/git-history) — commit edilmiş geçmişi sırlara karşı tarayın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
