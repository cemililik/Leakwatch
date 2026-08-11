---
title: "Slack Çalışma Alanı"
description: "Slack mesajlarını ve isteğe bağlı metin eklerini sızan sırlara karşı tarayın."
---

# Slack Çalışma Alanı

Geliştiriciler çoğu zaman kimlik bilgilerini sohbet üzerinden paylaşır — hızlı bir test için bir kanala yapıştırılan token, DM ile gönderilen parola ya da olay başlığına yüklenen bir yapılandırma dosyası. `leakwatch scan slack`, Slack çalışma alanınızdaki mesaj metinlerini ve açıkça etkinleştirildiğinde metin benzeri dosya eklerini okur.

:::note
Dosya eki taraması isteğe bağlıdır. `--include-files` kullanın ve `files:read` kapsamını verin; bayrak olmadan Leakwatch hiçbir eki indirmez.
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
| `channels:read` | Genel kanalları listele. |
| `channels:history` | Botun katıldığı genel kanallardaki mesajları oku. |
| `groups:read` | Özel kanalları listele. |
| `groups:history` | Botun katıldığı özel kanallardaki mesajları oku. |
| `im:read` | Doğrudan mesaj konuşmalarını listele (yalnızca `--include-dms` ile gerekli). |
| `im:history` | Doğrudan mesajları oku (yalnızca `--include-dms` ile gerekli). |
| `mpim:read` | Grup doğrudan mesaj konuşmalarını listele (yalnızca `--include-dms` ile gerekli). |
| `mpim:history` | Grup doğrudan mesajlarını oku (yalnızca `--include-dms` ile gerekli). |
| `files:read` | Dosya meta verisini ve içeriğini oku (yalnızca `--include-files` ile gerekli). |

## Bayraklar

### Slack'e özgü

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--token` | string | — | Slack Bot Token. `LEAKWATCH_SLACK_TOKEN` ortam değişkeni tercih edilir. |
| `--channels` | string | tüm kanallar | Taranacak kanal adlarının virgülle ayrılmış listesi. |
| `--exclude-channels` | string | — | Atlanacak kanal adlarının virgülle ayrılmış listesi. |
| `--since` | string (YYYY-MM-DD) | — | Bu tarihte veya sonrasında gönderilen mesajları tara. |
| `--include-dms` | bool | `false` | Doğrudan mesajları ve grup DM'lerini de tara. |
| `--include-files` | bool | `false` | Boyutu sınırlı metin benzeri dosya eklerini indir ve tara. `files:read` gerektirir. |
| `--rate-limit` | float | `0` | İsteğe bağlı, işlem başına saniyelik Slack istek üst sınırı. Sıfır, güvenli işlem varsayılanlarını korur: history `1/60`, liste/dosya/indirme sınırları daha yüksektir. |

### Ortak tarama bayrakları

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Tarama için belleğe alınan en büyük ek boyutu (bayt). |
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

Dosya başına bellek sınırını düşürerek metin benzeri ekleri dahil edin:

```bash
leakwatch scan slack \
  --include-files \
  --max-file-size 5242880
```

API istek hızını yalnız yayımlanmış katmanı izin veren Marketplace/dahili bir uygulama için artırın:

```bash
leakwatch scan slack --rate-limit 0.8 --format table
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
| `file_path` | Ekten gelen bulgularda bulunan sentetik `slack/<kanal>/<dosya-adı>` yolu. |

## Performans değerlendirmeleri

Slack API sınırları yöntem, çalışma alanı ve uygulama başına uygulanır. Bu nedenle Leakwatch bağımsız limiter kovaları kullanır: `conversations.history`, yeni dağıtılan Marketplace dışı uygulamalar için varsayılan dakikada bir istektir; `conversations.list` Tier 2'yi (20+/dakika), `files.info` Tier 4'ü (100+/dakika) izler ve ek indirmelerinin ayrı, ihtiyatlı bir 100/dakika istemci sınırı vardır. `--rate-limit` her kovayı aynı işlem-başı üst sınırla açıkça geçersiz kılar; Tier 3 erişimli Marketplace/dahili uygulamalar bunu bilinçli olarak artırabilir.

Slack `429 Too Many Requests` ile yanıt verdiğinde, Leakwatch `Retry-After` başlığına otomatik olarak uyar ve taramayı tamamen başarısız kılmak yerine isteği yeniden dener.

Dosya meta verisi ve indirmeler birbirlerinin veya history kapasitesini tüketmek yerine ayrı limiter kovaları kullanır. Leakwatch yalnızca Slack'e ait HTTPS indirme URL'lerini kabul eder, ek chunk'larını doğrudan backpressure ile aktarır, en fazla `--max-file-size` kadar veriyi belleğe alır, MIME boş ya da yanıltıcı olsa bile geçersiz UTF-8/ikili içeriği reddeder ve aynı Slack dosya kimliğini mesajlar arasında tekilleştirir.

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
