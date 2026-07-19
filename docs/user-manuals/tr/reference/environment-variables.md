---
title: "Ortam Değişkenleri"
description: "Leakwatch davranışını bayrak kullanmadan yapılandıran ortam değişkenleri."
---

# Ortam Değişkenleri

Leakwatch, yapılandırmayı öncelik sırasına göre üç kaynaktan okur: **komut satırı bayrakları**, **ortam değişkenlerini** geçersiz kılar; ortam değişkenleri **yapılandırma dosyasını** (`.leakwatch.yaml`) geçersiz kılar; yapılandırma dosyası yerleşik **varsayılanlara** geri döner. Ortam değişkenleri, bir yapılandırma dosyasını değiştiremeyeceğiniz veya her çağrıya bayrak geçiremeyeceğiniz CI ortamlarında kullanışlıdır.

## Yapılandırma değişkeni kalıbı

`.leakwatch.yaml`'daki herhangi bir anahtar, ortam değişkeni olarak şu şekilde ayarlanabilir:

1. Anahtar adını büyük harfe çevir.
2. `.` ve `-` karakterlerini `_` ile değiştir.
3. Başına `LEAKWATCH_` ekle.

Örneğin, `scan.concurrency` yapılandırma anahtarı `LEAKWATCH_SCAN_CONCURRENCY` olur.

## Değişken başvurusu

### Leakwatch'a özgü değişkenler

| Değişken | Açıklama |
|----------|----------|
| `LEAKWATCH_SLACK_TOKEN` | `scan slack` için Slack bot token'ı. `--token`'a eşdeğer. Token'ın kabuk geçmişinde veya CI günlüklerinde görünmesini önlemek için bayrak olarak geçirmek yerine bunu ayarlayın. |
| `LEAKWATCH_SCAN_CONCURRENCY` | Eşzamanlı tarama çalışanı sayısı. `--concurrency`'e eşdeğer. |
| `LEAKWATCH_VERIFICATION_ENABLED` | Canlı doğrulamayı genel olarak devre dışı bırakmak için `false` olarak ayarlayın. `--no-verify`'e eşdeğer. |
| `LEAKWATCH_VERIFICATION_RATE_LIMIT` | Tüm doğrulayıcılar genelinde saniye başına maksimum doğrulama isteği. |
| `LEAKWATCH_OUTPUT_FORMAT` | Varsayılan çıktı biçimi (`json`, `sarif`, `csv`, `table` veya `github`). `--format`'a eşdeğer. |
| `LEAKWATCH_DETECTION_ENTROPY_THRESHOLD` | Bir eşleşmenin raporlanması için gereken minimum Shannon entropisi. Float değer, örn. `3.5`. |

### Görüntüleme değişkeni

| Değişken | Açıklama |
|----------|----------|
| `NO_COLOR` | Boş olmayan herhangi bir değere ayarlandığında, `table` çıktı biçimlendiricisindeki ANSI renk kodlarını devre dışı bırakır. [no-color.org](https://no-color.org) kuralını izler. |

### AWS değişkenleri (`scan s3` ve AWS sır doğrulaması için)

Bunlar standart AWS SDK ortam değişkenleridir. Leakwatch bunları AWS SDK v2 varsayılan kimlik bilgisi zincirine aktarır.

| Değişken | Açıklama |
|----------|----------|
| `AWS_ACCESS_KEY_ID` | AWS erişim anahtarı kimliği. |
| `AWS_SECRET_ACCESS_KEY` | AWS gizli erişim anahtarı. |
| `AWS_SESSION_TOKEN` | AWS oturum token'ı (geçici kimlik bilgileri için). |
| `AWS_REGION` | Varsayılan AWS bölgesi. |
| `AWS_PROFILE` | Kullanılacak `~/.aws/credentials` dosyasından adlandırılmış profil. |

### GCS değişkeni (`scan gcs` için)

| Değişken | Açıklama |
|----------|----------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Google hizmet hesabı JSON anahtar dosyasının yolu. Bir GCS kovasını tararken Uygulama Varsayılan Kimlik Bilgileri tarafından kullanılır. |

## Öncelik örneği

Şu kurulumu varsayın:

- `.leakwatch.yaml`, `output.format: table` olarak ayarlıyor
- Ortamda `LEAKWATCH_OUTPUT_FORMAT=json` ayarlanmış
- Komut `leakwatch scan fs .` olarak çalıştırılıyor (`--format` bayrağı yok)

Ortam değişkeni yapılandırma dosyasını geçersiz kıldığından geçerli biçim `json`'dır.

Komut `leakwatch scan fs . --format sarif` olarak çalıştırılırsa, bayrak her şeyi geçersiz kıldığından geçerli biçim `sarif` olur.

## Doğrulama kimlik bilgileri ve tarama kimlik bilgileri

:::note
Yukarıdaki AWS ve GCP değişkenleri, Leakwatch'ın **kendisinin** nesneleri taramak için S3 veya GCS'ye bağlanırken kimliğini doğrulaması için kullanılır. Bulunan sırları doğrulamak için kullanılmazlar. Keşfedilen bir AWS anahtarının doğrulanması, örneğin, runner'ın kimlik bilgilerini değil, keşfedilen anahtarın kendisini kullanarak AWS STS'yi çağırır.
:::

## CI'da sırları güvenli biçimde geçirme

GitHub Actions'ta şifrelenmiş sırları kullanın:

```yaml
env:
  LEAKWATCH_SLACK_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
```

GitLab CI'da maskelenmiş CI/CD değişkenlerini kullanın:

```yaml
variables:
  LEAKWATCH_SLACK_TOKEN: $SLACK_BOT_TOKEN   # proje ayarlarında maskelenmiş değişken olarak tanımlanmış
```

Token değerlerini hiçbir zaman iş akışı dosyalarına veya Dockerfile'lara sabit olarak kodlamayın.

## Ayrıca bakın

- [Yapılandırma Dosyası](#/configuration/config-file) — tam `.leakwatch.yaml` anahtar başvurusu.
- [Bulut Depolama Taraması](#/scanning/cloud-storage) — `scan s3` ve `scan gcs` kimlik bilgileri.
- [Slack Taraması](#/scanning/slack) — Slack token kapsamları ve izinleri.
- [CLI Başvurusu](#/reference/cli-reference) — eşdeğer komut satırı bayrakları.
