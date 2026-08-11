---
title: "CLI Başvurusu"
description: "Her Leakwatch komutu, alt komutu ve bayrağı için tam başvuru kaynağı."
---

# CLI Başvurusu

Bu sayfa, tüm Leakwatch komutları ve bayrakları için yetkili başvuru kaynağıdır. Kavramsal açıklamalar ve çalışma örnekleri için ilgili tarama veya yapılandırma sayfalarındaki çapraz bağlantıları takip edin.

## Global bayraklar

Bu bayraklar her komut ve alt komut üzerinde kullanılabilir.

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--config <path>` | Otomatik olarak bulunan `.leakwatch.yaml` | Yapılandırma dosyasının yolu. Atlandığında Leakwatch, `.leakwatch.yaml` için önce geçerli dizini, ardından kullanıcının ana dizinini arar — üst dizin taraması **yapılmaz**. Her iki konumdaki bozuk bir yapılandırma dosyası (geçersiz YAML) da ölümcül bir hatadır. |
| `--log-level <level>` | `warn` | Günlük ayrıntı düzeyi: `debug`, `info`, `warn` veya `error`. Günlük çıktısı stderr'e gider ve tarama sonuçlarını etkilemez. |

## `leakwatch version`

İkili dosya sürümünü, commit karmasını ve derleme zaman damgasını yazdırır, ardından çıkar.

```bash
leakwatch version
```

```text
leakwatch v1.7.0 (commit: 1a2b3c4, built: 2026-07-20T19:44:14Z)
```

## `leakwatch init`

Geçerli dizinde önerilen varsayılanlarla bir `.leakwatch.yaml` yapılandırma dosyası oluşturur.

```bash
leakwatch init [flags]
```

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--output <path>` | `.leakwatch.yaml` | Yapılandırma dosyasını varsayılan yerine bu yola yaz. |
| `--force` | `false` | Mevcut bir yapılandırma dosyasının üzerine yaz. Bu bayrak olmadan, çıktı dosyası zaten mevcutsa `init` hatayla çıkar. |

```bash
# Varsayılan yapılandırmayı oluştur
leakwatch init

# Mevcut yapılandırmanın üzerine yaz
leakwatch init --force
```

## `leakwatch scan`

Tüm tarama alt komutları için üst komut. Kendi başına davranışı yoktur; bir alt komut çalıştırın.

### Ortak tarama bayrakları

Aşağıdaki bayraklar **tüm** `scan` alt komutlarında kullanılabilir.

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|-----------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table` veya `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosya yoluna yaz. Uzantısız düz bir yol verildiğinde, biçimin kendi uzantısı otomatik olarak eklenir (örn. `--format sarif --output results`, `results.sarif` dosyasını yazar). Dosya `0600` izinleriyle yazılır. Her zaman stdout'a yazan `--format github` için yok sayılır. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı tarama çalışanı sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu bayt sayısından büyük dosyaları veya blob'ları atla. |
| `--show-raw` | — | `false` | Çıktıya ham (maskelenmemiş) sır değerini dahil et. Dikkatli kullanın. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri (örn. `aws-access-key-id,generic-api-key`). Tekrarlanabilir veya virgülle ayrılabilir; yapılandırma dosyasındaki `filter.exclude-detectors` ile birleştirilir (onun yerine geçmez). |
| `--no-verify` | — | `false` | Canlı sır doğrulamasını devre dışı bırak. Giden API çağrısı yapılmaz. |
| `--only-verified` | — | `false` | Yalnızca canlı doğrulama ile etkin olduğu teyit edilen bulguları raporla. |
| `--min-severity` | — | `low` | Çıktıya dahil edilecek minimum önem derecesi: `low`, `medium`, `high` veya `critical`. Tanınmayan bir değer (örn. bir yazım hatası) sessizce kabul edilmek yerine kesin bir hataya yol açar. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi (dönüşüm/iptal adımları) ekle. |

`--exclude <pattern>` (tekrarlanabilir) bayrağı, `scan slack` **hariç** her tarama alt komutunda da kullanılabilir — bu bayrak tüm alt komutlar arasında paylaşılmak yerine komut başına kaydedildiğinden, aşağıda her alt komutun kendi bayrak tablosuna bakın.

Çıkış kodu sözleşmesinin tamamı için [Çıkış Kodları](#/reference/exit-codes) sayfasına bakın: `0` temiz, `1` bulgu var, `2` hata, `3` tamamlanmadan kesildi.

---

### `scan fs`

Bir veya daha fazla yerel dosya sistemi yolunu tarar — her biri bir dizin (özyinelemeli olarak dolaşılır) veya tek bir dosya olabilir.

```bash
leakwatch scan fs [path...] [flags]
```

**Sıfır veya daha fazla** konumsal argüman kabul eder. Yol verilmediğinde `.` (geçerli dizin) taranır. Tek bir çağrıda dosya ve dizinler karıştırılarak birden fazla yol verilebilir.

#### Dosya sistemine özgü bayraklar

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--exclude <pattern>` | — | Dışlanacak yollar için glob kalıbı. Tekrarlanabilir. |

#### Örnekler

```bash
# Geçerli dizini tara, renklendirilmiş tablo yazdır
leakwatch scan fs . --format table

# Tek bir dosyayı tara
leakwatch scan fs cmd/main.go

# Birden fazla dosya ve dizini birlikte tara
leakwatch scan fs cmd/ main.go internal/config

# SARIF çıktısını kaydet, test dosyalarını ve vendor'ı dışla
leakwatch scan fs . \
  --exclude "**/*_test.go" \
  --exclude "vendor/**" \
  --format sarif \
  --output results.sarif

# Bu çalıştırma için belirli dedektörleri hariç tut
leakwatch scan fs . --exclude-detectors aws-access-key-id,generic-api-key
```

---

### `scan git`

Yerel veya uzak bir Git deposunun tam commit geçmişini tarar.

```bash
leakwatch scan git <url_or_path> [flags]
```

Tam olarak bir konumsal argüman gereklidir: yerel bir yol veya HTTP/HTTPS/SSH URL'si.

#### Git'e özgü bayraklar

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--since <YYYY-MM-DD>` | — | Yalnızca bu tarihten sonraki commit'leri tara. |
| `--since-commit <hash>` | — | Yalnızca bu commit karmasından HEAD'e kadar olan değişiklikleri tara. |
| `--branch <name>` | — | Varsayılan dal yerine belirli bir dalı hedefle. |
| `--depth <int>` | `0` (tam) | Uzak depolar için sığ klonlama derinliği. `0` tam geçmişi getirir. |
| `--exclude <pattern>` | — | Dışlanacak blob yolları için glob kalıbı. Tekrarlanabilir. |

#### Örnekler

```bash
# Tam yerel geçmişi tara
leakwatch scan git . --format table

# Bir pull request tarafından eklenen commit'leri tara
leakwatch scan git . --since-commit a1b2c3d --format json
```

---

### `scan image`

Bir OCI/Docker imajının katmanlarını sırlar açısından tarar. Leakwatch daemonsuz çalışır ve kayıt defterinden doğrudan çeker — Docker soketi gerekmez.

```bash
leakwatch scan image <image:tag> [flags]
```

Tam olarak bir konumsal argüman gereklidir. Ortak tarama bayraklarının ötesinde imaja özgü bir bayrak yoktur; ortak bayraklar arasında, katmanlar içindeki dosya yollarıyla eşleştirilen `--exclude <pattern>` (tekrarlanabilir) de bulunur.

#### Örnekler

```bash
# Genel bir imajı tara
leakwatch scan image nginx:latest --format table

# Özel kayıt defteri imajını tara, JSON çıktısını kaydet
leakwatch scan image registry.example.com/my-app:v2.3.0 \
  --format json \
  --output image-results.json
```

---

### `scan s3`

Bir AWS S3 kovasındaki nesneleri tarar.

```bash
leakwatch scan s3 <bucket> [flags]
```

Tam olarak bir konumsal argüman gereklidir.

#### S3'e özgü bayraklar

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--prefix <string>` | — | Taramayı, anahtarı bu ön ekle başlayan nesnelerle sınırla. |
| `--region <string>` | — | Kovanın bulunduğu AWS bölgesi. `AWS_REGION` ortam değişkenine veya AWS SDK varsayılanına geri döner. |
| `--exclude <pattern>` | — | Dışlanacak nesne anahtarları için glob kalıbı. Tekrarlanabilir. |

#### Örnekler

```bash
# Tüm kovayı tara
leakwatch scan s3 my-data-bucket --region us-east-1 --format table

# Belirli bir ön eki tara
leakwatch scan s3 my-data-bucket --prefix backups/2026/ --format json
```

---

### `scan gcs`

Bir Google Cloud Storage kovasındaki nesneleri tarar.

```bash
leakwatch scan gcs <bucket> [flags]
```

Tam olarak bir konumsal argüman gereklidir.

#### GCS'ye özgü bayraklar

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--prefix <string>` | — | Taramayı, adı bu ön ekle başlayan nesnelerle sınırla. |
| `--project <string>` | — | GCP proje kimliği. Varsayılan kimlik bilgilerinden proje çıkarılamadığında gereklidir. |
| `--exclude <pattern>` | — | Dışlanacak nesne adları için glob kalıbı. Tekrarlanabilir. |

#### Örnekler

```bash
# Tüm GCS kovasını tara
leakwatch scan gcs my-gcs-bucket --project my-gcp-project --format table

# Ön ek tara
leakwatch scan gcs my-gcs-bucket --prefix uploads/2026/ --format json
```

---

### `scan slack`

Bir Slack çalışma alanındaki mesaj metnini tarar.

```bash
leakwatch scan slack [flags]
```

Konumsal argüman yoktur.

#### Slack'e özgü bayraklar

| Bayrak | Varsayılan | Açıklama |
|--------|-----------|----------|
| `--token <string>` | — | Slack bot token'ı. `LEAKWATCH_SLACK_TOKEN` ortam değişkeni ile de ayarlanabilir. |
| `--channels <list>` | — | Taranacak kanal adları veya kimliklerinin virgülle ayrılmış listesi. Atlandığında erişilebilir tüm kanalları tarar. |
| `--exclude-channels <list>` | — | Atlanacak kanal adları veya kimliklerinin virgülle ayrılmış listesi. |
| `--since <YYYY-MM-DD>` | — | Yalnızca bu tarihten sonra gönderilen mesajları tara. |
| `--include-dms` | `false` | Doğrudan mesajları dahil et (ek OAuth kapsamları gerektirir). |
| `--rate-limit <float>` | `1` | Saniye başına maksimum Slack API isteği. |

`scan slack` komutunda (diğer her tarama alt komutunun aksine) `--exclude` yol-kalıbı bayrağı yoktur — bunun yerine tüm kanalları atlamak için `--exclude-channels` kullanın.

#### Örnekler

```bash
# Erişilebilir tüm kanalları tara
leakwatch scan slack --token xoxb-••••••••••••-••••••••••••-•••••••••••••••••••••••• --format table

# Belirli kanalları belirli bir tarihten itibaren tara
leakwatch scan slack \
  --token xoxb-••••••••••••-••••••••••••-••••••••••••••••••••••••• \
  --channels general,engineering \
  --since 2026-01-01 \
  --format json
```

---

### `scan repos`

Birden fazla Git deposunu paralel olarak tarar.

```bash
leakwatch scan repos <url_or_path...> [flags]
```

En az iki konumsal argüman (depo URL'leri veya yerel yollar) gereklidir.

#### Repos'a özgü bayraklar

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|-----------|----------|
| `--parallel` | — | `3` | Eşzamanlı olarak taranacak depo sayısı. |
| `--concurrency` | `-c` | CPU sayısı | Her depo taramasındaki çalışan eşzamanlılığı. |
| `--exclude <pattern>` | — | — | Her depoya uygulanan, dışlanacak blob yolları için glob kalıbı. Tekrarlanabilir. |

#### Örnekler

```bash
# İki depoyu paralel olarak tara
leakwatch scan repos \
  https://github.com/org/repo-a.git \
  https://github.com/org/repo-b.git \
  --format json

# Büyük bir depo seti için paralellizmi artır
leakwatch scan repos \
  https://github.com/org/repo-a.git \
  https://github.com/org/repo-b.git \
  https://github.com/org/repo-c.git \
  --parallel 3 \
  --format sarif \
  --output multi-repo.sarif
```

---

## Ayrıca bakın

- [Çıkış Kodları](#/reference/exit-codes) — çıkış kodlarının tarama sonuçlarıyla nasıl eşleştiği.
- [Ortam Değişkenleri](#/reference/environment-variables) — Leakwatch'ı bayrak kullanmadan yapılandırma.
- [Dosya Sistemi Taraması](#/scanning/filesystem) — ayrıntılı `scan fs` rehberi.
- [Git Geçmişi](#/scanning/git-history) — ayrıntılı `scan git` rehberi.
- [Yapılandırma Dosyası](#/configuration/config-file) — `.leakwatch.yaml` başvurusu.
