---
title: "Bulut Depolama (S3 & GCS)"
description: "AWS S3 ve Google Cloud Storage kovalarını sızan sırlara karşı tarayın."
---

# Bulut Depolama (S3 & GCS)

Sırlar sıklıkla bulut depolamaya taşınır — dışa aktarılan veritabanı dökümleri, ortam dosyaları, CI artefaktları ve günlük arşivleri, düşünüldüğünden çok daha fazla kişinin erişebildiği kovalara akar. Leakwatch, AWS S3 ve Google Cloud Storage kovalarını nesne nesne tarayabilir ve bulduğu sırları bir olaya dönüşmeden işaretler.

## AWS S3

### Kullanım

```bash
leakwatch scan s3 <bucket>
```

Komut tam olarak bir argüman alır: **kova adı** (`s3://` öneki olmadan). Tarama hedefi `s3://<bucket>` olarak gösterilir.

### Kimlik doğrulama

Leakwatch standart [AWS varsayılan kimlik bilgisi zincirini](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) kullanır:

1. Ortam değişkenleri (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).
2. Paylaşılan kimlik bilgileri dosyası (`~/.aws/credentials`).
3. Paylaşılan yapılandırma dosyası (`~/.aws/config`).
4. Örneğe veya göreve atanmış IAM rolü (EC2, ECS, Lambda).

AWS CLI ile zaten kimlik doğrulaması yaptıysanız (`aws configure` veya üstlenilmiş bir rol) ek yapılandırma gerekmez.

### S3'e özgü bayraklar

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--prefix` | string | — | Yalnızca anahtarı bu önekle başlayan nesneleri tara. |
| `--region` | string | AWS yapılandırmasından | Kovanın bulunduğu AWS bölgesi. |

### S3 örnekleri

Tüm kovayı tarayın:

```bash
leakwatch scan s3 my-config-bucket
```

Belirli bir bölgede belirli bir anahtar öneki altındaki nesneleri tarayın:

```bash
leakwatch scan s3 my-bucket --prefix logs/ --region us-east-1
```

SARIF olarak kaydedin:

```bash
leakwatch scan s3 my-bucket --format sarif --output s3-results.sarif
```

:::tip
Taramayı ilgili bir alt yola sınırlamak için `--prefix` kullanın. Milyonlarca nesne içeren büyük bir kovayı taramak yavaş olabilir ve S3 GET istek maliyeti doğurabilir. Öneki gerçekten önemli olana — örneğin `configs/` veya `exports/` — daraltın.
:::

---

## Google Cloud Storage

### Kullanım

```bash
leakwatch scan gcs <bucket>
```

Komut tam olarak bir argüman alır: **kova adı** (`gs://` öneki olmadan). Tarama hedefi `gs://<bucket>` olarak gösterilir.

### Kimlik doğrulama

Leakwatch [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials) kullanır. Kimlik bilgisi arama sırası şu şekildedir:

1. Hizmet hesabı anahtar dosyasına işaret eden `GOOGLE_APPLICATION_CREDENTIALS` ortam değişkeni.
2. `gcloud auth application-default login` ile yapılandırılmış kullanıcı kimlik bilgileri.
3. Google Compute Engine örneğine, Cloud Run hizmetine veya GKE iş yüküne atanmış hizmet hesabı.

### GCS'ye özgü bayraklar

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--prefix` | string | — | Yalnızca adı bu önekle başlayan nesneleri tara. |
| `--project` | string | — | GCP proje kimliği (bazı ADC yapılandırmalarında gereklidir). |

### GCS örnekleri

Belirli bir GCP projesiyle tüm kovayı tarayın:

```bash
leakwatch scan gcs my-config-bucket --project my-gcp-project
```

Yalnızca belirli bir önek altındaki nesneleri tarayın:

```bash
leakwatch scan gcs my-bucket --project my-gcp-project --prefix exports/
```

CSV olarak çıktı alın:

```bash
leakwatch scan gcs my-bucket --format csv --output gcs-results.csv
```

---

## Ortak tarama bayrakları

Hem `s3` hem de `gcs` aynı ortak tarama bayraklarını destekler:

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu boyutu aşan nesneleri atla (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude` | — | — | Dışlanacak nesne anahtarı kalıbı. Tekrarlanabilir; `filter.exclude-paths` ile birleştirilir. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri. Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

Nesne anahtarlarına uygulanan yol dışlamaları `.leakwatch.yaml` dosyasında `filter.exclude-paths` altında ya da her çalıştırma için `--exclude` ile yapılandırılır. `--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir.

## Bulgu meta verisi

Bir S3 veya GCS bulgusu yalnızca her kaynakta ortak olan alanları ve `<bucket>/<object-key>` olarak ayarlanan `file_path` alanını taşır (bulut depolama bulguları için ayrı bir `line` alanı yoktur).

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı, bulgu yok. |
| `1` | Tarama tamamlandı, bulgular raporlandı. |
| `2` | Tarama başarısız oldu (kimlik doğrulama hatası, kova bulunamadı, vb.). |
| `3` | Tarama tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve hiçbir bulgu raporlanmamıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Yapılandırma Dosyası](#/configuration/config-file) — dışlamaları ve diğer varsayılanları yapılandırın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — bilinen yanlış pozitifleri bastırın.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [Dosya Sistemi](#/scanning/filesystem) — yerel bir dizin ağacını tarayın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
