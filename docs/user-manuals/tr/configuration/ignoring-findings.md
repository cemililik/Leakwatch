---
title: "Bulguları Yok Sayma"
description: ".leakwatchignore dosyaları, satır içi yok sayma işaretçileri ve yerleşik ikili dosya ve kilit dosyası atlamaları ile yanlış pozitifleri bastırın."
---

# Bulguları Yok Sayma

Hiçbir tarayıcının yanlış pozitif oranı sıfır değildir. Leakwatch, gürültüyü bastırmak için size üç katmanlı mekanizma sunar: yol tabanlı dışlamalar için bir `.leakwatchignore` dosyası, satır düzeyinde bastırma için satır içi işaretçiler ve ikili dosyalar ile yaygın kilit dosyaları için her zaman etkin olan yerleşik atlamalar.

## `.leakwatchignore` dosyası

Tarama sonuçlarından yolları hariç tutmak için depo kökünüze (veya geçerli dizine) bir `.leakwatchignore` dosyası oluşturun. Gitignore stilinde söz dizimi kullanır:

- `#` ile başlayan satırlar yorum satırlarıdır.
- Boş satırlar atlanır.
- `!` öneki bir deseni **geçersiz kılar**; önceki bir desen tarafından dışlanmış olacak bir yolu yeniden dahil eder.
- **Son eşleşen desen kazanır** — sıra önemlidir.

### Yükleme sırası

Leakwatch, bulduğu **ilk** `.leakwatchignore` dosyasını yükler; önce tarama kökünü, ardından yedek olarak geçerli çalışma dizinini kontrol eder. Her tarama için yalnızca bir dosya kullanılır — tarama kökünde bir `.leakwatchignore` varsa, geçerli dizindeki dosya (varsa) hiçbir zaman açılmaz, birleştirilmesi bir yana. Dosyalar arası öncelik veya birleştirme yoktur: öngörülebilir bir davranış için kurallarınızı tarama kökündeki tek bir `.leakwatchignore` dosyasında toplayın.

### Glob söz dizimi

Üç desen stili desteklenir:

| Stil | Açıklama | Örnek |
|---|---|---|
| Standart glob | `filepath.Match` stili, hem tam yola hem de temel dosya adına karşı eşleştirilen | `*.pem` |
| Çift yıldız `**` | Sıfır veya daha fazla yol segmentini kapsar | `test/fixtures/**` |
| Sondaki eğik çizgi `dir/` | Adlandırılmış dizinin herhangi bir derinliğindeki her dosyayla eşleşir | `snapshots/` |

### `.leakwatchignore` örneği

```text
# Tüm test fixture dosyalarını yok say
test/fixtures/**

# Dokümantasyondaki bilinen yer tutucu anahtarları yok say
docs/examples/

# Ağaçtaki herhangi bir yerdeki belirli uzantılı dosyaları yok say
*.pem.example

# Yukarıdaki kural tarafından dışlanan belirli bir dosyayı yeniden dahil et
!docs/examples/real-config-sample.yaml
```

:::note
`.leakwatchignore` filtrelemesi, her bulgunun dosya yoluna göre tarama tamamlandıktan **sonra** uygulanır. Dosyaların okunmasını engellemez — ürettikleri bulguları bastırır. Dosyaları okunmadan önce atlamak için yapılandırma dosyasında `filter.exclude-paths` veya `scan fs` komutunda `--exclude` kullanın.
:::

## Satır içi yok sayma işaretçileri

Söz konusu satırdaki dedektörleri bastırmak için herhangi bir kaynak satırına doğrudan bir işaretçi koyun. İşaretçi satırın herhangi bir yerine yerleştirilebilir — genellikle bir yorum içinde — ve motor tarafından doğrulamadan **önce** uygulanır; böylece yok sayılan bir satır hiçbir zaman ağ çağrısını tetiklemez.

### Bir satırdaki tüm dedektörleri bastır

```python
# Ödeme işleme yapılandırması
STRIPE_KEY = "sk_test_XXXXXXXXXXXXXXXXXXXX"  # leakwatch:ignore
```

### Bir satırdaki belirli bir dedektörü bastır

Yalnızca bir dedektörü bastırırken diğerlerini etkin bırakmak için `leakwatch:ignore:<detector-id>` kullanın:

```go
// Bu token dokümantasyon için kasıtlı olarak bir yer tutucudur
exampleToken := "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" // leakwatch:ignore:github-token
```

```yaml
# Platform tarafından ayarlanan CI ortam değişkeni — gerçek bir sır değil
api_key: "${CI_API_KEY_PLACEHOLDER}"  # leakwatch:ignore:generic-api-key
```

:::tip
Mümkün olduğunda genel form yerine dedektöre özgü formu (`leakwatch:ignore:<detector-id>`) tercih edin. Hangi dedektörü bastırdığınızı belgeler ve diğer tüm dedektörleri o satırda etkin bırakır.
:::

## Yerleşik atlamalar (her zaman uygulanır)

Leakwatch, herhangi bir dedektörü çalıştırmadan önce aşağıdakileri koşulsuz olarak atlar:

**İkili dosya uzantıları** — `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, `.png`, `.jpg`, `.gif`, `.mp4`, `.zip`, `.tar`, `.gz`, `.pdf`, `.woff`, `.ttf` ve diğerleri gibi uzantılara sahip dosyalar hiçbir zaman taranmaz.

**İkili içerik tespiti** — ilk 8 KB'ı null bayt içeren herhangi bir dosya, uzantısından bağımsız olarak ikili olarak kabul edilir ve atlanır.

**Yaygın kilit dosyaları** — aşağıdaki dosya adları, yüksek oranda yanlış pozitif üreten hash ve sağlama toplamları içerdikleri için her zaman atlanır:

| Dosya |
|---|
| `package-lock.json` |
| `yarn.lock` |
| `pnpm-lock.yaml` |
| `composer.lock` |
| `Gemfile.lock` |
| `Cargo.lock` |
| `poetry.lock` |
| `go.sum` |
| `Pipfile.lock` |

Bu yerleşik atlamalar devre dışı bırakılamaz. `filter.exclude-paths` ayarından ayrıdır ve yapılandırma tabanlı filtrelemeden önce çalışır.

## Tarama öncesi yol tabanlı dışlama

Yolları tarama motoru tarafından okunmadan önce dışlamak için yapılandırma dosyanızda `filter.exclude-paths` kullanın:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "third-party/"
```

Bu ayar **tüm tarama kaynaklarına** uygulanır (dosya sistemi, Git geçmişi, konteyner imajları, bulut depolama, Slack). Yolları tarayan her `scan` alt komutunda (`fs`, `git`, `image`, `s3`, `gcs`, `repos` — bunun yerine `--exclude-channels` ile dışlama yapan `slack` hariç) komut satırında da `--exclude <pattern>` geçirebilirsiniz; tekrarlanabilir olan bu bayrak, `filter.exclude-paths`'in yerine geçmek yerine onunla birleştirilir.

Yapılandırma dosyasını düzenlemeden gürültülü bir dedektörü tek bir çalıştırma için susturmak üzere, herhangi bir tarama alt komutunda `--exclude-detectors <id>[,<id>...]` (tekrarlanabilir) geçirin — bkz. [Dedektör Kataloğu](#/detectors/detector-catalog).

Tam yapılandırma şeması için [Yapılandırma Dosyası](#/configuration/config-file), dedektör düzeyinde ve önem derecesi düzeyinde filtreleme için [Önem Derecesi & Filtreleme](#/configuration/severity-and-filtering) bölümlerine bakın.

## Ayrıca bakın

- [Yapılandırma Dosyası](#/configuration/config-file)
- [Önem Derecesi & Filtreleme](#/configuration/severity-and-filtering)
