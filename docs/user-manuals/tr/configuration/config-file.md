---
title: "Yapılandırma Dosyası"
description: "Leakwatch'ı .leakwatch.yaml ile yapılandırma — tam şema, varsayılanlar, doğrulama kuralları, ortam değişkeni geçersiz kılmaları ve leakwatch init komutu."
---

# Yapılandırma Dosyası

Leakwatch'ın her tarama komutundaki davranışı, `.leakwatch.yaml` adlı tek bir YAML dosyasıyla yönetilir. Bu dosyayı anlamak; eşzamanlılık, doğrulama, çıktı biçimi ve yol filtrelemeyi bir kez ayarlamanızı ve her taramanın bu ayarları otomatik olarak almasını sağlar.

## Dosya keşfi

Leakwatch, yapılandırma dosyasını aşağıdaki sırayla çözer:

1. **`--config <path>` bayrağı** — çalışma dizininden bağımsız olarak açık bir yol kullanır.
2. **Geçerli dizin** — komutun çalıştırıldığı dizindeki `.leakwatch.yaml`.
3. **Ana dizin** — yedek olarak `~/.leakwatch.yaml`.

Hiçbir dosya bulunamazsa, her ayar için yerleşik varsayılanlar kullanılır. Bir dosya bulunur**sa** (veya `--config` bir dosyayı işaret ederse) ama geçerli bir YAML olarak ayrıştırılamazsa, bu ölümcül bir hatadır — tarama sessizce varsayılanlara geri dönmez, çünkü bunu yapmak operatörün yapılandırdığı sınırların ötesinde tespit kapsamını sessizce genişletebilir.

## Başlangıç dosyası oluşturma

`leakwatch init` komutu, önerilen varsayılanlarla düzenlemeye hazır bir dosya yazar:

```bash
leakwatch init
```

Varsayılan olarak dosya, geçerli dizindeki `.leakwatch.yaml` konumuna yazılır. Farklı bir yol seçmek için `--output` kullanın:

```bash
leakwatch init --output /etc/leakwatch/.leakwatch.yaml
```

Hedef dosya zaten mevcutsa, `leakwatch init` üzerine yazmayı reddeder ve hata vererek çıkar. Üzerine yazmak için `--force` kullanın:

```bash
leakwatch init --force
```

## Ortam değişkeni geçersiz kılmaları

Her yapılandırma anahtarı bir ortam değişkeniyle geçersiz kılınabilir. İsimlendirme kuralı şudur:

- Önek: `LEAKWATCH_`
- `.` ve `-` karakterlerini `_` ile değiştirin
- Büyük harfe çevirin

Örnekler:

| Yapılandırma anahtarı | Ortam değişkeni |
|---|---|
| `scan.concurrency` | `LEAKWATCH_SCAN_CONCURRENCY` |
| `verification.rate-limit` | `LEAKWATCH_VERIFICATION_RATE_LIMIT` |
| `output.format` | `LEAKWATCH_OUTPUT_FORMAT` |
| `detection.entropy.threshold` | `LEAKWATCH_DETECTION_ENTROPY_THRESHOLD` |

## Öncelik sırası

Aynı ayar birden fazla yerde belirtildiğinde, en yüksek öncelikli kaynak kazanır:

1. Komut satırı bayrağı (en yüksek)
2. Ortam değişkeni
3. Yapılandırma dosyası değeri
4. Yerleşik varsayılan (en düşük)

## Tam şema

Aşağıdaki açıklamalı şema, desteklenen her anahtarı, varsayılan değerini ve geçerli aralığını göstermektedir.

```yaml
# ── Tarama motoru ─────────────────────────────────────────────────────────────

scan:
  # Eşzamanlı dosya işleme worker sayısı.
  # Varsayılan olarak ana makinedeki mantıksal CPU çekirdeği sayısı kullanılır.
  # >= 1 olmalıdır.
  concurrency: 8

  # Taranacak maksimum dosya boyutu (bayt cinsinden). Bu sınırı aşan dosyalar
  # tamamen atlanır. Varsayılan: 10 MB (10485760). >= 1 olmalıdır.
  max-file-size: 10485760

# ── Tespit ────────────────────────────────────────────────────────────────────

detection:
  entropy:
    # Her aday eşleşme için Shannon entropi hesaplamasını etkinleştirir.
    enabled: true

    # Gösterim için kullanılan ve yerleşik generic-api-key dedektörüyle kendi
    # entropy alanına sahip her özel kuralı kapılayan entropi eşiği.
    # Aralık: 0–8. Varsayılan: 4.0.
    # Yerleşik bulgular hakkındaki nota bakın.
    threshold: 4.0

# ── Doğrulama ─────────────────────────────────────────────────────────────────

verification:
  # Sağlayıcı API'lerine karşı canlı doğrulamayı etkinleştirir.
  enabled: true

  # İstek başına HTTP zaman aşımı. Doğrulama etkinleştirildiğinde >= 1ms olmalıdır.
  # Süre dizesi kullanın (örn. "10s", "500ms") — tam sayı nanosaniye olarak
  # yorumlanır ve doğrulama başarısız olur.
  timeout: 10s

  # Eşzamanlı doğrulama worker sayısı. >= 1 olmalıdır.
  concurrency: 4

  # Saniyedeki maksimum doğrulama isteği (token-bucket hız sınırlayıcı).
  # > 0 olmalıdır.
  rate-limit: 10.0

# ── Filtreleme ────────────────────────────────────────────────────────────────

filter:
  # Taramadan hariç tutulacak yollar için glob desenleri.
  # Desteklenen glob stilleri: filepath.Match desenleri, sıfır veya daha fazla
  # yol segmentini kapsayan ** çift yıldız ve herhangi bir derinlikte adlandırılmış
  # dizini eşleştiren sondaki eğik çizgili dir/ desenleri. Her desen hem tam yol
  # hem de temel dosya adına karşı test edilir.
  # Tüm tarama kaynaklarına uygulanır. (`scan slack` hariç her tarama alt
  # komutunda bulunan --exclude bayrağı, bu listenin yerine geçmek yerine
  # çalışma zamanında ona ekleme yapar.)
  # Varsayılan: [] (yerleşik ikili/kilit dosya atlamalarının ötesinde hariç tutma yok).
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "go.sum"
    - "package-lock.json"
    - "yarn.lock"

  # Tamamen devre dışı bırakılacak dedektör ID'leri. Listelenen dedektörlerden
  # gelen bulgular, diğer ayarlardan bağımsız olarak hiçbir zaman üretilmez.
  # Varsayılan: [].
  # Her tarama alt komutunda bulunan --exclude-detectors bayrağı, bu listenin
  # yerine geçmek yerine çalışma zamanında ona ekleme yapar.
  exclude-detectors: []

# ── Çıktı ─────────────────────────────────────────────────────────────────────

output:
  # Çıktı biçimi. Şunlardan biri: json, sarif, csv, table, github. Varsayılan: json.
  # --format / -f bayrağı bunu çalışma zamanında geçersiz kılar.
  format: json

  # Çıktıyı stdout yerine bu dosya yoluna yaz. Varsayılan: "" (stdout).
  # --output / -o bayrağı bunu çalışma zamanında geçersiz kılar. Uzantısız düz
  # bir yol, biçimin kendi uzantısıyla otomatik olarak tamamlanır ve dosya
  # 0600 izinleriyle yazılır. Her zaman stdout'a yazan "github" biçiminde
  # yok sayılır.
  file: ""

  # Bu önem seviyesinin altındaki bulguları bırak.
  # Şunlardan biri: low, medium, high, critical. Varsayılan: "" (tümünü göster).
  # --min-severity bayrağı bunu çalışma zamanında geçersiz kılar.
  severity-threshold: ""

  # Çıktıda maskelenmemiş sır değerini dahil et.
  # Varsayılan: false. --show-raw bayrağı bunu çalışma zamanında geçersiz kılar.
  show-raw: false

# ── Özel kurallar ─────────────────────────────────────────────────────────────

# Kendi dedektörlerinizi YAML kuralları olarak tanımlayın. Tam kural şeması
# için özel kurallar sayfasına bakın.
# custom-rules:
#   - id: "my-internal-token"
#     description: "Internal Service Token"
#     regex: "mycompany_[a-zA-Z0-9]{32}"
#     keywords: ["mycompany_"]
#     severity: critical
custom-rules: []
```

:::note
`detection.entropy.enabled`, hesaplanan entropi değerinin bulguların yanında bulunup bulunmadığını kontrol eder. `detection.entropy.threshold` gösterimi kontrol etmez; motor entropi sezgisini tercih eden dedektörleri kapılar — şu anda yalnızca yerleşik `generic-api-key` dedektörü. Entropisi eşiğin altına düşen bir eşleşme olası bir yer tutucu olarak bastırılır. Kendi `entropy` alanını bildiren özel kurallar bağımsız kural-başı eşiklerini uygular. Diğer her yapısal/biçim-çapalı yerleşik dedektör — `aws-access-key-id`, `github-token` ve diğerleri — entropiden bağımsız olarak motor eşiği tarafından **hiçbir zaman** bırakılmaz.
:::

## Doğrulama

Leakwatch, taramaya başlamadan önce yüklenen yapılandırmayı doğrular ve aşağıdaki durumların herhangi birinde hata vererek çıkar:

| Koşul | Hata |
|---|---|
| `scan.concurrency < 1` | Geçersiz eşzamanlılık değeri |
| `scan.max-file-size < 1` | Geçersiz max-file-size değeri |
| `output.format` `json\|sarif\|csv\|table\|github` içinde değil | Desteklenmeyen çıktı biçimi |
| `detection.entropy.threshold` 0–8 dışında | Geçersiz entropi eşiği |
| `output.severity-threshold` geçerli bir seviye değil (boş değilse) | Geçersiz severity-threshold |
| `verification.timeout < 1ms` (doğrulama etkinleştirildiğinde) | Geçersiz doğrulama zaman aşımı |
| `verification.concurrency < 1` (doğrulama etkinleştirildiğinde) | Geçersiz doğrulama eşzamanlılığı |
| `verification.rate-limit <= 0` (doğrulama etkinleştirildiğinde) | Geçersiz doğrulama rate-limit |

## Ayrıca bakın

- [Bulguları Yok Sayma](#/configuration/ignoring-findings)
- [Önem Derecesi & Filtreleme](#/configuration/severity-and-filtering)
- [Özel Kurallar](#/detectors/custom-rules)
- [Ortam Değişkenleri](#/reference/environment-variables)
