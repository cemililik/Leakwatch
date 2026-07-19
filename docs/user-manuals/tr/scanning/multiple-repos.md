---
title: "Çoklu Depo"
description: "Birden fazla Git deposunu eşzamanlı olarak tarayın ve sonuçları tek bir raporda birleştirin."
---

# Çoklu Depo

Bir kuruluş büyüdükçe sırlar düzinelerce hatta yüzlerce deponun herhangi birine yerleşebilir. Bunları tek tek kontrol etmek pratik değildir. `leakwatch scan repos`, birden fazla depo URL'sini alır, bunları eşzamanlı olarak tarar ve tüm bulguları tek bir çıktıda birleştirir — tek komut, tek rapor.

## Temel kullanım

```bash
leakwatch scan repos <url1> <url2> [url...]
```

Komut **en az iki** depo URL'si gerektirir. Tüm depolar otomatik olarak klonlanır, taranır ve temizlenir. Sonunda birleşik bulgu sayısı ve tek bir tarama özeti raporlanır.

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git
```

## Nasıl çalışır

Leakwatch aynı anda en fazla `--parallel` sayıda depo taraması başlatır. Her depo:

1. Sağlanan URL'den klonlanır (güvenlik açısından kimlik bilgileri günlüklerden ve çıktıdan ayıklanır).
2. Tam tespit hattıyla taranır; bu depo için `--concurrency` sayıda çalışan kullanılır.
3. Tarama tamamlandığında temizlenir (geçici klon silinir).

Tüm depolardan elde edilen bulgular toplanır ve tek bir kaynaktan yapılmış tarama gibi tek bir çıktı olarak yazılır. Görüntülenen hedef `<N> repositories` (N depo) şeklindedir.

## Bayraklar

### Çoklu depoya özgü

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--parallel` | int | `3` | Eşzamanlı olarak taranacak depo sayısı. |

### Ortak tarama bayrakları

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | **Depo başına** eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu boyutu aşan blob'ları atla (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude` | — | — | Her deponun taramasından dışlanacak yol kalıbı. Tekrarlanabilir; `filter.exclude-paths` ile birleştirilir. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri (örn. `aws-access-key-id`). Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

`.leakwatch.yaml` dosyasındaki `filter.exclude-paths` yol dışlamaları (veya `--exclude`) tüm depolara uygulanır. `--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir.

## Örnekler

İki depoyu tarayın ve sonuçları tablo olarak görüntüleyin:

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git \
  --format table
```

Beş depoyu daha yüksek paralellik ile tarayın ve birleşik sonuçları SARIF olarak kaydedin:

```bash
leakwatch scan repos \
  https://github.com/org/api.git \
  https://github.com/org/web.git \
  https://github.com/org/infra.git \
  https://github.com/org/mobile.git \
  https://github.com/org/docs.git \
  --parallel 4 \
  --format sarif \
  --output all-repos.sarif
```

Depo başına daha fazla çalışan kullanarak yalnızca doğrulanmış bulguları gösterin:

```bash
leakwatch scan repos \
  https://github.com/org/backend.git \
  https://github.com/org/frontend.git \
  --concurrency 8 \
  --only-verified \
  --format json \
  --output verified-findings.json
```

## Paralelliği ayarlama

Verimi kontrol eden iki parametre vardır:

- `--parallel`, kaç depo klonlama ve taramasının aynı anda çalışacağını kontrol eder. Varsayılan `3`, çoğu iş yükü için uygundur. Ağ bant genişliği ve CPU kapasitesi izin verdiğinde artırın; kısıtlı makinelerde düşürün.
- `--concurrency` (`-c`), her bir depodaki dosya blob'larını işleyen çalışan goroutine sayısını kontrol eder. Bu, tüm tarama komutlarında bulunan aynı bayraktır.

Tepe noktasındaki toplam eşzamanlı işlem = `--parallel` × `--concurrency`.

:::note
Bir veya daha fazla depo taraması başarısız olursa (örneğin ağ hatası veya kimlik doğrulama sorunu nedeniyle), Leakwatch hatayı günlüğe kaydeder ve kalan depoları taramaya devam eder. **Bulgular önceliklidir**: filtrelemeden sonra tüm çalıştırma genelinde tek bir bulgu bile kalırsa, bazı depoların taraması başarısız olsa dahi çıkış kodu `1` olur. Çıkış kodu `2` (depo tarama hatası) yalnızca genel olarak sıfır bulgu raporlandığında döndürülür.
:::

## Kimlik bilgisi güvenliği

Depo URL'lerindeki gömülü kimlik bilgileri (örn. `https://user:TOKEN@host/repo.git`), URL günlüklere, çıktıya veya tarama özetine yazılmadan önce ayıklanır.

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tüm depo taramaları tamamlandı, bulgu yok. |
| `1` | Filtrelemeden sonra bir veya daha fazla bulgu kaldı — bazı depoların taraması başarısız olsa veya çalıştırma kesintiye uğrasa bile döndürülür; böylece "sır bulundu" sinyali ilgisiz bir hata tarafından hiçbir zaman gizlenmez. |
| `2` | Sıfır bulgu raporlandı ve bir veya daha fazla depo taraması başarısız oldu, ya da bir yapılandırma hatası oluştu. |
| `3` | Çalıştırma tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve sıfır bulgu raporlanmıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

## Ayrıca bakın

- [Git Geçmişi](#/scanning/git-history) — tek bir depoyu derinlemesine tarayın.
- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Yapılandırma Dosyası](#/configuration/config-file) — tüm kaynaklar için paylaşılan varsayılanları yapılandırın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — bilinen yanlış pozitifleri bastırın.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
