---
title: "Dosya Sistemi"
description: "leakwatch scan fs komutuyla yerel bir dizin ağacını sızan sırlara karşı tarayın."
---

# Dosya Sistemi

Sırlar çoğu zaman önce yerel kaynak kodda ortaya çıkar. `leakwatch scan fs` komutu, bir dizin ağacındaki tüm dosyaları dolaşır, her biri üzerinde tam tespit hattını çalıştırır ve bulguları raporlar — henüz commit edilmeden önce yakalamak ya da mevcut bir kod tabanını sonradan taramak için kullanabilirsiniz.

## Temel kullanım

```bash
leakwatch scan fs [path...]
```

`path`, **sıfır veya daha fazla** argüman kabul eder; atlandığında Leakwatch geçerli çalışma dizinini (`.`) tarar. Her yol bir dizin (özyinelemeli olarak dolaşılır) veya tek bir dosya olabilir — tek bir çağrıda dosyaları ve dizinleri karıştırıp birden fazlasını geçebilirsiniz.

```bash
# Geçerli dizini tara
leakwatch scan fs

# Belirli bir proje klasörünü tara
leakwatch scan fs ./my-project

# Tek bir dosyayı tara
leakwatch scan fs cmd/main.go

# Birden fazla dosya ve dizini birlikte tara
leakwatch scan fs cmd/ main.go internal/config
```

## Dosya sistemi kaynağının otomatik olarak atladıkları

Taramaları hızlı ve gürültüsüz tutmak için dosya sistemi kaynağı herhangi bir yapılandırma gerekmeksizin şunları atlar:

- **İkili dosyalar** — dosyanın ilk 8 KB'ında null byte bulunmasıyla tespit edilir.
- **Bilinen ikili uzantılar** — yaygın derlenmiş, görsel, ses, video ve arşiv biçimleri.
- **Kilit dosyaları** — `package-lock.json`, `yarn.lock`, `Pipfile.lock` ve benzerleri.
- **`.git` dizinleri** — Git nesne/paket deposu asla dolaşılmaz veya düz dosya olarak okunmaz, çünkü commit geçmişini taramanın özel yolu `scan git`'tir. Bu, dolaşım sırasında karşılaşılan herhangi bir `.git` dizini için geçerlidir; `.git`'i tarama yolu olarak açıkça verirseniz bu muafiyet uygulanmaz ve normal şekilde taranır. Ayrıca etkilenmeyen bir diğer nokta: döngüleri önlemek için sembolik bağlantılar her zaman atlanır.

## Bayraklar

### Dosya sistemine özgü

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--exclude` | string (tekrarlanabilir) | — | Dışlanacak yollar için glob desenleri. Birden fazla kez belirtilebilir veya virgülle ayrılabilir. |

### Ortak tarama bayrakları

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu boyutu aşan dosyaları atla (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri. Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

`--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir.

## Örnekler

Geçerli dizini tarayın ve terminalde renklendirilmiş bir tablo yazdırın:

```bash
leakwatch scan fs . --format table
```

Test dosyalarını ve vendor dizinlerini dışlayıp GitHub Code Scanning için SARIF çıktısı kaydedin:

```bash
leakwatch scan fs . \
  --exclude "**/*_test.go" \
  --exclude "vendor/**" \
  --format sarif \
  --output results.sarif
```

Büyük bir monorepo için dosya boyutunu sınırlayın ve çalışan sayısını artırın:

```bash
leakwatch scan fs . --max-file-size 5242880 --concurrency 8 --format table
```

Yalnızca yüksek önem dereceli bulguları gösterip rotasyon talimatlarını dahil edin:

```bash
leakwatch scan fs . --min-severity high --remediation --format table
```

## Yolları dışlama

`--exclude` bayrağı glob desenlerini kabul eder ve birden fazla kez belirtilebilir ya da virgülle ayrılmış liste olarak kullanılabilir:

```bash
# İki ayrı bayrak
leakwatch scan fs . --exclude "**/*_test.go" --exclude "docs/**"

# Virgülle ayrılmış
leakwatch scan fs . --exclude "**/*_test.go,docs/**"
```

Takımınızla paylaşılan kalıcı dışlama kuralları için `.leakwatch.yaml` dosyasına `filter.exclude-paths` altında ekleyin. Bu kurallar yalnızca dosya sistemi taramalarına değil, tüm kaynaklara uygulanır. Proje kök dizininizde bir `.leakwatchignore` dosyası da oluşturabilirsiniz. Ayrıntılar için [Yapılandırma Dosyası](#/configuration/config-file) ve [Bulguları Yoksayma](#/configuration/ignoring-findings) sayfalarına bakın.

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı, bulgu yok. |
| `1` | Tarama tamamlandı, bulgular raporlandı. |
| `2` | Tarama başarısız oldu (yapılandırma hatası, okunamayan yol, vb.). |
| `3` | Tarama tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve hiçbir bulgu raporlanmamıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti (kaynak türü, hedef, dosya sayısı, süre ve bulgu sayısı) yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

:::tip
Geliştirme sırasında `leakwatch scan fs . --format table` komutunu çalıştırarak hızlı bir görsel genel bakış elde edin. CI hatlarında GitHub Code Scanning ile entegrasyon için `--format sarif` seçeneğine geçin.
:::

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Yapılandırma Dosyası](#/configuration/config-file) — varsayılan biçimi, dışlamaları ve daha fazlasını yapılandırın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — `.leakwatchignore` ve satır içi baskılama.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [Git Geçmişi](#/scanning/git-history) — çalışma ağacı yerine commit edilmiş geçmişi tarayın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
