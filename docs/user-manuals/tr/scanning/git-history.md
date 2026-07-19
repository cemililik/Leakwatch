---
title: "Git Geçmişi"
description: "Yerel veya uzak bir Git deposunun tüm commit geçmişini sızan sırlara karşı tarayın."
---

# Git Geçmişi

Commit edilip sonradan silinen bir sır, önceki her commit'te hâlâ mevcuttur ve depoya erişimi olan herkes tarafından ulaşılabilir durumdadır. `leakwatch scan git`, bir deponun — yerel veya uzak — *tüm* commit geçmişini dolaşarak bu sırları, istismar edilmeden önce gün yüzüne çıkarır.

## Temel kullanım

```bash
leakwatch scan git <url_or_path>
```

Komut tam olarak bir argüman alır: depoya giden **yerel dosya sistemi yolu** (geçerli dizin için `.`) ya da **uzak HTTP/HTTPS veya SSH URL'si**.

Leakwatch tüm Git işlemleri için [go-git](https://github.com/go-git/go-git) kullanır; bu, sistem `git` ikili dosyasına bağımlılığı olmayan saf bir Go uygulamasıdır.

```bash
# Geçerli dizindeki yerel depoyu tara
leakwatch scan git .

# HTTPS üzerinden uzak bir depoyu tara
leakwatch scan git https://github.com/org/repo.git

# SSH üzerinden tara
leakwatch scan git git@github.com:org/repo.git
```

## Tarama nasıl çalışır

Leakwatch geçmişteki her commit'i dolaşır ve her commit tarafından eklenen blob'ları inceler. **Blob-hash tekilleştirmesi**, aynı dosya içeriğinin kaç commit tarafından referans alındığından bağımsız olarak yalnızca bir kez taranmasını sağlar. Bu, tarama süresini ham commit sayısı yerine depodaki *benzersiz içerik* miktarıyla orantılı tutar.

:::note
Leakwatch commit-bazlı diff'leri incelediğinden, sonradan silinen — yani mevcut çalışma ağacında görünmeyen — sırları da bulur.
:::

## Bayraklar

### Git'e özgü

| Bayrak | Tür | Varsayılan | Açıklama |
|--------|-----|------------|----------|
| `--since` | string (YYYY-MM-DD) | — | Yalnızca bu tarihten sonraki commit'leri tara. |
| `--since-commit` | string | — | Yalnızca bu commit hash'inden HEAD'e kadar olan değişiklikleri tara (diff tabanlı). |
| `--branch` | string | — | Varsayılan yerine belirli bir dalı hedef al. |
| `--depth` | int | `0` (tam) | **Yalnızca uzak depolar** için klonlama derinliği. `0` tam geçmişi tarar. |

### Ortak tarama bayrakları

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu boyutu aşan blob'ları atla (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude` | — | — | Dışlanacak yol kalıbı. Tekrarlanabilir; `filter.exclude-paths` ile birleştirilir. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri. Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

`--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir.

## Örnekler

Yerel deponun tam geçmişini tarayın ve tablo olarak yazdırın:

```bash
leakwatch scan git . --format table
```

`develop` dalında belirli bir tarihten sonraki commit'leri tarayın:

```bash
leakwatch scan git . --since 2026-02-23 --branch develop
```

Belirli bir commit'ten bu yana tanıtılan değişiklikleri tarayın (CI'da yeni commit'leri kontrol etmek için kullanışlıdır):

```bash
leakwatch scan git . --since-commit a1b2c3d
```

Büyük bir uzak depoyu hızlandırmak için sığ klonlama yapın:

```bash
leakwatch scan git https://github.com/org/repo.git --depth 50
```

Uzak depoyu tarayıp yalnızca doğrulanmış bulguları SARIF olarak kaydedin:

```bash
leakwatch scan git https://github.com/org/repo.git \
  --only-verified \
  --format sarif \
  --output git-results.sarif
```

## Bulgu meta verisi

Git taramasından elde edilen her bulgu commit meta verisi içerir:

| Alan | Açıklama |
|------|----------|
| `repository` | Taranan deponun URL'si veya yolu (kimlik bilgileri ayıklanmış). |
| `commit` | Sırrın tanıtıldığı commit hash'i. |
| `author` | Yalnızca commit yazarının adı. |
| `email` | Commit yazarının e-posta adresi, ayrı bir alan olarak. |
| `date` | Commit zaman damgası. |
| `branch` | Dal bağlamı (kullanılabilir olduğunda). |

:::tip
Pull request CI işlerinde yalnızca PR tarafından eklenen commit'leri taramak için `--since-commit` kullanın. Son aktiviteyi kapsayan zamanlanmış gece taramaları için `--since <tarih>` tercih edin.
:::

## Kimlik bilgisi güvenliği

Depo URL'leri gömülü kimlik bilgileri içeriyorsa (örn. `https://user:TOKEN@host/repo.git`), Leakwatch bu bilgileri günlüklere veya çıktıya yazmadan önce URL'den ayırır; bu sayede token tarama sonuçlarında veya CI izlerinde hiçbir zaman görünmez.

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı, bulgu yok. |
| `1` | Tarama tamamlandı, bulgular raporlandı. |
| `2` | Tarama başarısız oldu (geçersiz URL, kimlik doğrulama hatası, vb.). |
| `3` | Tarama tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve hiçbir bulgu raporlanmamıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Çoklu Depo](#/scanning/multiple-repos) — tek komutla birden fazla depoyu tarayın.
- [Dosya Sistemi](#/scanning/filesystem) — geçmiş yerine çalışma ağacını tarayın.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — bilinen yanlış pozitifleri bastırın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
