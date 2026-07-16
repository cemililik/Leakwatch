---
title: "Konteyner İmajları"
description: "Docker daemon gerektirmeksizin OCI ve Docker imaj katmanlarını sızan sırlara karşı tarayın."
---

# Konteyner İmajları

Konteyner imajları sırların sıklıkla gizlendiği yerlerden biridir: ortam değişkenlerine gömülen API anahtarları, derleme katmanlarına yerleştirilmiş kimlik bilgileri ve imaj katmanlarına kopyalanıp unutulan yapılandırma dosyaları. `leakwatch scan image`, bir OCI veya Docker imajının her katmanını inceler ve bu sırları dağıtım öncesinde gün yüzüne çıkarır.

## Temel kullanım

```bash
leakwatch scan image <image:tag>
```

Komut tam olarak bir argüman alır: standart `name:tag` gösteriminde bir imaj referansı. Leakwatch imajları çekmek ve incelemek için [go-containerregistry](https://github.com/google/go-containerregistry) kullanır — herhangi bir Docker daemon **gerekmez**.

```bash
# Docker Hub imajını tara
leakwatch scan image nginx:latest

# Özel GitHub Container Registry imajını tara
leakwatch scan image ghcr.io/org/myapp:v1.2.0

# Amazon ECR imajını tara
leakwatch scan image 123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest
```

## Desteklenen kayıt sunucuları

| Kayıt Sunucusu | Örnek referans |
|----------------|----------------|
| Docker Hub | `nginx:latest`, `myorg/myapp:1.0.0` |
| GitHub Container Registry (GHCR) | `ghcr.io/org/myapp:v1.2.0` |
| Amazon ECR | `123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp:latest` |
| Google Container Registry (GCR) | `gcr.io/my-project/myapp:latest` |
| OCI uyumlu herhangi bir kayıt sunucusu | Standart `registry/name:tag` biçimi |

## Kimlik doğrulama

Leakwatch, Docker ve diğer OCI araçları tarafından kullanılan standart kimlik bilgisi anahtarlığını kullanır. `docker login` (veya `crane`, `skopeo`, bulut sağlayıcısı kimlik bilgisi yardımcıları gibi eşdeğer araçlar) ile oturum açtıysanız, Leakwatch bu kimlik bilgilerini otomatik olarak kullanır.

```bash
# Önce GHCR'a giriş yapın
docker login ghcr.io

# Ardından tarayın — kimlik bilgileri otomatik olarak alınır
leakwatch scan image ghcr.io/org/private-app:latest
```

Amazon ECR için, taramadan önce ECR kimlik bilgisi yardımcısını yapılandırın ya da `AWS_ACCESS_KEY_ID` ve ilgili ortam değişkenlerini ayarlayın.

## Tarama nasıl çalışır

Leakwatch imaj manifestini çeker, her katmanı sırayla işler ve her katmandaki dosyaları çıkarır. Her dosyanın içeriği, dosya sistemi taramasıyla aynı tespit hattından geçirilir. `.leakwatch.yaml` içindeki `filter.exclude-paths` yol dışlamaları (veya `--exclude`) burada da geçerlidir ve katmanlar içinde hangi dosya yollarının inceleneceğini sınırlar.

:::note
Sıkıştırma bombası katmanlarına karşı bir savunma olarak Leakwatch, okuyacağı kümülatif sıkıştırması açılmış bayt miktarını sınırlar: katman başına 2 GiB ve tüm imaj genelinde 10 GiB. Bir katman veya imaj bu tavanı aşarsa, sıkıştırma açmanın sınırsız çalışmasına izin vermek yerine etkilenen katmanın taraması kısaltılır (bir uyarı günlüğe kaydedilir).
:::

## Bayraklar

İmaja özgü bayrak yoktur. Tüm ortak tarama bayrakları geçerlidir:

| Bayrak | Kısa | Varsayılan | Açıklama |
|--------|------|------------|----------|
| `--format` | `-f` | `json` | Çıktı biçimi: `json`, `sarif`, `csv`, `table`, `github`. |
| `--output` | `-o` | stdout | Sonuçları stdout yerine bu dosyaya yaz. |
| `--concurrency` | `-c` | CPU sayısı | Eşzamanlı çalışan sayısı. |
| `--max-file-size` | — | `10485760` (10 MB) | Bu boyutu aşan dosyaları atla (bayt). |
| `--show-raw` | — | `false` | Çıktıda ham sır değerini göster. |
| `--exclude` | — | — | Dışlanacak yol kalıbı. Tekrarlanabilir; `filter.exclude-paths` ile birleştirilir. |
| `--exclude-detectors` | — | — | Bu çalıştırma için hariç tutulacak dedektör kimlikleri. Tekrarlanabilir; `filter.exclude-detectors` ile birleştirilir. |
| `--no-verify` | — | `false` | Sır doğrulamasını devre dışı bırak. |
| `--only-verified` | — | `false` | Yalnızca doğrulama ile aktif olduğu onaylanan bulguları raporla. |
| `--min-severity` | — | `low` | Raporlanacak minimum önem: `low`, `medium`, `high`, `critical`. |
| `--remediation` | — | `false` | Her bulguya düzeltme rehberi ekle. |

Yol tabanlı dışlamalar `.leakwatch.yaml` dosyasında `filter.exclude-paths` altında ya da her çalıştırma için `--exclude` ile yapılandırılır. Ayrıntılar için [Yapılandırma Dosyası](#/configuration/config-file) sayfasına bakın.

`--config` ve `--log-level` (varsayılan `warn`) kök bayrakları da geçerlidir.

## Örnekler

Docker Hub imajını tarayın ve sonuçları tablo olarak yazdırın:

```bash
leakwatch scan image alpine:3.20 --format table
```

Özel kayıt sunucusu imajını tarayın ve SARIF çıktısı kaydedin:

```bash
leakwatch scan image ghcr.io/org/myapp:v1.2.0 --format sarif -o results.sarif
```

Yalnızca doğrulanmış aktif sırları gösterin:

```bash
leakwatch scan image myapp:latest --only-verified --format table
```

JSON çıktısına düzeltme rehberi dahil edin:

```bash
leakwatch scan image myapp:latest --remediation --format json -o image-findings.json
```

## Bulgu meta verisi

İmaj taramasından elde edilen her bulgu katman meta verisi içerir:

| Alan | Açıklama |
|------|----------|
| `image` | Taranan imaj referansı. |
| `layer` | Bulgunun tespit edildiği katman özeti (imaj yapılandırmasındaki bir bulgu için `"config"`, katman değil). |
| `layer_idx` | İmaj manifestindeki katmanın sayısal indeksi (0 tabanlı); imaj yapılandırmasındaki bir bulgu için `-1`. |
| `file_path` | Katman içindeki dosyanın yolu. |

:::tip
Gizli bilgilerin bir kayıt sunucusuna push edilmeden önce yakalanması için konteyner imaj taramasını CI/CD hattınızın derleme aşamasına entegre edin. Sonuçları doğrudan GitHub Code Scanning'e yüklemek için `--format sarif` kullanın.
:::

## Çıkış kodları

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı, bulgu yok. |
| `1` | Tarama tamamlandı, bulgular raporlandı. |
| `2` | Tarama başarısız oldu (imaj bulunamadı, kimlik doğrulama hatası, vb.). |
| `3` | Tarama tamamlanmadan kesildi (`Ctrl+C` / `SIGTERM`) ve hiçbir bulgu raporlanmamıştı. |

Her çalıştırmanın ardından stderr'e bir tarama özeti yazdırılır. Taramalar SIGINT/SIGTERM sinyalinde düzgün biçimde iptal edilir.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Dosya Sistemi](#/scanning/filesystem) — yerel bir dizin ağacını tarayın.
- [Yapılandırma Dosyası](#/configuration/config-file) — dışlamaları ve diğer varsayılanları yapılandırın.
- [Bulguları Yoksayma](#/configuration/ignoring-findings) — bilinen yanlış pozitifleri bastırın.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — doğrulama durumlarını anlayın.
- [CLI Referansı](#/reference/cli-reference) — tüm komutlar için tam bayrak referansı.
