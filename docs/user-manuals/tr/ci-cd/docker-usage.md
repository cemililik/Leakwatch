---
title: "Docker Kullanımı"
description: "Resmi Docker imajını kullanarak Leakwatch taramalarını bir konteyner içinde çalıştırın."
---

# Docker Kullanımı

Resmi Leakwatch konteyner imajı, ana makineye herhangi bir şey kurmadan tarama yapmanızı sağlar. İmaj `CGO_ENABLED=0` ile statik olarak derlenmiş ve root olmayan bir kullanıcı olarak çalışır; bu nedenle kilitli CI ortamlarında ve ana sistemi değiştirmek istemediğiniz paylaşımlı makinelerde güvenle kullanılabilir.

## İmaj referansı

```text
ghcr.io/hodetech/leakwatch
```

| Etiket | Açıklama |
|--------|----------|
| `:latest` | En son sürüm |
| `:v1.8.0` | Güncel sürüme tam sabitleme |
| `:v1.7` | Güncel küçük sürüme sabitleme (yama sürümlerini takip eder) |

İmaj Alpine tabanlıdır, root olmayan `leakwatch` kullanıcısı olarak çalışır, çalışma dizini olarak `/scan` kullanır ve giriş noktası olarak `leakwatch`'ı ayarlar.

:::note
Giriş noktası `leakwatch` olduğundan alt komutu ve bayrakları doğrudan imaj adının ardına eklersiniz — örneğin `ghcr.io/hodetech/leakwatch:latest scan fs /scan`. İkili dosya adını tekrar yazmanıza gerek yoktur.
:::

## Yerel dizin tarama

Taramak istediğiniz dizini konteyner içindeki `/scan` dizinine bağlayın:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

Ana makinedeki bir dosyaya sonuç yazmak için çıktı dosyasını bağlı birime yazın:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --format sarif -o /scan/leakwatch.sarif
```

`leakwatch.sarif` dosyası, konteyner çıktıktan sonra ana makinedeki geçerli dizinde görünür.

## Uzak Git deposu tarama

```bash
docker run --rm \
  ghcr.io/hodetech/leakwatch:latest \
  scan git https://github.com/org/repo.git --format json
```

Uzak Git depoları için birim bağlaması gerekli değildir — Leakwatch bunları konteyner içindeki geçici bir dizine klonlar.

## Konteyner imajı tarama

Leakwatch daemonsuz çalışır: imaj katmanlarını Docker daemon'ına ihtiyaç duymadan doğrudan kayıt defterinden çeker. Bu, Leakwatch konteynerinden, ana makine Docker soketini bağlamadan uzak bir imajı tarayabileceğiniz anlamına gelir:

```bash
docker run --rm \
  ghcr.io/hodetech/leakwatch:latest \
  scan image registry.example.com/my-app:v2.3.0
```

Özel kayıt defterleri için kimlik bilgilerini, kayıt defterinizin desteklediği standart ortam değişkenleri aracılığıyla geçirin (örneğin, bağlı bir kimlik bilgisi dosyasına işaret eden `DOCKER_CONFIG`).

## Yapılandırma dosyası geçirme

`.leakwatch.yaml` dosyasını `/scan` dizinine bağlayın; Leakwatch onu otomatik olarak bulur:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

`.leakwatch.yaml` bağlanan dizinde olduğu sürece Leakwatch onu bulur çünkü `/scan` hem çalışma dizini hem de taramaya geçirilen yoldur. Yapılandırma dosyanız başka bir yerdeyse onu ayrıca bağlayın ve `--config` kullanın:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  -v "/path/to/custom-config.yaml:/config/leakwatch.yaml:ro" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan --config /config/leakwatch.yaml
```

## Ortam değişkenleri geçirme

Bulut taraması ve token tabanlı kimlik doğrulama için ortam değişkenleri `-e` ile enjekte edilebilir:

```bash
# AWS kimlik bilgileriyle S3 taraması
docker run --rm \
  -e AWS_ACCESS_KEY_ID=AKIA••••••••••••EXAMPLE \
  -e AWS_SECRET_ACCESS_KEY=••••••••••••••••••••••••••••••••••••••• \
  -e AWS_REGION=us-east-1 \
  ghcr.io/hodetech/leakwatch:latest \
  scan s3 my-bucket
```

CI ortamlarında, kimlik bilgilerini komut satırına gömmek yerine maskelenmiş CI değişkenleri olarak enjekte etmeyi tercih edin.

## Çıktı dosyası kalıbı

CI'da yaygın bir Docker kalıbı, sonuçları bağlı birime yazmak ve ardından dosyayı bir pipeline artifact'i olarak yüklemek veya arşivlemektir:

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan \
    --format json \
    --only-verified \
    -o /scan/leakwatch-results.json
```

## Ayrıca bakın

- [Kurulum](#/getting-started/installation) — Docker kullanmak yerine yerel ikili dosyayı kurma.
- [Dosya Sistemi Taraması](#/scanning/filesystem) — `scan fs` bayrakları ve davranışı.
- [Konteyner İmajları](#/scanning/container-images) — OCI/Docker imaj katmanlarını sır açısından tarama.
- [Diğer CI Sistemleri](#/ci-cd/other-ci) — GitLab CI ve diğer pipeline'larda Docker imajını kullanma.
- [CLI Referansı](#/reference/cli-reference) — tüm alt komutlar için tam bayrak referansı.
