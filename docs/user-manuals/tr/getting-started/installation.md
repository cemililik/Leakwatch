---
title: "Kurulum"
description: "Leakwatch'ı Homebrew, go install, Docker veya hazır bir ikili dosya ile kurun."
---

# Kurulum

Leakwatch'ı makinenize kurmak bir dakikadan az sürer. İş akışınıza en uygun yöntemi seçin: Homebrew macOS ve Linux'ta en basit seçenektir, `go install` halihazırda bir Go araç zinciriniz varsa idealdir, Docker ana sisteminizi temiz tutar ve hazır ikili dosyalar herhangi bir araç zinciri gerektirmeden her yerde çalışır.

## Homebrew (macOS ve Linux)

Resmi tap, amd64 ve arm64 mimarilerinde macOS ve Linux'u destekler.

```bash
brew install HodeTech/tap/leakwatch
```

Tap, [github.com/HodeTech/homebrew-tap](https://github.com/HodeTech/homebrew-tap) adresinde barındırılmaktadır. Homebrew ile yükseltmek için `brew upgrade leakwatch` komutunu kullanın.

## go install

Go 1.25 veya daha yeni bir sürümü yüklüyse, en son sürümü doğrudan kaynaktan derleyip kurabilirsiniz:

```bash
go install github.com/HodeTech/leakwatch@latest
```

İkili dosya `$(go env GOPATH)/bin` dizinine yerleştirilir. Bu dizinin `PATH` değişkeninde olduğundan emin olun.

:::note
`go install` her zaman en son etiketli sürümü getirir. Belirli bir sürüme sabitlemek için `@latest` yerine `@v1.5.0` gibi bir etiket kullanın.
:::

## Docker

Minimal, çok aşamalı bir Alpine imajı GitHub Container Registry'de yayımlanmaktadır. İmaj, root olmayan bir kullanıcı (`leakwatch`) olarak çalışır, CGO devre dışıdır ve çalışma dizini olarak `/scan` kullanır.

```bash
docker run --rm \
  -v "$(pwd):/scan" \
  ghcr.io/hodetech/leakwatch:latest \
  scan fs /scan
```

Kullanılabilir etiketler:

| Etiket | Açıklama |
|--------|----------|
| `:latest` | En son sürüm |
| `:v1.5.0` | Tam sürüm sabitleme |
| `:v1.5` | Küçük sürüm sabitleme (yama sürümlerini takip eder) |

Taramak istediğiniz dizini konteyner içindeki `/scan` dizinine bağlayın. Bayraklar ve seçenekler yerel ikili dosyayla tamamen aynı şekilde çalışır — tam liste için [CLI Referansı](#/reference/cli-reference) sayfasına bakın.

:::tip
Uzak Git depolarını tarama ve kimlik bilgilerini güvenli biçimde geçirme dahil Docker'a özgü kullanım kalıpları için [Docker Kullanımı](#/ci-cd/docker-usage) sayfasına bakın.
:::

## Hazır ikili dosya

Her sürüm, desteklenen tüm platformlar için [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases) sayfasında tar arşivleri yayımlar. Platformunuza ait arşivi indirin, açın ve ikili dosyayı `PATH` değişkeninizdeki bir dizine taşıyın.

**Desteklenen platformlar:** amd64 ve arm64 mimarilerinde Linux, macOS ve Windows.

```bash
# Linux amd64 örneği — OS ve ARCH değerlerini platformunuza göre değiştirin
curl -LO https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_amd64.tar.gz
tar -xzf leakwatch_Linux_amd64.tar.gz
sudo mv leakwatch /usr/local/bin/leakwatch
```

Platform adlandırması `leakwatch_<OS>_<ARCH>.tar.gz` kalıbını izler; `<OS>` değeri `Linux`, `Darwin` veya `Windows`, `<ARCH>` değeri ise `amd64` veya `arm64` olabilir.

:::tip
Her sürüm ayrıca her arşiv için bir Yazılım Malzeme Listesi (SBOM) ve sürümün sağlama toplamları dosyası üzerinde bir [Sigstore/cosign](https://github.com/sigstore/cosign) anahtarsız imza (`checksums.txt.sig` / `checksums.txt.pem`) yayımlar; böylece indirilen bir ikili dosyanın kökeni, tedarik zinciri açısından hassas ortamlarda doğrulanabilir.
:::

## Kurulumu doğrulama

Herhangi bir kurulum yönteminin ardından ikili dosyanın erişilebilir olduğunu doğrulayın ve sürümü kontrol edin:

```bash
leakwatch version
```

Beklenen çıktı:

```text
leakwatch v1.5.0 (commit: a3f9c12, built: 2026-05-10T08:22:00Z)
```

Komut bulunamazsa kurulum dizininin `PATH` değişkeninde olup olmadığını kontrol edin.

## Sonraki adımlar

- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Nasıl Çalışır](#/getting-started/how-it-works) — Leakwatch taramasının arkasındaki mimari.
- [Yapılandırma Dosyası](#/configuration/config-file) — `.leakwatch.yaml` ile tarama davranışını özelleştirin.

## Ayrıca bakın

- [Hızlı Başlangıç](#/getting-started/quick-start)
- [Docker Kullanımı](#/ci-cd/docker-usage)
- [CLI Referansı](#/reference/cli-reference)
- [Yapılandırma Dosyası](#/configuration/config-file)
