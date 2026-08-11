---
title: "GitHub Action"
description: "GitHub iş akışlarında sır taraması yapmak için resmi Leakwatch GitHub Action'ını kullanın."
---

# GitHub Action

Deponuza yapılan her push, bir sırrın içeri sızması için bir fırsattır. GitHub Marketplace'te yayımlanan ve `HodeTech/Leakwatch@v1` olarak kullanılan resmi **Leakwatch GitHub Action**, Leakwatch'ı doğrudan GitHub iş akışınıza entegre eder. Runner için önceden derlenmiş Leakwatch ikilisini indirir (Go araç zinciri veya derleme adımı gerekmez), taramayı çalıştırır, çıkış kodlarını işler, bir iş özeti (job summary) yazar ve isteğe bağlı olarak SARIF sonuçlarını GitHub Code Scanning'e yükler — bunların hepsini harici bir servis bağımlılığı olmadan yapar.

:::note
**Desteklenen runner'lar:** action, Linux (`ubuntu-*`) ve macOS (`macos-*`) runner'larında çalışır. Windows runner'ları henüz desteklenmemektedir; taramayı bir Linux/macOS runner'ında çalıştırın veya `ghcr.io/hodetech/leakwatch` konteyner imajını kullanın.
:::

## Hızlı başlangıç

Sır bulunduğunda iş akışını engelleyen minimal yapılandırma:

```yaml
# .github/workflows/leakwatch-minimal.yml
name: Sır taraması (minimal)

on: [push, pull_request]

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: HodeTech/Leakwatch@v1
```

Yalnızca varsayılan değerlerle action, dosya sistemi taraması yapar (`scan-type: fs`), SARIF çıktısı üretir, canlı doğrulamayı atlar (`no-verify: true`) ve herhangi bir bulgu raporlandığında işi başarısız kılar.

## SARIF yükleme ile tam örnek

Aşağıdaki iş akışı, GitHub Code Scanning'e SARIF yüklemeyi etkinleştirir ve bulguları depo içinde güvenlik uyarıları olarak gösterir:

```yaml
# .github/workflows/leakwatch.yml
name: Sır taraması

on:
  push:
    branches: ["main", "develop"]
  pull_request:

permissions:
  contents: read
  security-events: write   # SARIF yüklemesi için gerekli

jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Sırları tara
        uses: HodeTech/Leakwatch@v1
        with:
          scan-type: fs
          path: .
          format: sarif
          no-verify: "true"
          min-severity: low
          sarif-upload: "true"
          fail-on-findings: "true"
```

:::note
SARIF yüklemesi, işin `permissions: security-events: write` bildirmesini gerektirir. Bu olmadan yükleme adımı 403 hatasıyla başarısız olur. `actions/checkout@v4` için `contents: read` izni de gereklidir.
:::

## Girdiler

| Girdi | Varsayılan | Açıklama |
|-------|-----------|----------|
| `scan-type` | `fs` | Çalıştırılacak tarama türü: `fs`, `git` veya `image`. |
| `path` | `.` | Taranacak yol (`fs`/`git` için) veya imaj referansı (`image` için). |
| `format` | `sarif` | Çıktı biçimi: `sarif`, `json`, `csv`, `table` veya `github` (satır içi pull-request ek açıklamaları). |
| `output` | `` | Biçimlendirilmiş çıktıyı bu dosyaya yaz (`working-directory`'ye göreli). `format: github` için yok sayılır. Boş ve `format: sarif` ise varsayılan `results.sarif`'tir. |
| `only-verified` | `false` | Yalnızca canlı doğrulama ile etkin olduğu teyit edilen bulguları raporla. |
| `no-verify` | `true` | Sır doğrulamasını devre dışı bırak (sağlayıcılara giden ağ çağrısı yapılmaz). |
| `min-severity` | `low` | Raporlanacak minimum önem derecesi: `low`, `medium`, `high` veya `critical`. |
| `remediation` | `false` | Çıktıya giderme (remediation) rehberi ekle. |
| `config` | `` | Bir `.leakwatch.yaml` yapılandırma dosyasının yolu. |
| `scan-diff` | `auto` | `git` taramalarında yalnızca olaya yeni gelen commit'leri tara. `auto`, bunu `pull_request`/`push` olaylarında etkinleştirir; `true` zorlar; `false` her zaman tüm geçmişi tarar. `actions/checkout` ile `fetch-depth: 0` gerektirir. |
| `extra-args` | `` | `leakwatch scan` komutuna eklenen ek ham argümanlar (boşlukla ayrılmış). Action'ın kendi yönettiği bayraklar (`--format`, `--output`, `--config`, `--show-raw`) reddedilir — bunun yerine ilgili input'ları kullanın. |
| `working-directory` | `.` | Taramanın çalıştırılacağı dizin. |
| `sarif-upload` | `false` | Taramadan sonra SARIF sonuçlarını GitHub Code Scanning'e yükle. |
| `fail-on-findings` | `true` | Bulgular raporlandığında (çıkış kodu 1) iş akışı adımını başarısız kıl. `false` olarak ayarlandığında adım başarısız olmak yerine `::warning::` ek açıklaması yayar. Ciddi hatalar (çıkış kodu ≥ 2) bu ayardan bağımsız olarak her zaman adımı başarısız kılar. |
| `version` | `latest` | Kurulacak Leakwatch sürümü: `latest` veya belirli bir sürümü sabitlemek için `v1.8.0` gibi bir etiket. |
| `release-repo` | `HodeTech/Leakwatch` | Sürüm ikilisinin indirileceği depo (`owner/name`). Yalnızca fork veya kendi sunucunuzdaki aynalar için değiştirin. |

## Çıktılar

| Çıktı | Açıklama |
|-------|----------|
| `findings-count` | Bulgu raporlanmadıysa `0`; bulgu raporlandıysa `1`. Leakwatch çıkış kodunu yansıtır. |
| `sarif-file` | Runner üzerindeki SARIF çıktı dosyasının yolu (`format: sarif` olduğunda ayarlanır). |

## CI'da doğrulama

Varsayılan olarak `no-verify` değeri `true`'dur — CI'da canlı doğrulama **kapalıdır**. Bu, taramayı hızlı tutar ve CI runner'larından sağlayıcı API'lerine giden ağ çağrılarını önler; runner'lar güvenlik duvarı arkasında olabilir veya hız sınırlı kimlik bilgilerine sahip olabilir.

CI'da doğrulamayı etkinleştirmek için `no-verify: "false"` olarak ayarlayın:

```yaml
- uses: HodeTech/Leakwatch@v1
  with:
    no-verify: "false"
```

:::warn
CI'da doğrulamayı etkinleştirmek, Leakwatch'ın her aday bulgu için sağlayıcılara (AWS, GitHub, Stripe vb.) kimlik doğrulamalı API çağrıları yapmasına neden olur. Sağlayıcı hız limitlerinden haberdar olun ve runner'ın giden internet erişimine sahip olduğundan emin olun.
:::

## SARIF yüklemesi nasıl çalışır

`sarif-upload: "true"` ve `format: sarif` olduğunda action:

1. Leakwatch'a çıktıyı `results.sarif` dosyasına yazmasını söyler.
2. Taramanın ardından `category: leakwatch` ile `github/codeql-action/upload-sarif@v3`'ü çağırır.
3. GitHub dosyayı işler ve bulguları deponun **Security** sekmesinde **Code Scanning uyarıları** olarak gösterir.

Yükleme adımı `if: always()` ile çalışır; dolayısıyla `fail-on-findings: "true"` tarama adımını başarısız kılsa bile sonuçlar yüklenir.

## Action çıktılarını kullanmak

```yaml
- name: Sırları tara
  id: scan
  uses: HodeTech/Leakwatch@v1
  with:
    fail-on-findings: "false"   # iş akışının devam etmesine izin ver

- name: Sonucu yazdır
  run: echo "Raporlanan bulgular: ${{ steps.scan.outputs.findings-count }}"
```

## Belirli bir sürümü sabitleme

Yeniden üretilebilir derlemeler için `version` değerini belirli bir etikete sabitleyin:

```yaml
- uses: HodeTech/Leakwatch@v1
  with:
    version: "v1.8.0"
```

Bu, önceden derlenmiş `v1.8.0` ikilisini [Leakwatch sürümlerinden](https://github.com/HodeTech/Leakwatch/releases) indirir ve çalıştırmadan önce SHA-256 sağlama toplamını doğrular. En yüksek tedarik zinciri güvenliği için action'ın kendisini de bir commit SHA'sına sabitleyebilirsiniz: `uses: HodeTech/Leakwatch@<sha>`.

## Yalnızca değişen kodu tarama (pull-request diff)

`git` taramalarında action, taramayı bir pull request veya push'un gerçekten getirdiği commit'lerle sınırlayabilir; bu daha hızlıdır ve yalnızca yeni eklenen sırları yüzeye çıkarır. `scan-diff` (varsayılan `auto`) ile kontrol edilir ve base commit'in yerel olarak bulunması için tam bir checkout gerektirir:

```yaml
jobs:
  leakwatch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # PR base commit'inin mevcut olması için gerekli
      - uses: HodeTech/Leakwatch@v1
        with:
          scan-type: git
          path: .
          # scan-diff: auto (varsayılan) — pull_request/push'ta yalnızca base..HEAD taranır
```

`pull_request` olayında action `github.event.pull_request.base.sha`'dan; `push` olayında `github.event.before`'dan itibaren tarar. Her zaman tüm geçmişi taramak için `scan-diff: "false"`, diff modunu zorlamak için `scan-diff: "true"` kullanın. `scan-diff`'in `fs`/`image` taramalarında etkisi yoktur.

## Satır içi pull-request ek açıklamaları

Bulguları GitHub Actions iş akışı komutları olarak yaymak için `format: github` ayarlayın; bunlar pull request'in **Files changed** görünümünde ve çalışma günlüğünde satır içi ek açıklamalar olarak görünür:

```yaml
- uses: HodeTech/Leakwatch@v1
  with:
    format: github
    fail-on-findings: "false"   # isterseniz engellemeden yalnızca ek açıklama yapın
```

Ek açıklamalar her zaman yalnızca **maskelenmiş** değeri gösterir — ham sır, (çoğu zaman herkese açık olan) PR arayüzüne veya günlüklere asla yazılmaz. Hızlı ve görünür PR geri bildirimi için `format: github`, bulguları **Security** sekmesinde Code Scanning uyarıları olarak kaydetmek için `sarif-upload: true` ile `format: sarif` kullanın.

## Ayrıca bakın

- [Çıktı Biçimleri](#/output/output-formats) — JSON, SARIF, CSV ve tablo çıktısını anlama.
- [Çıkış Kodları](#/reference/exit-codes) — çıkış kodlarının tarama sonuçlarıyla nasıl eşleştiği.
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) — Leakwatch'ın sağlayıcı API'lerini ne zaman ve nasıl çağırdığı.
- [Pre-commit Kancası](#/ci-cd/pre-commit) — commit edilmeden önce sırları yakalama.
- [Diğer CI Sistemleri](#/ci-cd/other-ci) — GitLab CI, Jenkins ve genel kabuk entegrasyonu.
