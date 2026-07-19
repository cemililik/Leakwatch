---
title: "Hızlı Başlangıç"
description: "İlk Leakwatch taramanızı bir dakikadan kısa sürede çalıştırın."
---

# Hızlı Başlangıç

Leakwatch'ın neler yapabileceğini anlamanın en hızlı yolu, onu gerçek bir dizine yönlendirmektir. Bu sayfa ilk taramanızda size rehberlik eder, çıktının ne anlama geldiğini açıklar ve en sık kullanacağınız bayrakları gösterir.

## Ön koşullar

Leakwatch kurulu ve `PATH` değişkeninizde erişilebilir olmalıdır. Henüz yapmadıysanız [Kurulum](#/getting-started/installation) sayfasına bakın.

## İlk taramanız

Mevcut dizini tek bir komutla tarayın:

```bash
leakwatch scan fs .
```

Varsayılan olarak çıktı JSON biçiminde stdout'a yazılır. Bunun yerine okunabilir, renklendirilmiş bir tablo almak için `--format table` ekleyin:

```bash
leakwatch scan fs . --format table
```

Bir sonucun nasıl göründüğü aşağıdadır (tablo formatlayıcısı her zaman sondaki REMEDIATION sütununu yazdırır; `--remediation` de ayarlanmadıkça `-` gösterir):

```text
SEVERITY  DETECTOR           FILE                       LINE  REDACTED      STATUS           REMEDIATION
--------  --------           ----                       ----  --------      ------           -----------
CRITICAL  aws-access-key-id  config/deploy.env          12    ****MNOP      verified_active   -
HIGH      npm-token          scripts/bootstrap.sh       37    npm_****wxyz  verified_active   -
MEDIUM    generic-api-key    src/services/analytics.js  89    ****w2y4      unverified        -

Found 3 secrets (1 critical, 1 high, 1 medium).

── Scan Summary ─────────────────────────────────
  Date:            2026-05-23 14:03:11
  Source:          filesystem
  Target:          /home/user/myproject
  Files scanned:   312
  Duration:        1.24s
  Findings:        3
─────────────────────────────────────────────────
```

Tarama özeti her zaman **stderr**'e yazdırılır; bu nedenle pipe veya yeniden yönlendirilen çıktıyla hiçbir zaman çakışmaz.

## Bulguyu anlamak

Tablodaki her satır (veya JSON'daki her nesne) bir bulguyu temsil eder. Temel alanlar şunlardır:

| Alan | Anlam |
|------|-------|
| **SEVERITY** | Sır türünün ne kadar kritik olduğu: `low`, `medium`, `high` veya `critical` |
| **DETECTOR** | Eşleşen dedektör — sır türünü tanımlar (örneğin `aws-access-key-id`) |
| **FILE** | Sırrın bulunduğu dosyanın tarama köküne göreli yolu |
| **LINE** | Eşleşmenin satır numarası |
| **REDACTED** | Sırrın maskelenmiş gösterimi — `--show-raw` ayarlanmadıkça ham değer hiçbir zaman gösterilmez |
| **STATUS** | Doğrulama sonucu: `verified_active`, `verified_inactive`, `unverified` veya `verify_error` |
| **REMEDIATION** | Döndürme/iptal rehberi başlığı, veya `--remediation` geçilmediğinde `-` |

`verified_active` durumu, Leakwatch'ın sağlayıcıya salt-okunur bir API çağrısı yaparak sırrın hâlâ etkin olduğunu doğruladığı anlamına gelir. **Her `verified_active` bulgusunu açık bir olay olarak değerlendirin.**

## Yaygın tarama seçenekleri

### Yalnızca onaylanmış sırlara odaklanın

```bash
leakwatch scan fs . --only-verified
```

Bu seçenek doğrulanmamış ve etkin olmayan bulguları gizler; yalnızca etkin olduğu onaylananları bırakır. Çok sayıda sonucunuz olduğunda önceliklendirme için kullanışlıdır.

### Hızlı çevrimdışı tarama için ağ doğrulamasını atlayın

```bash
leakwatch scan fs . --no-verify
```

Doğrulama tamamen atlanır — hiçbir giden ağ çağrısı yapılmaz. Sonuçlar daha hızlı görünür ve internet bağlantısı olmadan çalışır, ancak tüm bulgular `unverified` olarak işaretlenir.

### Düzeltme kılavuzu ekleyin

```bash
leakwatch scan fs . --remediation --format table
```

Her bulgu, söz konusu sır türünü nasıl döndüreceğinizi veya iptal edeceğinizi açıklayan bir **REMEDIATION** sütunu kazanır. Bayrak ayarlandığında aynı veriler JSON, SARIF ve CSV çıktısına da dahil edilir.

### Minimum önem derecesine göre filtreleyin

```bash
leakwatch scan fs . --min-severity high
```

Yalnızca `high` veya `critical` önem derecesindeki bulgular raporlanır.

### Sonuçları dosyaya kaydedin

```bash
leakwatch scan fs . --format sarif --output results.sarif
```

`--output` / `-o` bayrağı stdout yerine bir dosyaya yazar. SARIF çıktısı [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning) ile uyumludur.

## Yapılandırma dosyası oluşturma

İlk denemede varsayılanlarla çalıştırmak uygundur; ancak tekrarlayan kullanım için proje düzeyinde bir yapılandırma isteyeceksiniz:

```bash
leakwatch init
```

Bu komut, eşzamanlılık, entropi, doğrulama, çıktı biçimi ve yaygın yol dışlamaları için önerilen varsayılanlarla mevcut dizine `.leakwatch.yaml` yazar. Mevcut bir dosyanın üzerine yazmak için `--force`, farklı bir yola yazmak için `--output` kullanın.

Her seçeneğin tam açıklaması için [Yapılandırma Dosyası](#/configuration/config-file) sayfasına bakın.

## Çıkış kodları

Leakwatch, CI betiklerinin çıktıyı ayrıştırmadan sonuçlara göre hareket edebilmesi için farklı çıkış kodları kullanır:

| Kod | Anlam |
|-----|-------|
| `0` | Tarama tamamlandı — bulgu yok |
| `1` | Tarama tamamlandı — bir veya daha fazla sır bulundu |
| `2` | Tarama bir hata nedeniyle başarısız oldu |
| `3` | Tarama tamamlanmadan (`Ctrl+C` / `SIGTERM`) kesildi ve henüz hiçbir bulgu raporlanmamıştı |

Tipik bir CI kapısı şöyle görünür:

```bash
leakwatch scan fs . --only-verified --format sarif --output results.sarif
if [ $? -eq 1 ]; then
  echo "Etkin sırlar bulundu — derleme başarısız"
  exit 1
fi
```

:::warn
Çıkış kodu `1`, etkin filtreleri geçen (`--min-severity` ve `--only-verified` dahil) *herhangi bir* bulgu olduğunda döndürülür. Temiz çıkış kodu `0`, hiçbir bulgunun eşleşmediği anlamına gelir — kod tabanında sır olmadığı anlamına gelmez.
:::

## Taramayı iptal etme

Çalışan bir taramayı iptal etmek için `Ctrl+C` tuşuna basın (veya `SIGTERM` gönderin). Leakwatch düzgün biçimde durur: işlemdeki parçalar tamamlanır, kısmi sonuçlar yazılır ve özet `Status: interrupted (partial results)` olarak gösterilir. Bulgular kesintiye rağmen önceliklidir — kesintiden önce sırlar zaten bulunmuşsa tarama `1` ile çıkar, böylece bu sinyal hiçbir zaman gizlenmez. `3` çıkış kodu yalnızca tarama sıfır bulguyla kesintiye uğradığında döndürülür; bu sayede bir CI hattı tamamlanmamış bir taramayı asla temiz bir geçişle karıştırmaz.

## Ayrıca bakın

- [Kurulum](#/getting-started/installation)
- [Nasıl Çalışır](#/getting-started/how-it-works)
- [CLI Referansı](#/reference/cli-reference)
- [Yapılandırma Dosyası](#/configuration/config-file)
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works)
