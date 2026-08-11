---
title: "Çıktı Formatları"
description: "Leakwatch'ın desteklediği beş çıktı formatı — JSON, SARIF, CSV, tablo ve GitHub ek açıklamaları — örnekler ve her birini ne zaman kullanacağınıza dair rehberlik."
---

# Çıktı Formatları

Leakwatch beş çıktı formatını destekler: makine tarafından okunabilir hatlar, güvenlik araç entegrasyonları, elektronik tablo dışa aktarmaları, insan tarafından okunabilir terminal incelemesi ve GitHub Actions ek açıklamaları. `--format` (veya `-f`) ile bir format seçin; stdout yerine bir dosyaya yazmak için `--output` (veya `-o`) kullanın.

```bash
leakwatch scan fs . --format json
leakwatch scan fs . --format sarif --output results.sarif
leakwatch scan fs . --format csv   --output findings.csv
leakwatch scan fs . --format table
leakwatch scan fs . --format github   # GitHub Actions ek açıklamaları (CI kullanımı)
```

Varsayılan format `json`'dur.

## JSON

JSON varsayılan format ve en eksiksiz temsil biçimidir. Leakwatch, stdout'a (veya `--output` ile verilen dosyaya) bulgu nesnelerinden oluşan bir JSON **dizisi** yazar.

Ham sır değeri, `--show-raw` açıkça ayarlanmadıkça **hiçbir zaman** serileştirilmez. `--show-raw` ile her nesneye bir `"raw"` alanı eklenir.

### Örnek çağrı

```bash
leakwatch scan fs ./src --format json --output findings.json
```

### Örnek bulgu nesnesi

```json
{
  "id": "447b5d2846d08ce25dd3d638cfe911ad",
  "detector_id": "github-token",
  "severity": "critical",
  "redacted": "ghp_****************************Xk9R",
  "source": {
    "source_type": "filesystem",
    "file_path": "scripts/deploy.sh",
    "line": 14
  },
  "verification": {
    "status": "verified_active"
  },
  "entropy": 5.82,
  "detected_at": "2026-05-23T10:15:30Z"
}
```

`id`, düz 32 karakterlik küçük harfli bir hex dizesi olarak gösterilen, deterministik ve kısaltılmış bir SHA-256 değeridir — bir UUID **değildir** ve hiçbir zaman tire içermez. Nasıl hesaplandığı için [Nasıl Çalışır](#/getting-started/how-it-works) sayfasına bakın.

`entropy` hesaplanmadığında atlanır; hesaplanan `0.0` değeri sıfır olarak yazılır. Zaman damgası olmayan kütüphane üretimi bulgularda `detected_at`, Go'nun 1. yıl sıfır zamanı yerine atlanır. Normal CLI bulguları zaman damgasını ayarlar.

Sağlayıcı tarafından doğrulanmış kimlik, kapsam ve sona erme meta verisi mevcut olduğunda `verification.extra_data` altında görünür. Değerler sınırlı ve şema doğrulamalıdır; alanın olmaması token'ın izni veya sona ermesi olmadığı değil, sağlayıcının güvenli meta veri sunmadığı anlamına gelir.

`--remediation` de ayarlandığında her bulgunun içine iç içe bir `"remediation"` nesnesi yerleştirilir. Bkz. [Düzeltme Rehberi](#/output/remediation).

## SARIF

`sarif` formatı, [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)'e yüklenmek üzere tasarlanmış bir SARIF v2.1.0 belgesi üretir. Araç adı `Leakwatch`'tır ve `informationUri` `https://github.com/HodeTech/Leakwatch` adresine işaret eder.

Bulgularda görünen her dedektör, SARIF sürücüsünde bir **kural** haline gelir; `--remediation` ayarlandığında düzeltme adımlarından doldurulan `help` metni ve sağlayıcı belgelerine işaret eden bir `helpUri` ile birlikte. Sonuçlar, dedektör ID'si, maskelenmiş değer ve dosya yolundan hesaplanan bir `leakwatch/v1` kısmi parmak izi taşır — bu, çevresindeki kod kaydığında bile GitHub Code Scanning'in aynı uyarıyı takip etmesini sağlar.

### Örnek çağrı

```bash
leakwatch scan fs . --format sarif --output results.sarif
```

### GitHub Code Scanning'e yükleme

```yaml
# Bir GitHub Actions iş akışı adımında:
- name: SARIF sonuçlarını yükle
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Tam CI kurulumu için [GitHub Action](#/ci-cd/github-action) bölümüne bakın.

## CSV

`csv` formatı, bir başlık satırı ve ardından bulgu başına bir satır yazar; standart virgülle ayrılmış değerler kullanır. Her hücre yazılmadan önce elektronik tablo formül enjeksiyonuna karşı sterilize edilir.

**Sütunlar (varsayılan):**

```text
id,detector_id,severity,redacted,source,file_path,line,commit,verification_status,remediation
```

`source`, bir bulgunun geldiği kaynak depoyu, konteyner imajını veya Slack kanalını tanımlayan, insan tarafından okunabilir bir etikettir (bir `scan repos` çalıştırması birden fazla depodan gelen bulguları tek bir CSV'de birleştirdiğinde kullanışlıdır); tek bir dizinin düz bir dosya sistemi taraması için boştur. `line` satır numarasıdır, uygulanamadığında boştur.

`--show-raw` ayarlandığında, sona bir `raw` sütunu eklenir.

`remediation` sütunu, `--remediation` ayarlandığında düzeltme başlığını (örn. `"Revoke GitHub Token"`) içerir, aksi hâlde boş kalır.

### Örnek çağrı

```bash
leakwatch scan git . --format csv --output findings.csv
```

### Örnek çıktı

```csv
id,detector_id,severity,redacted,source,file_path,line,commit,verification_status,remediation
447b5d2846d08ce25dd3d638cfe911ad,github-token,critical,ghp_****Xk9R,,scripts/deploy.sh,14,7d3e1f2,verified_active,Revoke GitHub Token
e6fa909746d7d5242309b64c33209fa9,aws-access-key-id,high,AKIA****K7NP,,config/aws.yml,3,7d3e1f2,unverified,Rotate AWS Access Key
```

## Tablo

`table` formatı; CJK, birleşen işaretler ve emoji için doğru görüntü genişliği dahil, terminal hücrelerine göre hizalanmış insan tarafından okunabilir bir tablo yazar. Sonuçların hızlı görsel taramasını istediğiniz etkileşimli terminal oturumları için en uygun formattır.

**Sütunlar:**

```text
SEVERITY | DETECTOR | FILE | LINE | REDACTED | STATUS | REMEDIATION
```

`LINE` sütunu, satır numarası mevcut olmadığında (örneğin bir Slack veya konteyner imajı bulgusu için) `-` gösterir. `REMEDIATION` sütunu her zaman bulunur ve `--remediation` ayarlanmadıkça `-` gösterir. `--show-raw` ayarlandığında da, sona bir `RAW` sütunu eklenir. Yalnızca tablo çıktısında bu değer geri çevrilebilir, Go-tırnaklı bir dize olarak gösterilir: `\\n`, `\\t` ve `\\x1b` gibi kaçışlar terminal kontrol baytlarını etkisiz tutarken `strconv.Unquote` özgün baytları eksiksiz geri yükleyebilir. JSON ve CSV ham değerleri mevcut makine-okunur gösterimlerini korur. Tablonun altına bir özet satırı yazdırılır (örn. `Found 3 secrets (1 critical, 2 high).`).

Saldırgan tarafından etkilenebilecek alanlar (dedektör ID'si, dosya yolu, maskelenmiş değer), terminale yazılmadan önce kontrol karakterlerinden ve ANSI kaçış dizilerinden arındırılır. Unicode çift yönlü metin (bidi) kontrol karakterleri görünür `\\uXXXX` kod noktaları olarak yazılır; böylece varlıkları gizlenmeden görsel sıralama saldırıları önlenir. CJK, birleşen işaretler ve emoji ZWJ dizileri dahil olağan uluslararası metin korunur.

**ANSI rengi**, `SEVERITY` sütununa otomatik olarak uygulanır, ancak yalnızca dört koşulun tamamı sağlandığında:

1. `--format table` seçilmiş
2. Çıktı stdout'a gidiyor (`--output <file>` yok)
3. stdout bir TTY (pipe veya yönlendirme değil)
4. `NO_COLOR` ortam değişkeni ayarlanmamış

| Önem derecesi | Renk |
|---|---|
| `critical` | Kalın kırmızı |
| `high` | Kırmızı |
| `medium` | Sarı |
| `low` | Mavi |

### Örnek çağrı

```bash
leakwatch scan fs . --format table --min-severity high
```

### Örnek çıktı

```text
SEVERITY  DETECTOR           FILE                LINE  REDACTED      STATUS           REMEDIATION
--------  --------           ----                ----  --------      ------           -----------
CRITICAL  github-token       scripts/deploy.sh   14    ghp_****Xk9R  verified_active  Revoke GitHub Token
HIGH      aws-access-key-id  config/aws.yml      3     AKIA****K7NP  unverified       Rotate AWS Access Key

Found 2 secrets (1 critical, 1 high).
```

## GitHub ek açıklamaları

`github` formatı, [GitHub Actions iş akışı komutlarını](https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions) (`::error` / `::warning` / `::notice`) yayar; böylece bulgular bir pull request'in *Files changed* görünümünde ve çalışma günlüğünde **satır içi ek açıklamalar** olarak görünür. Runner'ın stdout'una akıtılmak üzere tasarlanmıştır — bir dosyaya yazmanın etkisi yoktur.

Önem derecesi ek açıklama seviyesine eşlenir: `critical` → `error`, `high` → `warning`, `medium`/`low` → `notice`. Dosya yolu olan bir bulgu o dosya ve satıra bağlanır; dosya yolu olmayan bir bulgu çalışma düzeyinde (run-level) bir ek açıklama olur.

Güvenlik için bu format ham sırrı **asla** yazdırmaz — `--show-raw` ile bile yalnızca maskelenmiş değer gösterilir; çünkü ek açıklamalar (çoğu zaman herkese açık olan) PR arayüzünde ve günlüklerde görüntülenir.

### Örnek çağrı

```bash
leakwatch scan fs . --format github
```

### Örnek çıktı

```text
::error file=config/prod.env,line=12,title=Leakwatch%3A aws-access-key-id::Potential secret detected by aws-access-key-id (critical): AKIA****K7NP
```

Bu format normalde elle çağrılmak yerine [GitHub Action](#/ci-cd/github-action) (`format: github`) tarafından kullanılır.

## Yaygın çıktı bayrakları

| Bayrak | Kısa | Açıklama |
|---|---|---|
| `--format` | `-f` | Çıktı formatı: `json`, `sarif`, `csv`, `table`, `github` (varsayılan `json`) |
| `--output` | `-o` | stdout yerine dosyaya yaz |
| `--show-raw` | | Çıktıya maskelenmemiş sır değerini dahil et |
| `--min-severity` | | Bu önem seviyesinin altındaki bulguları bırak |
| `--only-verified` | | Yalnızca `verified_active` bulgularını tut |
| `--remediation` | | Bulguları sağlayıcı düzeltme rehberiyle zenginleştir |

## Ayrıca bakın

- [Düzeltme Rehberi](#/output/remediation)
- [GitHub Action](#/ci-cd/github-action)
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works)
