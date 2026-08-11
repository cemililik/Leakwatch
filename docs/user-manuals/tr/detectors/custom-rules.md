---
title: "Özel Kurallar"
description: "YAML ile kendi sır tespit kalıplarınızı nasıl tanımlayacağınız ve 65 yerleşik dedektörün yanında bir Leakwatch taramasına nasıl ekleyeceğiniz."
---

# Özel Kurallar

65 yerleşik dedektör yaygın kullanılan kimlik bilgisi formatlarını kapsar; ancak her kuruluşun dahili token'ları, özel servis anahtarları veya hiçbir genel aracın önceden tahmin edemeyeceği ortama özgü kalıpları vardır. Özel kurallar, kaynak kodu değiştirmeden veya ikili dosyayı yeniden derlemeden kendi kalıplarınızı düz YAML ile tanımlamanıza ve çalışma zamanında yüklemenize olanak tanıyarak Leakwatch'ı genişletmenizi sağlar.

## Özel kurallar nerede tanımlanır

Özel kurallar, `.leakwatch.yaml` yapılandırma dosyanızda en üst düzey bir `custom-rules:` listesi altında tanımlanır:

```yaml
custom-rules:
  - id: acme-internal-token
    description: "ACME Corp dahili servis token'ı"
    regex: 'acme_[a-z0-9]{32}'
    keywords:
      - acme_
    severity: critical
    entropy: 3.5
```

Kurallar, Leakwatch başladığında çalışma zamanında kaydedilir. Aynı Aho-Corasick ön-filtre hattını kullanarak yerleşik dedektörlerle birlikte çalışırlar.

## Kural alanları

| Alan | Zorunlu | Tür | Açıklama |
|------|---------|-----|----------|
| `id` | Evet | string | Benzersiz dedektör ID'si. Çıktıda ve `filter.exclude-detectors` içinde kullanılır. Yerleşik dedektör ID'si veya başka bir özel kural ID'si ile çakışmamalıdır. |
| `description` | Hayır | string | Çıktıda gösterilen insan tarafından okunabilir açıklama. |
| `regex` | Evet | string | RE2 uyumlu düzenli ifade. Maksimum 4096 karakter. |
| `keywords` | Hayır | string listesi | Aho-Corasick ön-filtre anahtar kelimeleri. Regex yalnızca bu dizelerden en az birini içeren parçalar üzerinde çalışır. Bu alanın atlanması regex'in her parça üzerinde çalışmasına neden olur. |
| `severity` | Hayır | string | `critical`, `high`, `medium` veya `low`. Varsayılan `medium`'dur. |
| `entropy` | Hayır | float | Shannon entropi eşiği (0–8). Entropisi bu değerin **altında** olan eşleşmeler atılır. Düşük rastgelelikli yanlış pozitifleri filtrelemek için kullanışlıdır. |

:::tip
Her zaman `keywords` belirtin. Tek kısa bir anahtar kelime bile (token ön eki gibi) regex motorunun işlediği parça sayısını önemli ölçüde azaltır ve büyük depolarda taramaların hızlı kalmasını sağlar. Örneğin tüm dahili token'larınız `acme_` ile başlıyorsa `keywords: [acme_]` ayarlayın.

`entropy` kullanarak `acme_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx` gibi kalıbı karşılayan ancak açıkça gerçek sır olmayan yer tutucu değerlerdeki eşleşmeleri bastırın. 3,0–3,5 civarı bir eşik iyi bir başlangıç noktasıdır.
:::

## Çakışma yönetimi

Bir özel kuralın `id`'si zaten kayıtlı bir dedektörle eşleşirse — yerleşik dedektör veya daha önce yüklenen özel kural olsun fark etmez — yinelenen kural **atlanır** ve bir hata loglanır. Leakwatch çökmez; geri kalan kurallar normal şekilde yüklenir. Bir özel kuralın etkisiz göründüğü durumlarda log çıktısını kontrol edin.

## Doğrulama

Özel kuralların eşleştirilmiş doğrulayıcısı yoktur. Özel kurallardan gelen bulgular her zaman `unverified` durumuyla raporlanır — hiçbir zaman `verified_active` veya `verified_inactive` olmaz.

## Tam örnek

Aşağıdaki `.leakwatch.yaml`, iki özel kural tanımlar: biri dahili servis token'ı, diğeri webhook'larda kullanılan imzalama sırrı için.

```yaml
custom-rules:
  - id: acme-internal-token
    description: "ACME Corp dahili servis token'ı (format: acme_ + 32 hex karakter)"
    regex: 'acme_[a-f0-9]{32}'
    keywords:
      - acme_
    severity: critical
    entropy: 3.2

  - id: acme-webhook-signing-secret
    description: "ACME Corp webhook imzalama sırrı (format: whsec_ + 40 base64url karakter)"
    regex: 'whsec_[A-Za-z0-9_\-]{40}'
    keywords:
      - whsec_
    severity: high
    entropy: 3.5
```

Bu yapılandırmayla bir tarama çalıştırın:

```bash
leakwatch scan fs . --config .leakwatch.yaml
```

Özel kural bulgusu için örnek JSON çıktısı (sır değeri maskelenmiştir) — bir özel kural bulgusu, her yerleşik dedektörle tamamen aynı `Finding` şemasını kullanır (bkz. [Çıktı Biçimleri](#/output/output-formats)); özel kurallar için ayrı bir şema yoktur:

```json
{
  "id": "8a403a46336fc6ffdc847d202b74536c",
  "detector_id": "acme-internal-token",
  "severity": "critical",
  "redacted": "****cdef",
  "source": {
    "source_type": "filesystem",
    "file_path": "config/production.env",
    "line": 14
  },
  "verification": {
    "status": "unverified"
  },
  "detected_at": "2026-05-23T10:15:30Z",
  "entropy": 4.12
}
```

:::note
`redacted` alanı gerçek sırrı her zaman maskeler (varsayılan olarak, `****` ve ardından en fazla son 4 karakter). Ham değer, açıkça `--show-raw` geçilmedikçe çıktıya asla yazılmaz (kontrollü ortamlar dışında önerilmez). Özel kuralların doğrulayıcısı olmadığından, `verification.status` her zaman `unverified` olur.
:::

## Özel kuralı hariç tutma

Özel kurallar, yerleşik dedektörlerle aynı filtrelemeye katılır. Bir özel kuralı yapılandırmadan kaldırmadan devre dışı bırakmak için:

```yaml
filter:
  exclude-detectors:
    - acme-internal-token
```

## Ayrıca bakın

- [Yapılandırma: Yapılandırma Dosyası](#/configuration/config-file) — `custom-rules:` öğesinin belge yapısındaki yeri dahil `.leakwatch.yaml` için tam referans.
- [Dedektör Kataloğu](#/detectors/detector-catalog) — özel kuralınızı adlandırmadan önce ID çakışmalarını kontrol etmek için 65 yerleşik dedektör.
- [Nasıl Çalışır](#/getting-started/how-it-works) — `keywords` öğesinin bağlandığı Aho-Corasick ön-filtre hattı.
