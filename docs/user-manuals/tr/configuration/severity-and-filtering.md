---
title: "Önem Derecesi & Filtreleme"
description: "Önem eşikleri, yalnızca doğrulanmış mod, dedektör dışlamaları ve yol dışlamaları kullanarak hangi bulguların çıktınıza ulaşacağını kontrol edin."
---

# Önem Derecesi & Filtreleme

Yoğun bir kod tabanı çok sayıda bulgu üretebilir. Leakwatch, en önemli sinyallere odaklanmak için birleştirebileceğiniz birkaç bağımsız filtre sunar: önem eşikleri düşük öncelikli gürültüyü eler, yalnızca doğrulanmış mod yalnızca onaylanmış canlı sırları ortaya çıkarır, dedektör dışlamaları bilinen yanlış pozitif kaynakları susturur ve yol dışlamaları tüm dizin ağaçlarını kapsamın dışında bırakır.

## Önem seviyeleri

Her yerleşik dedektör, varsayılan bir önem derecesiyle birlikte gelir. En düşükten en yüksek önceliğe doğru dört seviye şunlardır:

| Seviye | Tipik kullanım |
|---|---|
| `low` | Daha yüksek yanlış pozitif oranına sahip genel desenler |
| `medium` | Tanınabilir kimlik bilgisi biçimleri, doğrulanmamış |
| `high` | Maruziyetin büyük olasılıkla önemli olduğu iyi yapılandırılmış sırlar |
| `critical` | Onaylanmış canlı sırlar veya neredeyse sıfır yanlış pozitif oranlı biçimler |

Her dedektöre atanan önem derecesi [Dedektör Kataloğu](#/detectors/detector-catalog)'nda listelenmiştir.

## `--min-severity`: eşiğin altındaki bulguları bırak

Belirtilen seviyenin altındaki önem derecesine sahip bulguları atmak için `--min-severity <level>` parametresini kullanın. Yalnızca eşik değerinde veya üzerindeki bulgular çıktıya ulaşır.

```bash
# Yalnızca high ve critical bulguları göster
leakwatch scan fs . --min-severity high

# medium, high ve critical bulguları göster
leakwatch scan fs . --min-severity medium
```

`output.severity-threshold` altında yapılandırma dosyasında kalıcı bir varsayılan ayarlayabilirsiniz. `--min-severity` bayrağı, çalışma zamanında yapılandırma değerini geçersiz kılar:

```yaml
output:
  severity-threshold: medium
```

## `--only-verified`: yalnızca onaylanmış aktif sırlar

Yalnızca doğrulama durumu `verified_active` olan bulguları, yani Leakwatch'ın sağlayıcı API'sine kontrollü bir salt-okunur çağrı yaparak hâlâ geçerli olduğunu doğruladığı sırları tutmak için `--only-verified` parametresini kullanın. Diğer tüm bulgular (`unverified`, `verified_inactive` veya `verify_error`) bırakılır.

```bash
leakwatch scan fs . --only-verified
```

Bu bayrak, derlemeyi yalnızca onaylanmış olaylar üzerinde, yer tutucu veya zaten döndürülmüş kimlik bilgileri olabilecek şüpheli desenler üzerinde değil, başarısız kılmak istediğiniz CI hatlarında en kullanışlıdır.

Hangi dedektörlerin canlı doğrulamayı desteklediği için [Doğrulama Nasıl Çalışır](#/verification/how-verification-works) bölümüne bakın.

## `filter.exclude-detectors`: belirli dedektörleri devre dışı bırak

Bir veya daha fazla dedektörü kalıcı olarak devre dışı bırakmak için ID'lerini yapılandırma dosyasındaki `filter.exclude-detectors` altında listeleyin. Listelenen dedektörlerden gelen bulgular, diğer ayarlardan bağımsız olarak hiçbir zaman üretilmez:

```yaml
filter:
  exclude-detectors:
    - generic-api-key
    - jwt
```

Dedektör ID'leri [Dedektör Kataloğu](#/detectors/detector-catalog)'nda listelenmiştir. Bir dedektör sürekli olarak kod tabanınız için yanlış pozitifler ürettiğinde ve diğer bastırma mekanizmaları (satır içi yok saymalar veya `.leakwatchignore`) yeterince ayrıntılı olmadığında bu ayarı kullanın.

Yapılandırma dosyasını düzenlemeden bir dedektörü tek bir çalıştırma için susturmak üzere, herhangi bir tarama alt komutunda `--exclude-detectors <id>[,<id>...]` (tekrarlanabilir) geçirin. Bu, `filter.exclude-detectors`'ın yerine geçmek yerine ona ekleme yapar.

## `filter.exclude-paths`: tarama öncesi yolları atla

Yolları tarama motoru okumadan önce dışlamak için yapılandırma dosyasında `filter.exclude-paths` kullanın. Desenler, `.leakwatchignore` ile aynı glob söz dizimini kullanır (standart globlar, `**` çift yıldız ve sondaki eğik çizgili dizin desenleri) ve **tüm tarama kaynaklarına** uygulanır:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "test/fixtures/"
```

:::note
`--exclude <pattern>` bayrağı, `filter.exclude-paths`'in komut satırı eşdeğeridir ve `scan slack` **hariç** (bunun yerine `--exclude-channels` ile dışlama yapan) her tarama alt komutunda kullanılabilir. Tekrarlanabilir olup `filter.exclude-paths`'in yerine geçmek yerine ona ekleme yapar.
:::

## CI'da filtreleri birleştirme

Bir CI hattında genellikle yalnızca gerçek olaylarda başarısız olan, düşük gürültülü ve yüksek sinyalli bir çalışma istersiniz. Önerilen bir kombinasyon:

```bash
leakwatch scan fs . \
  --only-verified \
  --min-severity high \
  --format sarif \
  --output results.sarif
```

Yapılandırma dosyasının kalıcı yol dışlamalarını yönetmesiyle:

```yaml
filter:
  exclude-paths:
    - "vendor/**"
    - "node_modules/**"
    - "test/fixtures/"
  exclude-detectors:
    - generic-api-key

output:
  severity-threshold: high
```

Ardından CI için yalnızca biçimi ve hedefi komut satırında geçersiz kılın:

```bash
leakwatch scan fs . --only-verified --format sarif --output results.sarif
```

Doğrulama ayrıntıları için [Doğrulama Nasıl Çalışır](#/verification/how-verification-works), satır içi ve dosya tabanlı bastırma için [Bulguları Yok Sayma](#/configuration/ignoring-findings) ve tam şema için [Yapılandırma Dosyası](#/configuration/config-file) bölümlerine bakın.

## Ayrıca bakın

- [Dedektör Kataloğu](#/detectors/detector-catalog)
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works)
- [Yapılandırma Dosyası](#/configuration/config-file)
- [Bulguları Yok Sayma](#/configuration/ignoring-findings)
