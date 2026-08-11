---
title: "Tanıtım"
description: "Leakwatch nedir, neyi tarar ve sızan sırları nasıl tespit edip doğrular."
---

# Tanıtım

**Leakwatch**, sızan sırları — API anahtarları, token'lar, parolalar, bağlantı dizeleri ve özel anahtarlar — kod tabanlarınızda, Git geçmişinizde, konteyner imajlarınızda, bulut depolamanızda ve Slack çalışma alanlarınızda **tespit eden, doğrulayan ve raporlayan** yüksek performanslı, açık kaynaklı (MIT) bir güvenlik aracıdır.

Go ile yazılmıştır, çalışma zamanı bağımlılığı olmayan tek bir statik ikili dosya olarak dağıtılır (`CGO_ENABLED=0`) ve her yerde çalışacak şekilde tasarlanmıştır: bir geliştirici dizüstü bilgisayarı, bir pre-commit kancası veya bir CI/CD hattı.

## Neden Leakwatch

Tek bir commit'te sızan bir kimlik bilgisi — sonradan silinse bile — Git geçmişinde sonsuza dek erişilebilir kalabilir ve push edildikten dakikalar sonra istismar edilebilir. Leakwatch, bu sırları erken yakalamak ve hangilerinin *gerçekten tehlikeli* olduğunu söylemek için tasarlanmıştır:

- **Geniş tespit** — bulut sağlayıcılarını, yapay zekâ API'lerini, ödeme platformlarını, veritabanlarını, mesajlaşma araçlarını, yapılandırılmış config dosyalarını ve daha fazlasını kapsayan 65 yerleşik dedektör; ayrıca kendi YAML özel kurallarınız.
- **Dürüst doğrulama kabiliyeti** — 39 dedektör türü doğrudan canlı kontrole sahiptir, 9'u güvenilir issuer/bölge/eşlik eden bağlam gerektirir, 6'sı çevrimdışı format doğrular. Registry sayısı hiçbir zaman canlı kapsam gibi sunulmaz.
- **Çok sayıda kaynak** — yerel dosya sistemi, eksiksiz bir Git geçmişi, bir OCI/Docker imajı, AWS S3, Google Cloud Storage ve Slack mesajları.
- **CI-uyumlu çıktı** — JSON, SARIF (GitHub Code Scanning için), CSV, renklendirilmiş bir terminal tablosu ve satır içi GitHub Actions ek açıklamaları.
- **Tasarımı gereği sır-güvenli** — bulunan sırlar varsayılan olarak maskelenir ve asla loglanmaz, önbelleğe alınmaz veya diske yazılmaz.

## Neleri tarar

| Kaynak | Komut | Neyi kapsar |
|--------|-------|-------------|
| Dosya sistemi | `leakwatch scan fs` | Yerel bir dizin ağacındaki dosyalar |
| Git geçmişi | `leakwatch scan git` | Tüm commit geçmişindeki her blob (yerel veya uzak) |
| Konteyner imajı | `leakwatch scan image` | OCI/Docker imaj katmanları, daemonsuz |
| AWS S3 | `leakwatch scan s3` | Bir S3 kovasındaki nesneler |
| Google Cloud Storage | `leakwatch scan gcs` | Bir GCS kovasındaki nesneler |
| Slack | `leakwatch scan slack` | Kanallardaki ve (isteğe bağlı) DM'lerdeki mesaj metni |
| Çoklu depo | `leakwatch scan repos` | Aynı anda birden fazla Git deposu |

## Tespit kısaca nasıl çalışır

Leakwatch, büyük girdilerde bile hızlı kalmak için katmanlı bir hat kullanır:

1. **Aho-Corasick anahtar kelime ön-filtresi** — tek bir çok-desenli otomat, bir parçayı hangi dedektörlerin eşleştirebileceğine hızla karar verir; böylece dedektörlerin çoğu regex'ini hiç çalıştırmaz.
2. **Regex doğrulaması** — yalnızca kısa listeye alınan dedektörler kesin desenlerini çalıştırır.
3. **Entropi** — Shannon entropisi gösterim için hesaplanır ve yerleşik `generic-api-key` dedektörü ile kendi entropi eşiğine sahip her özel kuralı kapılayarak düşük rastgelelikteki yer tutucu eşleşmeleri eler. Diğer her (yapısal) yerleşik dedektör entropi tarafından hiçbir zaman kapılanmaz.
4. **Doğrulama** — uygun bulgular canlı sağlayıcı API'sine karşı kontrol edilir.

:::tip
Leakwatch'ı kullanmak için bu hattı anlamanız gerekmez — ancak taramaların neden hızlı olduğunu ve bazı bulguların neden bir doğrulama durumu gösterirken bazılarının göstermediğini açıklar. Tam tablo için [Nasıl Çalışır](#/getting-started/how-it-works) bölümüne bakın.
:::

## Leakwatch *ne değildir*

Beklentileri doğru belirlemek için:

- Git geçmişini yeniden yazmaz veya sırları sizin için **kaldırmaz** — onları bulup raporlar ve (`--remediation` ile) nasıl döndüreceğinizi söyler.
- Slack varsayılan olarak mesaj metnini tarar; boyutu sınırlı metin benzeri ekler `--include-files` ve `files:read` kapsamıyla isteğe bağlıdır.
- Doğrulama, birçok sır türü için mevcuttur ancak hepsi için değil — 10 dedektör türü (JWT'ler ve genel API anahtarları gibi) güvenli biçimde doğrulanamaz ve her zaman doğrulanmamış olarak raporlanır.

## Sonraki adımlar

- [Kurulum](#/getting-started/installation) — Homebrew, `go install`, Docker veya hazır bir ikili dosya ile kurun.
- [Hızlı Başlangıç](#/getting-started/quick-start) — ilk taramanızı bir dakikadan kısa sürede çalıştırın.
- [Nasıl Çalışır](#/getting-started/how-it-works) — taramanın arkasındaki mimari.
