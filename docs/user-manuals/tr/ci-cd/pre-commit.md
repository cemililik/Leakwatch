---
title: "Pre-commit Kancası"
description: "Her commit'ten önce sır taraması yapmak için Leakwatch pre-commit kancasını kullanın."
---

# Pre-commit Kancası

Bir sırrı yakalamak için en ucuz an, onu depoya girmeden önce durdurmaktır. Leakwatch, her `git commit` işleminde `leakwatch scan fs` komutunu otomatik olarak çalıştıran yerel bir [pre-commit](https://pre-commit.com) kancası sunar; böylece sızan bir API anahtarı veya parola, geçmişte yer almak yerine commit işlemini başarısız kılar.

## Ön koşullar

Şunlara ihtiyacınız var:

- Python 3.8+ (pre-commit bir Python aracıdır).
- Genel olarak kurulmuş [pre-commit](https://pre-commit.com/#install) (`pip install pre-commit` veya `brew install pre-commit`).
- `PATH` üzerinde Go 1.25+ — kanca dili `golang` olduğundan pre-commit, ilk çalıştırmada Leakwatch'ı kaynaktan derler.

## Yapılandırma

Deponuzun köküne bir `.pre-commit-config.yaml` dosyası ekleyin (veya mevcut olanı genişletin):

```yaml
repos:
  - repo: https://github.com/HodeTech/Leakwatch
    rev: v1.8.0
    hooks:
      - id: leakwatch
```

Kancaları yerel Git deposuna kurun:

```bash
pre-commit install
```

Hepsi bu kadar. Bundan itibaren her `git commit` işlemi bir dosya sistemi taraması tetikler. Leakwatch herhangi bir sır bulursa commit engellenir ve bulgular terminale yazdırılır.

## Elle çalıştırma

Tüm depoyu (yalnızca staged dosyaları değil) istediğiniz zaman taramak için:

```bash
pre-commit run --all-files
```

Diğerlerini tetiklemeden yalnızca Leakwatch kancasını çalıştırmak için:

```bash
pre-commit run leakwatch --all-files
```

## Ek argümanlar geçirme

Kancanın varsayılan davranışı, ek bayrak olmadan `leakwatch scan fs`'e karşılık gelir. `args:` anahtarı aracılığıyla ek argümanlar geçirebilirsiniz:

```yaml
repos:
  - repo: https://github.com/HodeTech/Leakwatch
    rev: v1.8.0
    hooks:
      - id: leakwatch
        args:
          - --only-verified
          - --min-severity
          - high
```

Bu örnek, yalnızca Leakwatch'ın hâlâ etkin olduğunu doğruladığı yüksek önem dereceli sırları raporlar — yanlış pozitif gürültüsünden kaçınmak isteyen ancak kapsam kaybetmek istemeyen ekipler için uygun katı bir politika.

Diğer kullanışlı argümanlar:

```yaml
args:
  - --no-verify          # daha hızlı commit'ler için canlı doğrulamayı atla
  - --min-severity
  - medium               # düşük önem dereceli gürültüyü bastır
  - --format
  - table                # terminalde insan tarafından okunabilir çıktı
```

:::note
Kanca tanımında `pass_filenames: false` ayarlandığından kanca, yalnızca mevcut commit için staged dosyaları değil her zaman tam çalışma ağacını tarar. Bu, staged olmayan dosyalarda halihazırda bulunan sırların da tespit edileceğini garanti eder.
:::

## Kancanın taradıkları

Kanca, depo çalışma dizinine karşı `leakwatch scan fs` çalıştırır. CLI ile aynı tespit hattını kullanır: Aho-Corasick ön filtreleme, regex doğrulama, entropi hesaplama ve (`--no-verify` ayarlanmadıkça) canlı doğrulama.

`.leakwatch.yaml`'daki yapılandırma otomatik olarak uygulanır — dışlama kalıpları, entropi eşikleri ve doğrulama ayarları, herhangi bir ek kanca yapılandırması olmadan geçerli olur.

## Kancayı geçici olarak atlama

Kancayı çalıştırmadan commit yapmak için (örneğin, maskelenmiş sır içeren bir test sabiti commit edilirken):

```bash
SKIP=leakwatch git commit -m "chore: test sabiti ekle"
```

:::warn
`SKIP=leakwatch` kullanmak, o commit için tüm sır taramasını devre dışı bırakır. Yalnızca içeriğin güvenli olduğunu teyit ettiğinizde kullanın; kalıcı bastırmalar için bunun yerine `.leakwatchignore` veya satır içi `leakwatch:ignore` yorumlarını tercih edin.
:::

## Kanca sürümünü sabitli tutma

`rev:` değerini dal adı yerine belirli bir etikete sabitleyin. Bu, ekipteki tüm geliştiricilerin aynı dedektör setini kullandığını ve kancanın sprint ortasında sessizce yükseltilmediğini garantiler:

```yaml
rev: v1.8.0   # sabitle; 'main' veya 'HEAD' kullanmayın
```

Güncellemek için:

```bash
pre-commit autoupdate
```

Bu komut `rev` değerini en son etikete yükseltir ve siz onu commit etmeden önce değişikliği inceleme fırsatı tanır.

## Ayrıca bakın

- [Dosya Sistemi Taraması](#/scanning/filesystem) — kancanın çalıştırdığı temel tarama komutu.
- [Yapılandırma Dosyası](#/configuration/config-file) — `.leakwatch.yaml`'da dışlamaları, entropiyi ve doğrulamayı kontrol etme.
- [GitHub Action](#/ci-cd/github-action) — GitHub CI'da her push ve pull request'te tarama.
- [Çıkış Kodları](#/reference/exit-codes) — çıkış kodlarının tarama sonuçlarıyla nasıl eşleştiği.
