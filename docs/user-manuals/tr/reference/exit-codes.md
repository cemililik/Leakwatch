---
title: "Çıkış Kodları"
description: "Leakwatch çıkış kodu başvurusu ve bunların betiklerde ve CI pipeline'larında nasıl kullanılacağı."
---

# Çıkış Kodları

Leakwatch, CI pipeline'larının ve kabuk betiklerinin çıktıyı ayrıştırmadan tarama sonuçlarına göre hareket edebilmesi için küçük, iyi tanımlanmış bir çıkış kodu seti kullanır. Her tarama alt komutu dört koddan biriyle çıkar.

## Kod başvurusu

| Kod | Ad | Anlam |
|-----|----|-------|
| `0` | Temiz | Tarama başarıyla tamamlandı ve etkin filtrelerden hiçbir bulgu geçmedi. |
| `1` | Bulgular var | Tarama tamamlandı ve etkin filtrelerden geçen bir veya daha fazla sır bulundu (ve etkin filtrelerden geçti). Bu, diğer her sonuca göre önceliklidir: bulgular raporlanmışsa, tarama daha sonra kesintiye uğrasa veya çoklu depo taramasındaki bir depo başarısız olsa bile çıkış kodu `1` döndürülür. |
| `2` | Hata | Taramanın hiç çalışamamasına neden olan ciddi bir hata oluştu — örneğin geçersiz bir bayrak, okunamaz bir yol veya kimlik doğrulama hatası. Stderr'e bir `Error: ...` mesajı ve kullanım ipucu yazdırılır. |
| `3` | Kesintiye uğradı | Tarama tamamlanmadan önce `SIGINT` (`Ctrl+C`) veya `SIGTERM` aldı ve kesinti anında **hiçbir** bulgu raporlamamıştı. Kısmi sonuçlar (filtrelemeden geçen varsa) yine de yapılandırılmış çıktıya yazılır. Bu nedenle bir CI hattı, tamamlanmadan biten bir tarama için asla temiz bir `0` çıkışı gözlemleyemez. |

## Filtrelerin çıkış kodu 1'i nasıl etkilediği

Çıkış kodu `1`, yalnızca en az bir bulgu etkin çıktı filtrelerinin tümünden geçtiğinde yayılır. En ilgili iki filtre şunlardır:

- **`--min-severity`** — eşiğin altındaki bulgular bastırılır. Tüm bulgular `low` önem derecesindeyse ve `--min-severity high` ile çalışıyorsanız, sırlar mevcut olmasına rağmen çıkış kodu `0` döndürülür.
- **`--only-verified`** — yalnızca canlı doğrulama ile etkin olduğu teyit edilen bulgular raporlanır. Etkin sır bulunamazsa çıkış kodu `0` döndürülür.

Bu, çıkış kodu `0`'ın "mevcut filtre ayarlarınızla eşleşen bulgu yok" anlamına geldiği anlamına gelir — kod tabanının hiçbir sır içermediği değil.

:::warn
`--only-verified` altında temiz `0` çıkışı, kod tabanının sırdan arındırılmış olduğunu garanti etmez. Doğrulamanın mevcut olmadığı sır türleri (10 dedektör türü) her zaman doğrulanmamış olarak raporlanır ve `--only-verified` tarafından bastırılır. Tam kapsam için `--only-verified` ile birlikte ayrı bir filtresiz tarama yapın.
:::

## Kabuk betiklerinde çıkış kodlarını kullanma

```bash
#!/usr/bin/env bash
set +e
leakwatch scan fs . --format json --output leakwatch.json --no-verify
EXIT_CODE=$?
set -e

case "$EXIT_CODE" in
  0)
    echo "Sır bulunamadı. Derleme devam ediyor."
    ;;
  1)
    echo "Sırlar bulundu — birleştirmeden önce leakwatch.json'u inceleyin ve düzeltin."
    exit 1
    ;;
  3)
    echo "Tarama tamamlanmadan kesintiye uğradı — güvenilmez sayın, birleştirmeyin."
    exit 3
    ;;
  *)
    echo "Leakwatch bir hatayla karşılaştı (çıkış $EXIT_CODE)."
    exit "$EXIT_CODE"
    ;;
esac
```

Taramadan önce `set +e` kullanmak, kabuğun sıfır dışı kodlarda çıkmasını engeller ve kodu kendiniz yakalayıp işlemenize olanak tanır.

## CI pipeline'larında çıkış kodlarını kullanma

Çoğu CI sistemi, sıfır dışı herhangi bir çıkış kodunu adım başarısızlığı olarak değerlendirir. Leakwatch sırlar bulunduğunda `1` ile çıktığından, ek yapılandırma olmadan pipeline otomatik olarak başarısız olur — yalnızca tarama komutunu çalıştırın.

Sırlar bulunsa bile pipeline'ın devam etmesine izin vermek için (örneğin, derlemeyi engellemeden raporu toplamak amacıyla) çıkış kodunu açıkça yoksayın:

```bash
leakwatch scan fs . --format sarif --output results.sarif --no-verify || true
```

Ya da GitLab CI'da:

```yaml
allow_failure: true
```

Ya da GitHub Action'da `fail-on-findings: "false"` olarak ayarlayın.

## Uygulamada çıkış kodu 2

Çıkış kodu `2`, taramanın hiç çalışamamasına neden olan bir yapılandırma veya çalışma zamanı hatasını gösterir. Yaygın nedenler:

- Geçersiz bir bayrak değeri (örneğin `--format invalid`).
- Mevcut olmayan veya okunamaz bir yol.
- Eksik gerekli argüman (örneğin, URL olmadan `scan git`).
- Bir bulut kaynağına bağlanırken kimlik doğrulama hatası.

Hata mesajı stderr'e yazdırılır ve sorunu teşhis etmeye yardımcı olacak bağlam içerir. Örneğin, geçersiz bir `--format` değeri şunu üretir:

```text
Error: failed to load configuration: unsupported output format: xlsx

Run 'leakwatch scan fs --help' for usage information.
```

Geçerli `--format` değerleri `json`, `sarif`, `csv`, `table` ve `github`'dır.

## Ayrıca bakın

- [Diğer CI Sistemleri](#/ci-cd/other-ci) — çıkış kodlarını GitLab CI, Jenkins ve diğerlerine bağlama.
- [GitHub Action](#/ci-cd/github-action) — resmi action'ın çıkış kodlarını adım sonuçlarıyla nasıl eşlediği.
- [CLI Başvurusu](#/reference/cli-reference) — tam bayrak başvurusu.
