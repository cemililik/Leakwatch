---
title: "Diğer CI Sistemleri"
description: "Leakwatch'ı GitLab CI, Jenkins, Bitbucket Pipelines ve diğer CI sistemlerine entegre edin."
---

# Diğer CI Sistemleri

Leakwatch, çalışma zamanı bağımlılığı olmayan tek bir statik ikili dosya olduğundan, kabuk komutu çalıştırabilen herhangi bir CI ortamında çalışır: GitLab CI, Jenkins, Bitbucket Pipelines, CircleCI, Azure DevOps ve diğerleri. Bu sayfada açıklananların ötesinde bu sistemler için yerleşik bir entegrasyon yoktur; kalıp her zaman aynıdır: ikili dosyayı kur, taramayı çalıştır, çıkış koduna göre hareket et.

## CI'da Leakwatch kurma

Runner ortamınıza en uygun yöntemi seçin:

### `go install` aracılığıyla (runner'da Go gerektirir)

```bash
go install github.com/HodeTech/leakwatch@latest
```

Yeniden üretilebilir derlemeler için belirli bir sürüme sabitleyin:

```bash
go install github.com/HodeTech/leakwatch@v1.5.0
```

### Docker imajı aracılığıyla (Go gerekmez)

`ghcr.io/hodetech/leakwatch:latest`'i iş imajı olarak kullanın veya `docker run` ile çalıştırın. Tam kalıp için [Docker Kullanımı](#/ci-cd/docker-usage) sayfasına bakın.

### Hazır bir sürüm ikili dosyası aracılığıyla

Uygun tar arşivini [GitHub Releases](https://github.com/HodeTech/Leakwatch/releases) sayfasından indirin, çıkarın ve `PATH`'e ekleyin:

```bash
curl -LO https://github.com/HodeTech/Leakwatch/releases/latest/download/leakwatch_Linux_amd64.tar.gz
tar -xzf leakwatch_Linux_amd64.tar.gz
sudo mv leakwatch /usr/local/bin/leakwatch
```

## Çıkış kodları

Leakwatch, bir CI derlemesini başarısız kılmanın birincil mekanizması olan dört koddan biriyle çıkar:

| Kod | Anlam | Önerilen CI eylemi |
|-----|-------|-------------------|
| `0` | Bulgu yok | Pipeline aşamasını geç |
| `1` | Sırlar bulundu | Pipeline aşamasını başarısız kıl |
| `2` | Ciddi hata (hatalı yapılandırma, okunamaz yol vb.) | Pipeline aşamasını başarısız kıl |
| `3` | Tamamlanmadan (`Ctrl+C` / `SIGTERM`) kesildi, hiçbir bulgu raporlanmadı | Pipeline aşamasını başarısız kıl — tarama tamamlanmadığından temiz bir sonuca güvenilemez |

Çıkış koduna göre dallanma yapan genel bir kabuk parçacığı:

```bash
set +e
leakwatch scan fs . --format json -o leakwatch.json --no-verify
EXIT_CODE=$?
set -e

if [ "$EXIT_CODE" -eq 0 ]; then
  echo "Sır bulunamadı."
elif [ "$EXIT_CODE" -eq 1 ]; then
  echo "Sırlar bulundu — derlemeyi başarısız kılıyorum."
  exit 1
else
  echo "Tarama hatası veya kesintisi (çıkış $EXIT_CODE) — derlemeyi başarısız kılıyorum."
  exit "$EXIT_CODE"
fi
```

## GitLab CI örneği

Aşağıdaki `.gitlab-ci.yml` işi Leakwatch'ı kurar, dosya sistemi taraması çalıştırır ve JSON raporunu pipeline artifact'i olarak saklar:

```yaml
leakwatch:
  stage: test
  image: golang:1.25-alpine
  script:
    - go install github.com/HodeTech/leakwatch@v1.5.0
    - leakwatch scan fs . --format json -o leakwatch.json --no-verify
  artifacts:
    when: always
    paths:
      - leakwatch.json
    expire_in: 7 days
  allow_failure: false
```

`allow_failure: false` (varsayılan) değeri, çıkış kodu `1`'in pipeline aşamasını başarısız kılması anlamına gelir. Taramanın merge işlemini engellemeden raporlamasını istiyorsanız `allow_failure: true` olarak ayarlayın.

:::tip
GitLab, SAST raporu artifact'larını destekler. Leakwatch SARIF üretir (`--format sarif`) ancak GitLab'ın yerel SAST JSON şemasını değil; bu nedenle `reports: sast:` anahtarı yerine `paths:` artifact yaklaşımını kullanın.
:::

## CI runner'ları için öneriler

**Giden internet erişimi olmayan runner'larda `--no-verify` kullanın.** Doğrulama, sağlayıcılara (AWS, GitHub, Stripe vb.) canlı API çağrıları yapar. Hava boşluklu veya güvenlik duvarıyla kısıtlanmış runner'larda bu çağrılar zaman aşımına uğrar ve taramayı yavaşlatır. Doğrulamayı tamamen atlamak için `--no-verify` geçirin:

```bash
leakwatch scan fs . --no-verify --format sarif -o results.sarif
```

**Çıktıyı artifact olarak kaydedin.** İşi tamamlandıktan sonra saklanabilecek, bir güvenlik açığı yönetim platformuna yüklenebilecek veya incelenebilecek bir dosya yazmak için `--format sarif` ya da `--format json` ile birlikte `--output` kullanın.

**`--min-severity`** değerini en çok önem taşıyan sırlara odaklanmak için ayarlayın. Gürültülü bir kod tabanında `--min-severity high` ile başlayın ve birikmiş öğeleri temizledikten sonra eşiği düşürün.

## Azure DevOps örneği

```yaml
- script: |
    go install github.com/HodeTech/leakwatch@v1.5.0
    leakwatch scan fs . --format sarif -o $(Build.ArtifactStagingDirectory)/leakwatch.sarif --no-verify
  displayName: "Leakwatch sır taraması"

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: "$(Build.ArtifactStagingDirectory)"
    artifactName: "leakwatch-results"
```

## Jenkins örneği

```groovy
stage('Sır taraması') {
    steps {
        sh '''
            go install github.com/HodeTech/leakwatch@v1.5.0
            leakwatch scan fs . --format json -o leakwatch.json --no-verify
        '''
        archiveArtifacts artifacts: 'leakwatch.json', allowEmptyArchive: true
    }
}
```

## Ayrıca bakın

- [Çıkış Kodları](#/reference/exit-codes) — tüm çıkış kodlarının tam referansı.
- [Çıktı Biçimleri](#/output/output-formats) — JSON, SARIF, CSV ve tablo çıktısı.
- [Docker Kullanımı](#/ci-cd/docker-usage) — ikili dosyayı kurmak yerine konteyner imajını kullanma.
- [GitHub Action](#/ci-cd/github-action) — GitHub iş akışları için resmi action.
