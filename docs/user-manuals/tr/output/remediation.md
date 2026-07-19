---
title: "Düzeltme Rehberi"
description: "Bulguları sağlayıcıya özgü döndürme ve iptal adımları, aciliyet dereceleri ve resmi dokümantasyon bağlantılarıyla zenginleştirmek için --remediation kullanın."
---

# Düzeltme Rehberi

Bir sırrın sızdığını bilmek işin yalnızca yarısıdır — ayrıca ne yapacağınızı da bilmeniz gerekir. Herhangi bir tarama komutuna `--remediation` eklemek, her bulguyu yapılandırılmış, sağlayıcıya özgü rehberlikle zenginleştirir: kimlik bilgisini döndürme veya iptal etme adımları, sağlayıcının belgelerine bağlantı, yönetim konsoluna bağlantı, aciliyet derecelendirmesi ve bir doğrulama kontrol listesi.

## Nasıl etkinleştirilir

Herhangi bir tarama komutuna `--remediation` ekleyin:

```bash
leakwatch scan fs . --remediation
leakwatch scan git . --remediation --format json
leakwatch scan image myapp:latest --remediation --format sarif
```

Düzeltme zenginleştirmesi varsayılan olarak devre dışıdır. Bayrak yoksa, her bulgunun `remediation` alanı `null` olur ve fazladan veri alınmaz veya hesaplanmaz.

## Ne içerir

Her düzeltme girişi aşağıdaki alanları içerir:

| Alan | Açıklama |
|---|---|
| `title` | Düzeltme eyleminin kısa adı (örn. `"Rotate AWS Access Key"`) |
| `steps` | Sırrı döndürmek veya iptal etmek için sıralı adımlar listesi |
| `doc_url` | Sağlayıcının resmi kimlik bilgisi yönetimi belgelerine bağlantı |
| `console_url` | Sağlayıcının yönetim konsolu sayfasına doğrudan bağlantı |
| `urgency` | Ne kadar hızlı harekete geçileceği: `"immediate"`, `"high"` veya `"medium"` |
| `checklist` | Döndürme sonrası doğrulama adımları (örn. denetim günlüklerini inceleyin, güvenlik ekibini bilgilendirin) |

Leakwatch, her yerleşik dedektör için bir tane olmak üzere 64 düzeltme girişiyle birlikte gelir. 64 girişin tamamı ikili dosyaya dahildir; rehberliği almak için herhangi bir ağ çağrısı yapılmaz.

## Her formatta nasıl görünür

Zenginleştirme, rehberliği bellekteki bulgu nesnesine ekler. Nasıl göründüğü çıktı formatına bağlıdır:

**JSON** — tam yapılandırılmış `remediation` nesnesi her bulgunun içine yerleştirilir:

```bash
leakwatch scan fs . --remediation --format json
```

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
  "remediation": {
    "title": "Revoke GitHub Token",
    "steps": [
      "Go to GitHub Settings > Developer settings > Personal access tokens.",
      "Revoke the compromised token immediately.",
      "Create a new token with the minimum required scopes.",
      "Update all integrations and CI/CD pipelines with the new token."
    ],
    "doc_url": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    "console_url": "https://github.com/settings/tokens",
    "urgency": "immediate",
    "checklist": [
      "Review the GitHub audit log for unauthorized actions performed with the token.",
      "Check repository and organization settings for unexpected changes.",
      "Notify the security team about the exposure.",
      "Scan for other repositories that may contain the same token."
    ]
  },
  "entropy": 5.82,
  "detected_at": "2026-05-23T10:15:30Z"
}
```

**SARIF** — `steps` alanları, kuralın `help.text` alanına yerleştirilir ve `doc_url`, kuralın `helpUri`'si olarak ayarlanır. Bu, GitHub Code Scanning'in uyarı ayrıntıları panelinde doğrudan görünür.

**CSV** — yalnızca düzeltme `title`'ı `remediation` sütununa yazılır. Tam yapılandırılmış rehberlik CSV çıktısına dahil edilmez.

**Tablo** — `REMEDIATION` sütununda yalnızca düzeltme `title`'ı gösterilir.

```bash
leakwatch scan fs . --remediation --format table
```

```text
SEVERITY  DETECTOR      FILE                LINE  REDACTED      STATUS           REMEDIATION
--------  --------      ----                ----  --------      ------           -----------
CRITICAL  github-token  scripts/deploy.sh   14    ghp_****Xk9R  verified_active  Revoke GitHub Token

Found 1 secret (1 critical).
```

:::tip
Otomatik olay müdahale iş akışları için tam yapılandırılmış rehberliğe ihtiyaç duyduğunuzda `--remediation --format json` kullanın. Terminalde hızlı, insan tarafından okunabilir bir önceliklendirme oturumu için `--remediation --format table` kullanın.
:::

:::note
Zenginleştirme yalnızca `--remediation` ayarlandığında çalışır. Bayrak olmadan, `remediation` alanı JSON ve SARIF çıktısında yoktur, CSV `remediation` sütunu boştur ve tablo `REMEDIATION` sütunu `-` gösterir. Bayrak, orijinal tarama sonuçlarını değiştirmez — bunların üzerine bir katman ekler.
:::

## Ayrıca bakın

- [Çıktı Formatları](#/output/output-formats)
- [Doğrulama Nasıl Çalışır](#/verification/how-verification-works)
