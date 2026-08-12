# FinRedOps Example Security Report

> **Checked-in synthetic example.** This document is a repository-visible example generated from the governed SARIF → qualified review → draft report workflow. It does not describe a live target, a real institution, or a regulatory submission.

# Sentetik Qualified-Review Kaynak Kod Güvenlik Raporu

> **Denetim destek taslağıdır.** Hukuki görüş, düzenleyici kabul, bağımsız denetim görüşü veya ISO belgelendirmesi değildir.

## Belge kontrolü

| Alan | Değer |
|---|---|
| Rapor kimliği | `FRX-RPT-REVIEWED-DEMO-001` |
| Kuruluş | Example Financial Institution (Synthetic) |
| Değerlendirme | `vendor_source_code_review` |
| Dönem | 2026-08-12 – 2026-08-12 |
| Durum | `draft` |
| Sınıflandırma | RESTRICTED — SYNTHETIC |
| Düzenleyici profil | `turkey-financial-assurance-v1` / `a420e50823ad11c8` |
| Rapor özeti | `061ef6aa685d9ef6c21b83f47f6cb0cd8bdcb61a7e8b9f2febefc1223c2a1adc` |

## Yönetici özeti

This synthetic workflow demonstrates controlled promotion from machine evidence into a human-reviewed draft report without contacting a live target. Qualified review completed for 2/2 candidates; 1 confirmed finding(s) were promoted into this draft.

## Kapsam ve yöntem

- Çalışma kuralları: `attachment://FRX-DEMO-2026-001/approved-roe`
- Test kuruluşu / lideri: Independent Test Team (Synthetic) / Synthetic Qualified Tester
- Bağımsızlık beyanı: Synthetic demonstration reviewer is represented as separate from development operations.
- Kapsam: `synthetic-source-repository`
- Hariç tutulanlar: `production-systems`
- Yöntem: bounded SARIF 2.1.0 intake, qualified human disposition, digest-bound evidence review, draft report promotion
- Zorunlu kapsam alanları: `authentication_authorization`, `cryptography`, `dependency_analysis`, `logging_error_handling`, `manual_code_review`, `release_integrity`, `sast`, `secret_detection`, `security_requirements`

## Bulgu özeti

| Kritik | Yüksek | Orta | Düşük | Bilgi |
|---:|---:|---:|---:|---:|
| 0 | 1 | 0 | 0 | 0 |

### FRX-SARIF-BA51E3E30C0CD41409EE3F7F — Synthetic query construction requires review

- Önem / durum: `high` / `open`
- Etkilenen varlık: `repo://src/synthetic/query.py`
- Güvenli özet: The synthetic qualified tester correlated the normalized scanner candidate with retained demonstration evidence and confirmed the condition.
- İş etkisi: In an equivalent authorized deployment, the confirmed condition could weaken application security controls and increase remediation risk.
- Öneri: Correct the defensive implementation, retain change evidence, and perform an independent authorized retest before closure.
- Kanıt: `evidence://sarif/f57c4d51acd6e290d16a75511a74eddd503fdaa5ae14999fb30b513cc2dfee9d/ba51e3e30c0cd41409ee3f7fbf4c69006575c80e4d87cd58b428bf6f1753b924`, `evidence://synthetic-review/ba51e3e30c0cd41409ee3f7fbf4c69006575c80e4d87cd58b428bf6f1753b924`
- Kontroller: `TR-BDDK-BSEBY-22-4-5`
- Sorumlu / hedef tarih: Synthetic Engineering Owner / 2026-09-30
- Yeniden test: `not_tested` / Tarih yok

## Düzenleyici çapraz kontrol

| Kurum | Dayanak | Sonuç | Kanıt / bulgu |
|---|---|---|---|
| BDDK | `TR-BDDK-BSEBY-22-4-5` — Madde 22/4-5 | `partial` | evidence://sarif/f57c4d51acd6e290d16a75511a74eddd503fdaa5ae14999fb30b513cc2dfee9d/ba51e3e30c0cd41409ee3f7fbf4c69006575c80e4d87cd58b428bf6f1753b924, evidence://synthetic-review/ba51e3e30c0cd41409ee3f7fbf4c69006575c80e4d87cd58b428bf6f1753b924, FRX-SARIF-BA51E3E30C0CD41409EE3F7F |
| BDDK | `TR-BDDK-BSEBY-23-1` — Madde 23/1 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| BDDK | `TR-BDDK-BSEBY-24-3-B` — Madde 24/3-b | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| SPK | `TR-SPK-VII-128.10-25` — Madde 25/1-13 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| SPK | `TR-SPK-VII-128.10-26` — Madde 26 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| SPK | `TR-SPK-VII-128.10-28` — Madde 28 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| KVKK | `TR-KVKK-6698-12` — Madde 12/1-2 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| KVKK | `TR-KVKK-GUIDE-3.5` — Bölüm 3.5 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-CLAUSES-6.1-8.1-9.1-10.2` — Clauses 6.1, 8.1, 9.1 and 10.2 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-A.5.19-A.5.22` — Controls 5.19-5.22 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-A.5.31-A.5.36` — Controls 5.31, 5.33-5.36 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-A.8.8-A.8.16` — Controls 8.8, 8.15 and 8.16 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-A.8.25-A.8.29` — Controls 8.25-8.29 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |
| ISO/IEC | `ISO27001-A.8.31-A.8.34` — Controls 8.31, 8.32 and 8.34 | `not_tested` | evidence://review-summary/68fbfb7e758d0ad6f6656ae6e7a5eaa1262c77822d9e4ece7954b601cd14e81c |

## Sınırlamalar ve insan onayı

- Synthetic evidence only; results cannot be generalized to a real institution.
- This draft was assembled only from a complete qualified-review set; machine candidates were not promoted without human disposition.
- Promotion does not issue the report, establish regulatory compliance, or replace independent human approval.
- Yapısal doğrulama: `geçti`
- Yayıma hazır: `hayır`
- İnsan onay kayıtları: Henüz yok
- BDDK/SPK tabiiyeti, TSE şartname kapsamı, istisnalar ve teslim süreleri her çalışma öncesinde hukuk/uyum ve yetkili test sorumlularınca doğrulanmalıdır.
- TS 13638/T2 ve ISO/IEC kontrol metinleri kuruluşun yetkili/lisanslı standart nüshalarından teyit edilmelidir.
- Ham kanıtlar rapora gömülmemeli; erişim kontrollü kanıt deposunda tutulmalıdır.
