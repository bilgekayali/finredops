# Türkiye finansal kuruluş güvenlik testi profili

Bu belge FinRedOps `turkey-financial-assurance-v1` profilinin kaynak ve
uygulanabilirlik kaydıdır. Amaç, güvenlik testi kanıtını düzenleyici beklentilerle
izlenebilir biçimde eşlemektir. Hukuki görüş, mevzuata uygunluk beyanı, bağımsız
denetim görüşü, düzenleyici kabul veya ISO belgelendirmesi değildir.

Profil en son **12 Ağustos 2026** tarihinde aşağıdaki resmî kaynaklara göre
kontrol edilmiştir. Kuruluşun türü, faaliyet izni, istisnaları ve geçiş hükümleri
her çalışma başında hukuk/uyum birimi tarafından yeniden doğrulanmalıdır.

## Değerlendirme türleri

| FinRedOps türü | Birincil kullanım | Zorunlu rapor çekirdeği |
|---|---|---|
| `annual_bank_penetration` | Bankanın periyodik/yıllık sızma testi | bağımsızlık, yeterlilik, yıllık dönem, BDDK kapsam matrisi, birleşik risk, bulgu ve yeniden test |
| `vendor_source_code_review` | Yeni veya değişen tedarik uygulamasının kaynak kod güvenlik incelemesi | sürüm/commit özeti, güvenlik gereksinimleri, SAST, bağımlılık, gizli bilgi, manuel kod incelemesi ve kabul kararı |
| `vendor_application_penetration` | Yeni tedarik edilen uygulamanın canlı öncesi sızma testi | kimlikli/kimliksiz senaryolar, yetkilendirme, oturum, API, iş mantığı, veri koruma, giderim ve yeniden test |
| `remediation_verification` | Önceki bulguların kapanış kontrolü | özgün bulgu izi, yeni kanıt, yeniden test sonucu, sorumlu ve insan onayı |

## BDDK

Kaynak: [Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik](https://www.resmigazete.gov.tr/eskiler/2020/03/20200315-10.htm)

| Profil kontrolü | Dayanak | Teknik değerlendirme amacı |
|---|---|---|
| `TR-BDDK-BSEBY-18-7` | Madde 18/7 | Geliştirme/işletimden bağımsız ekipçe yılda en az bir sızma testi; dönem, bağımsızlık ve onay kanıtı |
| `TR-BDDK-BSEBY-22-4-5` | Madde 22/4-5 | Güvenli yazılım gereksinimlerinin tedarik ve geliştirme başlangıcında tanımlanması; internete açık uygulamanın canlı öncesi ve güncelleme sonrası güvenlik kontrolü |
| `TR-BDDK-BSEBY-23-1` | Madde 23/1 | Dahili veya tedarik uygulaması kontrollerinin canlı öncesi test edilmesi ve sonuçların kaydedilmesi |
| `TR-BDDK-BSEBY-24-3-B` | Madde 24/3-b | Değişiklik sonrası yüksek güvenceli inceleme; uygulanabilir durumda kaynak kod incelemesi ve sürüm izlenebilirliği |

Kaynak: [Bilgi Sistemlerine İlişkin Sızma Testleri Hakkında Genelge 2012/1](https://www.bddk.org.tr/Mevzuat/DokumanGetir/915)

`TR-BDDK-GEN-2012-1`, yıllık banka testinde iletişim altyapısı, DNS, etki
alanı/uç noktalar, e-posta, veri tabanı, web, mobil, kablosuz ağ, ATM ve hizmet
sürekliliği/direnç alanlarının kapsam kaydını; erişim noktası ve kullanıcı
profili matrisini; birleşik risk, standart önem derecesi ve bulgu formatını
zorunlu kılar. Genelge [BDDK resmî mevzuat listesinde](https://www.bddk.org.tr/Mevzuat/Liste/134)
yer almakla birlikte, uygulanabilirliği her çalışma öncesinde banka hukuk/uyum
birimince teyit edilmelidir.

## SPK

Kaynak: [Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği (VII-128.10)](https://www.resmigazete.gov.tr/eskiler/2025/03/20250313-8.htm)

> [!IMPORTANT]
> Eski VII-128.9 güncel dayanak değildir. VII-128.10, 13 Mart 2025 tarihinde
> yayımlanmış ve 30 Haziran 2025 tarihinde yürürlüğe girerek önceki tebliği
> yürürlükten kaldırmıştır.

| Profil kontrolü | Dayanak | Teknik değerlendirme amacı |
|---|---|---|
| `TR-SPK-VII-128.10-8-6-7` | Madde 8/6-7 ve Ek-1 | Yeterli ve bağımsız tarafça yıllık test, Ek-1 kapsam matrisi, önceki bulgu kontrolü ve teslim tarihleri |
| `TR-SPK-VII-128.10-25` | Madde 25/1-13 | Tedarik/geliştirme güvenlik gereksinimleri, güvenli yaşam döngüsü, ortam ayrımı, canlı öncesi test, kritik bulgu giderimi ve sürüm kaydı |
| `TR-SPK-VII-128.10-26` | Madde 26 | Uygulama güvenliği; girdi/çıktı, hata, oturum, erişim, API, mobil, dosya ve hassas veri kontrolleri |
| `TR-SPK-VII-128.10-28` | Madde 28 | Değişiklik riski, test, onay, geri dönüş ve sonuç gözden geçirme kayıtları |

SPK kontrolleri yalnızca kuruluş veya hizmet Tebliğ kapsamındaysa uygulanır.
Bankalara ilişkin özel mevzuat önceliği ve Madde 2 kapsamı hukuk/uyum tarafından
değerlendirilir; profil otomatik hukuki tabiiyet kararı vermez.

## KVKK

Kaynaklar: [6698 sayılı Kanun Madde 12](https://www.kvkk.gov.tr/Icerik/2097/Kanun-doc),
[Veri Güvenliğine İlişkin Yükümlülükler](https://www.kvkk.gov.tr/Icerik/2040/Veri-Guvenligine-Iliskin-Yukumlulukler)
ve [Kişisel Veri Güvenliği Rehberi](https://www.kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf).

| Profil kontrolü | Dayanak | Teknik değerlendirme amacı |
|---|---|---|
| `TR-KVKK-6698-12` | Kanun Madde 12/1-2 | Hukuka aykırı işleme/erişimi önleyen ve muhafazayı sağlayan teknik-idari tedbirler; veri işleyen/tedarikçi sorumluluğu |
| `TR-KVKK-GUIDE-3.2` | Rehber Bölüm 3.2 | Düzenli zafiyet taraması ve sızma testi, sonuç değerlendirmesi, giderim ve izleme |
| `TR-KVKK-GUIDE-3.5` | Rehber Bölüm 3.5 | Yeni sistem tedariki, geliştirme veya iyileştirmede kişisel veri güvenliğinin baştan ele alınması |

Bir test kaydının bulunması tek başına kapanış değildir. FinRedOps yüksek/kritik
açık bulguda sorumlu ve hedef tarih; başarılı yeniden testte ayrı tarih ve
kanıt referansı ister. Ham kişisel veri rapora gömülmez; kanıt koruyucusu e-posta,
geçerli IBAN/kart ve sır olabilecek alanları deterministik olarak maskeler.

## TSE TS 13638/T2 ve Sızma Testi Kapsamı

Kamuya açık resmî kaynaklar:

- [TSE Bilişim Teknolojileri Sızma Testleri](https://www.tse.org.tr/sizma-testleri/)
- [TSE Sızma Testi Yapan Firmaların Belgelendirilmesi](https://www.tse.org.tr/sizma-testi-belgelendirmesi/)

TSE'nin kamuya açık sayfaları, bilişim teknolojileri sızma testlerini ulusal
`TS 13638` standardı çerçevesinde tanımlar; firma belgelendirme sayfası güncel
dayanağı `TS 13638/T2 — Bilgi Teknolojileri - Güvenlik Teknikleri - Sızma testi
yapan personel ve firmalar için şartlar` olarak adlandırır. Aynı sayfa A/B/C
firma seviyeleri, personel yeterlilikleri, uygulanabilir ISO/IEC 27001 koşulları,
sözleşme/proje kayıtları ve TSE incelemesi hakkında kamuya açık ön koşulları
verir.

| Profil kontrolü | Kamuya açık dayanak | Teknik değerlendirme amacı |
|---|---|---|
| `TR-TSE-TS13638-T2-QUALIFICATION` | TSE firma belgelendirme ön koşulları | Güncel firma belge numarası/seviyesi/kapsam/geçerliliği, görevlendirilen personel yeterlilik matrisi, uygulanabilir ISO belgesi/koşulu ve imzalı çalışma kayıtları |
| `TR-TSE-TS13638-T2-PROCESS` | Lisanslı TS 13638/T2'nin güncel çalışma ve raporlama şartları | Yetkili standart nüshasının kimliği ve revizyonu ile insan onaylı madde-kanıt-istisna matrisi |
| `TR-TSE-SIZMA-TESTI-KAPSAMI` | TSE sayfasından erişilen güncel “Sızma Testi Kapsamı” dokümanı | Onaylı kapsamın güncel TSE kapsamıyla karşılaştırılması; dahil, hariç ve uygulanamaz alanların gerekçeli kaydı |

> [!IMPORTANT]
> TSE, standardın temin edilmesini ve şartlarının karşılanmasını ister. FinRedOps
> telifli/lisanslı standart metnini veya erişilemeyen madde numaralarını kopyalamaz
> ve uydurmaz. Her çalışma için lisanslı nüshanın sürümü, erişim kaydı ve yetkili
> uzman tarafından onaylanan madde matrisi kanıt olarak sağlanmalıdır. TSE firma
> belgesi de tek başına düzenleyici uyum veya test sonucunun yeterliliğini kanıtlamaz.

`tse_ts13638_in_scope` kararı otomatik çıkarılmaz. Kuruluşun sözleşmesi, test
türü, düzenleyici beklentileri ve satın alma/denetim şartları dikkate alınarak
yetkili insan tarafından `true`, `false` veya `null` olarak kaydedilir. `null`
durumunda ilgili TSE kontrolleri `requires_confirmation` olur ve paket teslim
kapısı fail-closed davranır.

## ISO/IEC 27001:2022

Kaynaklar: [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) ve
[ISO/IEC 27002:2022](https://www.iso.org/standard/75652.html).

Profil, Madde 6.1, 8.1, 9.1 ve 10.2 ile Ek A kontrol grupları 5.19-5.22,
5.31/5.33-5.36, 8.8/8.15/8.16, 8.25-8.29 ve 8.31/8.32/8.34 için yalnızca
kontrol kimliği ve özgün kısa amaç özeti içerir. Standart metni yeniden üretmez.
Kontrolün gerçek yorumu ve denetim kanıtı, kuruluşun lisanslı ISO/IEC 27001 ve
27002 nüshalarına göre yetkili uzman tarafından doğrulanmalıdır.

## Uygulanabilirlik ve kanıt kuralları

- Her kontrol için `conforms`, `partial`, `gap`, `not_applicable` veya
  `not_tested` sonucu kaydedilir.
- `not_applicable` otomatik seçilmez; insan gerekçesi zorunludur.
- BDDK, SPK, KVKK, TSE ve ISO kapsam kararları tarihli yetkili kişi kaydına
  bağlanmadan denetim paketi teslimata hazır sayılmaz.
- Uygulanabilir sonuç kanıt veya bulgu referansı olmadan geçerli sayılmaz.
- Her bulgu en az bir kontrol ve erişim kontrollü kanıt URI'sine bağlanır.
- Yüksek/kritik açık bulgu sorumlu ve hedef tarih olmadan rapor doğrulamasını
  geçemez.
- Başarılı yeniden test ayrı kapanış kanıtı olmadan kaydedilemez.
- `approved` veya `issued` durumuna geçmek iki farklı insan onay kaydı gerektirir.

Bu kontroller `src/finredops/regulations.py` içinde sürümlü veri olarak,
zorunlu kapsam ve rapor kuralları ise `src/finredops/reporting.py` içinde
çalıştırılabilir doğrulama olarak bulunur.
