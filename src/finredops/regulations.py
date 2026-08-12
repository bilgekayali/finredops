"""Versioned regulatory crosswalk for Turkish financial-sector assessments.

The registry contains short, original summaries and source pointers. It does not
reproduce standards or replace legal interpretation by the regulated entity.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import StringEnum, sha256_digest, to_primitive


class AssessmentType(StringEnum):
    ANNUAL_BANK_PENETRATION = "annual_bank_penetration"
    VENDOR_SOURCE_CODE_REVIEW = "vendor_source_code_review"
    VENDOR_APPLICATION_PENETRATION = "vendor_application_penetration"
    REMEDIATION_VERIFICATION = "remediation_verification"


class Authority(StringEnum):
    BDDK = "BDDK"
    SPK = "SPK"
    KVKK = "KVKK"
    TSE = "TSE"
    ISO = "ISO/IEC"


@dataclass(frozen=True, slots=True)
class ControlReference:
    control_id: str
    authority: Authority
    instrument: str
    reference: str
    objective_summary: str
    assessment_types: tuple[AssessmentType, ...]
    expected_evidence: tuple[str, ...]
    source_url: str
    applicability_note: str = ""


@dataclass(frozen=True, slots=True)
class RegulatoryProfile:
    profile_id: str
    title: str
    version: str
    verified_on: str
    controls: tuple[ControlReference, ...]
    legal_notice: str

    def digest(self) -> str:
        return sha256_digest(self)

    def controls_for(self, assessment_type: AssessmentType) -> tuple[ControlReference, ...]:
        return tuple(
            control
            for control in self.controls
            if assessment_type in control.assessment_types
        )

    def get(self, control_id: str) -> ControlReference | None:
        return next((item for item in self.controls if item.control_id == control_id), None)

    def as_dict(self) -> dict[str, Any]:
        return {**to_primitive(self), "digest": self.digest()}


_ALL_APPLICATION = (
    AssessmentType.VENDOR_SOURCE_CODE_REVIEW,
    AssessmentType.VENDOR_APPLICATION_PENETRATION,
)
_ALL_TESTS = (
    AssessmentType.ANNUAL_BANK_PENETRATION,
    AssessmentType.VENDOR_SOURCE_CODE_REVIEW,
    AssessmentType.VENDOR_APPLICATION_PENETRATION,
    AssessmentType.REMEDIATION_VERIFICATION,
)
_PENETRATION_TESTS = (
    AssessmentType.ANNUAL_BANK_PENETRATION,
    AssessmentType.VENDOR_APPLICATION_PENETRATION,
    AssessmentType.REMEDIATION_VERIFICATION,
)


def turkey_financial_regulatory_profile() -> RegulatoryProfile:
    """Return the built-in, source-linked Turkish financial assessment profile."""

    bddk_regulation = (
        "https://www.resmigazete.gov.tr/eskiler/2020/03/20200315-10.htm"
    )
    bddk_circular = "https://www.bddk.org.tr/Mevzuat/DokumanGetir/915"
    spk_regulation = (
        "https://www.resmigazete.gov.tr/eskiler/2025/03/20250313-8.htm"
    )
    kvkk_law = "https://www.kvkk.gov.tr/Icerik/2097/Kanun-doc"
    kvkk_guide = (
        "https://www.kvkk.gov.tr/SharedFolderServer/CMSFiles/"
        "7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf"
    )
    tse_testing = "https://www.tse.org.tr/sizma-testleri/"
    tse_certification = "https://www.tse.org.tr/sizma-testi-belgelendirmesi/"
    iso_27001 = "https://www.iso.org/standard/27001"
    iso_27002 = "https://www.iso.org/standard/75652.html"

    controls = (
        ControlReference(
            "TR-BDDK-BSEBY-18-7",
            Authority.BDDK,
            "Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik",
            "Madde 18/7",
            "Banka hizmetlerini geliştiren veya işleten ekiplerden bağımsız bir ekibin yılda en az bir kez sızma testi yürütmesi.",
            (AssessmentType.ANNUAL_BANK_PENETRATION,),
            (
                "tester independence declaration",
                "annual assessment period",
                "approved scope and rules of engagement",
                "signed report and remediation register",
            ),
            bddk_regulation,
        ),
        ControlReference(
            "TR-BDDK-BSEBY-22-4-5",
            Authority.BDDK,
            "Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik",
            "Madde 22/4-5",
            "Güvenli yazılım gereksinimlerinin yaşam döngüsünde ele alınması ve internete açık uygulamaların kurulumdan önce ve güncellemeler sonrasında güvenlik açıkları açısından taranması.",
            _ALL_APPLICATION,
            (
                "security requirements",
                "pre-production security test",
                "release or commit identifier",
                "post-update verification",
            ),
            bddk_regulation,
        ),
        ControlReference(
            "TR-BDDK-BSEBY-23-1",
            Authority.BDDK,
            "Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik",
            "Madde 23/1",
            "Dahili veya tedarik edilen uygulama kontrollerinin mevzuat, veri bütünlüğü, yetkilendirme ve görevler ayrılığı açısından canlı öncesi test edilmesi ve sonuçların kaydedilmesi.",
            _ALL_APPLICATION,
            (
                "application control inventory",
                "test cases and results",
                "business owner approval",
                "segregation-of-duties evidence",
            ),
            bddk_regulation,
        ),
        ControlReference(
            "TR-BDDK-BSEBY-24-3-B",
            Authority.BDDK,
            "Bankaların Bilgi Sistemleri ve Elektronik Bankacılık Hizmetleri Hakkında Yönetmelik",
            "Madde 24/3-b",
            "Değişikliğin güvenlik zafiyeti doğurmadığına ilişkin, kaynak kod incelemesini de içerebilen yüksek güvenceli inceleme yapılması.",
            (AssessmentType.VENDOR_SOURCE_CODE_REVIEW,),
            (
                "source revision digest",
                "manual review record",
                "SAST and dependency-analysis evidence",
                "reviewer approval",
            ),
            bddk_regulation,
        ),
        ControlReference(
            "TR-BDDK-GEN-2012-1",
            Authority.BDDK,
            "Bilgi Sistemlerine İlişkin Sızma Testleri Hakkında Genelge 2012/1",
            "Bölüm 2-3 ve Ekler",
            "Asgari test alanları, erişim noktaları, kullanıcı profilleri, birleşik risk değerlendirmesi, önem derecesi ve standart bulgu formatının kayıt altına alınması.",
            (AssessmentType.ANNUAL_BANK_PENETRATION,),
            (
                "coverage matrix",
                "access-point and user-profile matrix",
                "finding severity rationale",
                "combined-risk analysis",
                "retest results",
            ),
            bddk_circular,
            "BDDK resmî mevzuat listesinde yer almaktadır; her çalışma öncesi banka hukuk/uyum birimi güncel uygulanabilirliği teyit etmelidir.",
        ),
        ControlReference(
            "TR-SPK-VII-128.10-8-6-7",
            Authority.SPK,
            "Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği (VII-128.10)",
            "Madde 8/6-7 ve Ek-1",
            "Yeterlilik sahibi bağımsız tarafça yıllık sızma testi, Ek-1 yönteminin uygulanması ve raporun düzenleyici süresi içinde iletilmesi.",
            (
                AssessmentType.ANNUAL_BANK_PENETRATION,
                AssessmentType.VENDOR_APPLICATION_PENETRATION,
            ),
            (
                "tester qualification evidence",
                "independence declaration",
                "Ek-1 coverage matrix",
                "completion and submission dates",
                "previous-finding verification",
            ),
            spk_regulation,
            "Yalnızca kuruluş SPK kapsamındaysa uygulanır. Bankalar için özel mevzuat önceliği VII-128.10 Madde 2/2 kapsamında ayrıca değerlendirilir.",
        ),
        ControlReference(
            "TR-SPK-VII-128.10-25",
            Authority.SPK,
            "Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği (VII-128.10)",
            "Madde 25/1-13",
            "Tedarik edilen veya geliştirilen sistemlerde yazılı güvenlik gereksinimleri, güvenli yaşam döngüsü, ortam ayrımı, canlı öncesi güvenlik testi, bulgu giderimi ve sürüm izlenebilirliği.",
            _ALL_APPLICATION,
            (
                "approved security requirements",
                "secure SDLC record",
                "source control revision",
                "acceptance criteria",
                "pre-production results and remediation evidence",
            ),
            spk_regulation,
        ),
        ControlReference(
            "TR-SPK-VII-128.10-26",
            Authority.SPK,
            "Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği (VII-128.10)",
            "Madde 26",
            "Kritik uygulamalarda girdi/çıktı, hata, oturum, erişim, API, mobil, kaynak kod, dosya yükleme ve hassas veri kontrollerinin doğrulanması.",
            _ALL_APPLICATION,
            (
                "application security control matrix",
                "API and session test results",
                "input and file validation evidence",
                "sensitive-data handling evidence",
                "source-protection review",
            ),
            spk_regulation,
        ),
        ControlReference(
            "TR-SPK-VII-128.10-28",
            Authority.SPK,
            "Bilgi Sistemleri Yönetimine İlişkin Usul ve Esaslar Tebliği (VII-128.10)",
            "Madde 28",
            "Değişikliklerin risk, test, onay, geri dönüş ve sonuç gözden geçirme kayıtlarıyla yönetilmesi.",
            _ALL_APPLICATION,
            (
                "change record",
                "risk and impact analysis",
                "test and rollback plan",
                "release approval",
            ),
            spk_regulation,
        ),
        ControlReference(
            "TR-KVKK-6698-12",
            Authority.KVKK,
            "6698 sayılı Kişisel Verilerin Korunması Kanunu",
            "Madde 12/1-2",
            "Kişisel verilerin hukuka aykırı işlenmesini ve erişimini önlemek, muhafazasını sağlamak için uygun teknik ve idari tedbirlerin alınması; veri işleyen tarafların kontrol edilmesi.",
            _ALL_TESTS,
            (
                "personal-data scope and minimization record",
                "technical and administrative control evidence",
                "processor or supplier responsibility record",
                "restricted evidence handling log",
            ),
            kvkk_law,
        ),
        ControlReference(
            "TR-KVKK-GUIDE-3.2",
            Authority.KVKK,
            "Kişisel Veri Güvenliği Rehberi (Teknik ve İdari Tedbirler)",
            "Bölüm 3.2",
            "Düzenli zafiyet taraması ve sızma testi yapılması, sonuçların değerlendirilmesi, tespitlerin giderilmesi ve güvenliğin izlenmesi.",
            (
                AssessmentType.ANNUAL_BANK_PENETRATION,
                AssessmentType.VENDOR_APPLICATION_PENETRATION,
                AssessmentType.REMEDIATION_VERIFICATION,
            ),
            (
                "test date and scope",
                "finding register",
                "remediation owner and due date",
                "closure evidence and retest status",
            ),
            kvkk_guide,
        ),
        ControlReference(
            "TR-KVKK-GUIDE-3.5",
            Authority.KVKK,
            "Kişisel Veri Güvenliği Rehberi (Teknik ve İdari Tedbirler)",
            "Bölüm 3.5",
            "Yeni sistemlerin tedariki, geliştirilmesi veya iyileştirilmesinde kişisel veri güvenliği gereksinimlerinin baştan değerlendirilmesi.",
            _ALL_APPLICATION,
            (
                "privacy and security requirements",
                "test-data provenance and masking evidence",
                "supplier security assessment",
                "release security acceptance",
            ),
            kvkk_guide,
        ),
        ControlReference(
            "TR-TSE-TS13638-T2-QUALIFICATION",
            Authority.TSE,
            "TS 13638/T2 Bilgi Teknolojileri - Güvenlik Teknikleri - Sızma testi yapan personel ve firmalar için şartlar",
            "TSE'nin kamuya açık firma belgelendirme ön koşulları",
            "Sızma testi hizmetini sunan firmanın güncel TSE belge seviyesi ve kapsamı ile görevlendirilen personelin yeterliliklerinin, ISO/IEC 27001 koşulunun ve sözleşme kayıtlarının doğrulanması.",
            _PENETRATION_TESTS,
            (
                "TSE certificate number, level, scope and validity",
                "assigned personnel qualification matrix",
                "applicable ISO/IEC 27001 certificate or requirement evidence",
                "signed contract, confidentiality and engagement records",
            ),
            tse_certification,
            "TSE belgesi tek başına düzenleyici uyum veya test sonucunun yeterliliği anlamına gelmez; güncel belge kapsamı insan incelemesiyle doğrulanmalıdır.",
        ),
        ControlReference(
            "TR-TSE-TS13638-T2-PROCESS",
            Authority.TSE,
            "TS 13638/T2 Bilgi Teknolojileri - Güvenlik Teknikleri - Sızma testi yapan personel ve firmalar için şartlar",
            "Lisanslı standardın güncel çalışma ve raporlama şartları",
            "Kullanılan lisanslı standardın sürümünün kaydedilmesi ve uygulanabilir çalışma, kanıt ve raporlama şartlarının insan tarafından onaylanmış bir madde matrisiyle izlenmesi.",
            _PENETRATION_TESTS,
            (
                "licensed standard identifier, revision and access record",
                "human-reviewed clause applicability matrix",
                "project records mapped to applicable clauses",
                "reviewer approval and documented exceptions",
            ),
            tse_certification,
            "TSE, standardın temin edilmesini ve tüm şartların karşılanmasını ister. Lisanslı metin bu projede çoğaltılmaz; kesin madde numaraları yetkili nüshadan eklenmelidir.",
        ),
        ControlReference(
            "TR-TSE-SIZMA-TESTI-KAPSAMI",
            Authority.TSE,
            "TSE Bilişim Teknolojileri Sızma Testleri",
            "Güncel Sızma Testi Kapsamı dokümanı",
            "Onaylı test kapsamının TSE'nin güncel kapsam dokümanıyla karşılaştırılması; dahil, hariç ve uygulanamaz alanların gerekçeli ve kanıt bağlantılı kaydedilmesi.",
            _PENETRATION_TESTS,
            (
                "approved scope and rules of engagement",
                "current TSE scope document link, access date and digest",
                "included, excluded and not-applicable coverage matrix",
                "scope owner and reviewer approval",
            ),
            tse_testing,
            "TSE bağlantısındaki kapsam dokümanı güncellenebileceğinden her çalışma için erişim tarihi, sürüm veya özet değer ve onaylı farklar saklanmalıdır.",
        ),
        ControlReference(
            "ISO27001-CLAUSES-6.1-8.1-9.1-10.2",
            Authority.ISO,
            "ISO/IEC 27001:2022",
            "Clauses 6.1, 8.1, 9.1 and 10.2",
            "Risk değerlendirme ve işleme, operasyonel kontrol, performans değerlendirme ve uygunsuzluk için düzeltici faaliyetin izlenmesi.",
            _ALL_TESTS,
            (
                "risk linkage",
                "assessment plan",
                "measurable result",
                "corrective-action and verification record",
            ),
            iso_27001,
            "Standart metni lisanslı kaynaktan doğrulanmalıdır; bu kayıt kısa bir uygulama haritasıdır.",
        ),
        ControlReference(
            "ISO27001-A.5.19-A.5.22",
            Authority.ISO,
            "ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022",
            "Controls 5.19-5.22",
            "Tedarikçi ilişkileri ve tedarik zinciri risklerinin sözleşme, izleme ve değişiklik süreçlerine bağlanması.",
            _ALL_APPLICATION,
            (
                "supplier risk assessment",
                "security contract requirements",
                "service review and change evidence",
            ),
            iso_27002,
            "Kontrol açıklamaları ISO/IEC 27002:2022 lisanslı nüshasından uygulanmalıdır.",
        ),
        ControlReference(
            "ISO27001-A.5.31-A.5.36",
            Authority.ISO,
            "ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022",
            "Controls 5.31, 5.33-5.36",
            "Yasal ve sözleşmesel yükümlülükler, kayıtların korunması, kişisel veri, bağımsız inceleme ve politika uyumunun kanıtlanması.",
            _ALL_TESTS,
            (
                "regulatory crosswalk",
                "evidence retention record",
                "privacy classification",
                "independent review and exception record",
            ),
            iso_27002,
            "Kontrol açıklamaları ISO/IEC 27002:2022 lisanslı nüshasından uygulanmalıdır.",
        ),
        ControlReference(
            "ISO27001-A.8.8-A.8.16",
            Authority.ISO,
            "ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022",
            "Controls 8.8, 8.15 and 8.16",
            "Teknik zafiyetlerin yönetimi ile olay kaydı ve izleme kontrollerinin test sonuçlarına bağlanması.",
            _ALL_TESTS,
            (
                "vulnerability and finding register",
                "logging evidence",
                "monitoring and alert validation",
                "remediation verification",
            ),
            iso_27002,
            "Kontrol açıklamaları ISO/IEC 27002:2022 lisanslı nüshasından uygulanmalıdır.",
        ),
        ControlReference(
            "ISO27001-A.8.25-A.8.29",
            Authority.ISO,
            "ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022",
            "Controls 8.25-8.29",
            "Güvenli geliştirme yaşam döngüsü, uygulama gereksinimleri, güvenli mimari, güvenli kodlama ve geliştirme/kabul güvenlik testlerinin kanıtlanması.",
            _ALL_APPLICATION,
            (
                "secure SDLC evidence",
                "application security requirements",
                "architecture and code review",
                "security acceptance test",
            ),
            iso_27002,
            "Kontrol açıklamaları ISO/IEC 27002:2022 lisanslı nüshasından uygulanmalıdır.",
        ),
        ControlReference(
            "ISO27001-A.8.31-A.8.34",
            Authority.ISO,
            "ISO/IEC 27001:2022 Annex A / ISO/IEC 27002:2022",
            "Controls 8.31, 8.32 and 8.34",
            "Ortam ayrımı, kontrollü değişiklik ve denetim testi sırasında üretim sistemlerinin korunması.",
            _ALL_TESTS,
            (
                "environment separation",
                "approved change record",
                "rules of engagement and safety controls",
                "test rollback and stop procedure",
            ),
            iso_27002,
            "Kontrol açıklamaları ISO/IEC 27002:2022 lisanslı nüshasından uygulanmalıdır.",
        ),
    )
    return RegulatoryProfile(
        profile_id="turkey-financial-assurance-v1",
        title="Türkiye Finansal Kuruluşlar Güvenlik Testi Çapraz Kontrol Profili",
        version="1.1.0",
        verified_on="2026-08-12",
        controls=controls,
        legal_notice=(
            "Bu profil mevzuat ve standart gereksinimlerinin teknik test kanıtlarına eşlenmesine "
            "yardımcı olur; hukuki görüş, düzenleyici onay, bağımsız denetim veya ISO uygunluk "
            "beyanı değildir. Kuruluşun tabiiyet ve istisnaları hukuk/uyum birimince doğrulanmalıdır. "
            "ISO standartları ve TS 13638/T2 gibi lisanslı metinler yetkili nüshalardan uygulanmalı; "
            "bu profildeki kısa özetler standardın yerine kullanılmamalıdır."
        ),
    )
