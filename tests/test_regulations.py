from __future__ import annotations

import unittest

from finredops.models import canonical_json
from finredops.regulations import (
    AssessmentType,
    Authority,
    turkey_financial_regulatory_profile,
)


class RegulationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = turkey_financial_regulatory_profile()

    def test_control_ids_are_unique_and_source_linked(self) -> None:
        ids = [control.control_id for control in self.profile.controls]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(control.source_url.startswith("https://") for control in self.profile.controls))

    def test_all_five_authorities_are_present(self) -> None:
        authorities = {control.authority for control in self.profile.controls}
        self.assertEqual(authorities, set(Authority))

    def test_tse_profile_uses_current_public_references(self) -> None:
        tse_controls = [
            control for control in self.profile.controls if control.authority == Authority.TSE
        ]
        self.assertEqual(len(tse_controls), 3)
        self.assertTrue(all("TS 13638/T2" in item.instrument for item in tse_controls[:2]))
        self.assertEqual(
            {item.source_url for item in tse_controls},
            {
                "https://www.tse.org.tr/sizma-testleri/",
                "https://www.tse.org.tr/sizma-testi-belgelendirmesi/",
            },
        )
        self.assertTrue(
            any("lisans" in item.applicability_note.casefold() for item in tse_controls)
        )

    def test_current_spk_instrument_replaces_old_reference(self) -> None:
        document = canonical_json(self.profile)
        self.assertIn("VII-128.10", document)
        self.assertNotIn("VII-128.9", document)

    def test_assessment_types_have_applicable_controls(self) -> None:
        for assessment_type in AssessmentType:
            self.assertTrue(
                self.profile.controls_for(assessment_type), assessment_type.value
            )

    def test_profile_digest_is_stable(self) -> None:
        self.assertEqual(
            self.profile.digest(), turkey_financial_regulatory_profile().digest()
        )


if __name__ == "__main__":
    unittest.main()
