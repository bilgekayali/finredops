from __future__ import annotations

import unittest

from finredops.asvs_coverage import AsvsRequirementCatalog


class AsvsCoverageTests(unittest.TestCase):
    def test_catalog_is_pinned_to_500(self):
        catalog = AsvsRequirementCatalog(
            source_version="5.0.0",
            source_sha256="a" * 64,
            source_ref="attachment://standards/asvs-5.0.0",
            requirement_refs=("v5.0.0-1.2.5",),
        )
        self.assertEqual(catalog.source_version, "5.0.0")
        self.assertFalse(catalog.requirement_text_embedded)
