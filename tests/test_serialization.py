from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from finredops.models import EngagementStatus, to_primitive
from finredops.serialization import (
    DocumentValidationError,
    engagement_from_document,
    read_json_document,
)

from tests.helpers import make_engagement


class SerializationTests(unittest.TestCase):
    def test_engagement_round_trip(self) -> None:
        source = to_primitive(make_engagement(status=EngagementStatus.DRAFT))
        parsed = engagement_from_document(source)
        self.assertEqual(parsed.digest(), make_engagement().digest())

    def test_unknown_engagement_field_fails_closed(self) -> None:
        source = to_primitive(make_engagement(status=EngagementStatus.DRAFT))
        source["command"] = "ignored"
        with self.assertRaises(DocumentValidationError):
            engagement_from_document(source)

    def test_invalid_asset_enum_is_rejected(self) -> None:
        source = to_primitive(make_engagement(status=EngagementStatus.DRAFT))
        source["assets"][0]["environment"] = "internet"
        with self.assertRaises(DocumentValidationError):
            engagement_from_document(source)

    def test_document_size_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.json"
            path.write_text(json.dumps({"value": "x" * 100}), encoding="utf-8")
            with self.assertRaises(DocumentValidationError):
                read_json_document(path, maximum_bytes=10)


if __name__ == "__main__":
    unittest.main()
