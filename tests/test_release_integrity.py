from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from finredops.release_integrity import (
    EXAMPLE_FILENAMES,
    ReleaseIntegrityError,
    export_packaged_examples,
    verify_release_checksums,
)


class ReleaseIntegrityTests(unittest.TestCase):
    def test_packaged_examples_export_without_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "examples"
            written = export_packaged_examples(output)
            self.assertEqual(tuple(path.name for path in written), EXAMPLE_FILENAMES)
            self.assertTrue(all(path.is_file() for path in written))
            self.assertIn('"version": "2.1.0"', (output / "synthetic_sast.sarif.json").read_text())

            with self.assertRaises(ReleaseIntegrityError):
                export_packaged_examples(output)

    def test_checksum_manifest_verifies_release_bytes_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "finredops-0.6.1-py3-none-any.whl"
            artifact.write_bytes(b"synthetic wheel bytes")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            manifest = root / "CHECKSUMS.sha256"
            manifest.write_text(f"{digest}  {artifact.name}\n", encoding="utf-8")

            result = verify_release_checksums(manifest, root)
            self.assertTrue(result["valid"])
            self.assertEqual(result["artifact_count"], 1)
            self.assertFalse(result["provenance_verified"])

            artifact.write_bytes(b"tampered wheel bytes")
            changed = verify_release_checksums(manifest, root)
            self.assertFalse(changed["valid"])
            self.assertEqual(changed["artifacts"][0]["error"], "digest_mismatch")

    def test_checksum_manifest_rejects_path_escape_and_duplicate_subjects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = "a" * 64
            escaped = root / "escaped.sha256"
            escaped.write_text(f"{digest}  ../artifact.whl\n", encoding="utf-8")
            with self.assertRaises(ReleaseIntegrityError):
                verify_release_checksums(escaped, root)

            duplicate = root / "duplicate.sha256"
            duplicate.write_text(
                f"{digest}  artifact.whl\n{digest}  artifact.whl\n",
                encoding="utf-8",
            )
            with self.assertRaises(ReleaseIntegrityError):
                verify_release_checksums(duplicate, root)


if __name__ == "__main__":
    unittest.main()
