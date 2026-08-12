"""Release-integrity helpers for packaged examples and local checksum verification.

This module does not attempt to establish provenance by itself. Release provenance
is produced by the GitHub Actions attestation workflow; this code provides the
local, deterministic integrity checks that can run without trusting a source
checkout.
"""

from __future__ import annotations

import hashlib
import re
from contextlib import contextmanager
from importlib import resources
from pathlib import Path
from typing import Iterator


class ReleaseIntegrityError(ValueError):
    """Raised when packaged examples or release-integrity inputs are invalid."""


EXAMPLE_FILENAMES = (
    "synthetic_engagement.json",
    "synthetic_ai_plan.json",
    "synthetic_sast.sarif.json",
)

_CHECKSUM_LINE = re.compile(r"^([0-9A-Fa-f]{64})[ \t]+\*?(.+)$")


def _example_resource(name: str):
    if name not in EXAMPLE_FILENAMES:
        raise ReleaseIntegrityError(f"Unknown packaged example: {name!r}.")
    return resources.files("finredops.examples").joinpath(name)


@contextmanager
def packaged_example_path(name: str) -> Iterator[Path]:
    """Yield a filesystem path for one packaged example, including zipped installs."""

    resource = _example_resource(name)
    with resources.as_file(resource) as path:
        yield Path(path)


def export_packaged_examples(output_dir: Path) -> tuple[Path, ...]:
    """Export the immutable bundled examples without overwriting existing files."""

    if output_dir.exists() and not output_dir.is_dir():
        raise ReleaseIntegrityError("output-dir must be a directory path.")
    collisions = [name for name in EXAMPLE_FILENAMES if (output_dir / name).exists()]
    if collisions:
        raise ReleaseIntegrityError(
            f"Refusing to overwrite existing packaged examples: {sorted(collisions)}."
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name in EXAMPLE_FILENAMES:
        destination = output_dir / name
        with resources.as_file(_example_resource(name)) as source:
            with destination.open("xb") as target:
                target.write(Path(source).read_bytes())
        written.append(destination)
    return tuple(written)


def _safe_manifest_name(raw: str) -> str:
    name = raw.strip()
    if not name:
        raise ReleaseIntegrityError("Checksum manifest contains an empty file name.")
    path = Path(name)
    if path.is_absolute() or name != path.name or ".." in path.parts:
        raise ReleaseIntegrityError(
            "Checksum manifest file names must be simple release-artifact basenames."
        )
    return name


def read_checksum_manifest(path: Path) -> dict[str, str]:
    """Read a sha256sum-style manifest with strict basename-only subjects."""

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseIntegrityError("Checksum manifest must be UTF-8 text.") from exc

    entries: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if not raw_line.strip():
            continue
        match = _CHECKSUM_LINE.fullmatch(raw_line)
        if match is None:
            raise ReleaseIntegrityError(
                f"Invalid checksum manifest line {line_number}; expected SHA-256 and filename."
            )
        digest, raw_name = match.groups()
        name = _safe_manifest_name(raw_name)
        if name in entries:
            raise ReleaseIntegrityError(
                f"Checksum manifest contains duplicate entry for {name!r}."
            )
        entries[name] = digest.lower()

    if not entries:
        raise ReleaseIntegrityError("Checksum manifest contains no release artifacts.")
    return entries


def verify_release_checksums(manifest_path: Path, directory: Path) -> dict[str, object]:
    """Verify every manifest subject against local bytes in one release directory."""

    if not directory.is_dir():
        raise ReleaseIntegrityError("Release directory does not exist or is not a directory.")

    entries = read_checksum_manifest(manifest_path)
    results: list[dict[str, object]] = []
    valid = True
    for name, expected in sorted(entries.items()):
        subject = directory / name
        if not subject.is_file():
            results.append(
                {
                    "file": name,
                    "expected_sha256": expected,
                    "actual_sha256": None,
                    "valid": False,
                    "error": "missing",
                }
            )
            valid = False
            continue
        actual = hashlib.sha256(subject.read_bytes()).hexdigest()
        matches = actual == expected
        results.append(
            {
                "file": name,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "valid": matches,
                "error": None if matches else "digest_mismatch",
            }
        )
        valid = valid and matches

    return {
        "schema_version": "finredops.release-checksum-verification.v1",
        "manifest": str(manifest_path),
        "directory": str(directory),
        "artifact_count": len(entries),
        "valid": valid,
        "artifacts": results,
        "provenance_verified": False,
        "provenance_note": (
            "SHA-256 verification checks local integrity only. Verify GitHub/Sigstore "
            "provenance separately with `gh attestation verify`."
        ),
    }
