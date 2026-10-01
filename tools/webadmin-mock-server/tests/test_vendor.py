"""Integrity checks for vendored browser assets."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path

from webadmin_mock_server.app import STATIC_DIRECTORY


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_vendored_htmx_matches_its_manifest() -> None:
    vendor_directory = STATIC_DIRECTORY / "debug" / "vendor" / "htmx"
    manifest = tomllib.loads((vendor_directory / "MANIFEST.toml").read_text(encoding="utf-8"))

    assert manifest["version"] == "4.0.0"
    assert _sha256(vendor_directory / "htmx.js") == manifest["htmx_sha256"]
    assert _sha256(vendor_directory / "LICENSE") == manifest["license_sha256"]
