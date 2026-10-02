# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
