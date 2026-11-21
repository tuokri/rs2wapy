# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Project-path resolution for source checkouts and editable installs."""

from __future__ import annotations

import tomllib
from pathlib import Path

PROJECT_NAME = "webadmin-api-docs"


def project_root(start: Path | None = None) -> Path:
    """Locate the webadmin-api-docs project without assuming a checkout layout."""
    module_path = Path(__file__).resolve()
    search_starts = [start.resolve() if start is not None else module_path]
    if start is None:
        search_starts.append(Path.cwd().resolve())

    for search_start in search_starts:
        if search_start.is_file():
            base = search_start.parent
        else:
            base = search_start
        for candidate in (base, *base.parents):
            pyproject = candidate / "pyproject.toml"
            if not pyproject.is_file():
                continue
            try:
                payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                continue
            project = payload.get("project")
            if isinstance(project, dict) and project.get("name") == PROJECT_NAME:
                return candidate.resolve()
    raise RuntimeError("unable to locate the webadmin-api-docs project root")
