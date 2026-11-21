#!/usr/bin/env python3

# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to
# do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Capture a reversible server-actors settings round trip."""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

import click
import httpx2

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger
from webadmin_api_docs.tools.gameplay_settings_roundtrip_probe import remaining_seconds
from webadmin_api_docs.tools.probe_webadmin import Capture
from webadmin_api_docs.tools.probe_webadmin import Sanitizer
from webadmin_api_docs.tools.probe_webadmin import WebAdminProbe
from webadmin_api_docs.tools.probe_webadmin import write_capture

MIN_REMAINING_SECONDS = 60
TEST_ACTOR = "IpDrv.WebServer\nRS2WAPY.TestServerActor"


def serveractors_value(body: str) -> str:
    """Extract and normalize the server actors textarea."""
    match = re.search(
        r'<textarea[^>]*\bname=["\']serveractors["\'][^>]*>(.*?)</textarea>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise RuntimeError("server actors page did not contain the textarea")
    return (
        html.unescape(match.group(1)).replace("\r\n", "\n").replace("\r", "\n").strip()
    )


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline: str | None = None

    try:
        logger.info("authenticating for server-actors save and restore")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        timer = probe.request("serveractors-match-timer", "current")
        captures.append(timer)
        seconds = remaining_seconds(timer.body)
        if seconds is None:
            raise RuntimeError("match timer was unavailable in the Current page")
        if seconds < MIN_REMAINING_SECONDS:
            raise RuntimeError(
                f"refusing server-actor write with {seconds} seconds left; "
                f"minimum safety window is {MIN_REMAINING_SECONDS}"
            )

        baseline_page = probe.request(
            "serveractors-baseline",
            "settings/serveractors",
        )
        captures.append(baseline_page)
        baseline = serveractors_value(baseline_page.body)
        if TEST_ACTOR in baseline:
            raise RuntimeError("test server actor already exists")

        changed = baseline.rstrip("\n") + "\nRS2WAPY.TestServerActor"
        captures.append(
            probe.request(
                "serveractors-change",
                "settings/serveractors",
                {"serveractors": changed, "action": "save"},
            )
        )
        after_change = probe.request(
            "serveractors-after-change",
            "settings/serveractors",
        )
        captures.append(after_change)
        if "RS2WAPY.TestServerActor" not in serveractors_value(after_change.body):
            raise RuntimeError("test server actor was not rendered after save")

        captures.append(
            probe.request(
                "serveractors-restore",
                "settings/serveractors",
                {"serveractors": baseline, "action": "save"},
            )
        )
        after_restore = probe.request(
            "serveractors-after-restore",
            "settings/serveractors",
        )
        captures.append(after_restore)
        if serveractors_value(after_restore.body) != baseline:
            raise RuntimeError("server actors were not restored exactly")
        baseline = None
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "serveractors", "error": str(error)})
    finally:
        if probe is not None and baseline is not None:
            try:
                captures.append(
                    probe.request(
                        "serveractors-cleanup",
                        "settings/serveractors",
                        {"serveractors": baseline, "action": "save"},
                    )
                )
                cleanup = probe.request(
                    "serveractors-after-cleanup",
                    "settings/serveractors",
                )
                captures.append(cleanup)
                if serveractors_value(cleanup.body) != baseline:
                    raise RuntimeError("server-actors cleanup mismatch")
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append({"route": "serveractors-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("serveractors-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "serveractors-logout", "error": str(error)})

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(args.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    if failures:
        for failure in failures:
            logger.warning("{}: {}", failure["route"], failure["error"])
        return 1
    logger.info("wrote {} sanitized captures to '{}'", len(entries), args.output)
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    username: str | None,
    password: str | None,
) -> None:
    """Run a reversible server-actors discovery pass."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
