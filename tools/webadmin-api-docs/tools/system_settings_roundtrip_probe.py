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

"""Capture a reversible RS2 WebAdmin system-settings round trip."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import click
import httpx2
from general_settings_roundtrip_probe import general_settings_form
from general_settings_roundtrip_probe import input_value
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger

FIELD = "settings_ChatRefresh"
MIN_REMAINING_SECONDS = 60


def remaining_seconds(body: str) -> int | None:
    """Read remaining match seconds from /current."""
    match = re.search(
        r"<dt>Time Limit</dt>\s*<dd>[^<]+<br\s*/>(\d+) seconds remaining",
        body,
        re.IGNORECASE,
    )
    return int(match.group(1)) if match else None


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline_form: dict[str, str] | None = None
    baseline_value = ""

    try:
        logger.info("authenticating for system-settings save and restore")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        timer = probe.request("system-settings-match-timer", "current")
        captures.append(timer)
        seconds = remaining_seconds(timer.body)
        if seconds is None:
            raise RuntimeError("match timer was unavailable in the Current page")
        if seconds < MIN_REMAINING_SECONDS:
            raise RuntimeError(
                f"refusing system-settings write with {seconds} seconds left; "
                f"minimum safety window is {MIN_REMAINING_SECONDS}"
            )

        baseline = probe.request("system-settings-baseline", "settings/system")
        captures.append(baseline)
        baseline_form = general_settings_form(baseline.body)
        baseline_value = input_value(baseline.body, FIELD)
        try:
            integer_value = int(baseline_value)
        except ValueError as error:
            raise RuntimeError(
                f"chat refresh was not an integer: {baseline_value}"
            ) from error
        if integer_value >= 9999:
            raise RuntimeError("chat refresh cannot be increased safely")

        changed_form = baseline_form.copy()
        changed_form[FIELD] = str(integer_value + 10)
        changed_form["action"] = "save"

        logger.info(
            "changing chat refresh from {} to {}",
            baseline_value,
            changed_form[FIELD],
        )
        captures.append(
            probe.request(
                "system-settings-change",
                "settings/system",
                changed_form,
            )
        )
        after_change = probe.request(
            "system-settings-after-change",
            "settings/system",
        )
        captures.append(after_change)
        if input_value(after_change.body, FIELD) != changed_form[FIELD]:
            raise RuntimeError("chat refresh did not match the submitted value")

        logger.info("restoring the exact system-settings baseline")
        captures.append(
            probe.request(
                "system-settings-restore",
                "settings/system",
                baseline_form,
            )
        )
        after_restore = probe.request(
            "system-settings-after-restore",
            "settings/system",
        )
        captures.append(after_restore)
        if input_value(after_restore.body, FIELD) != baseline_value:
            raise RuntimeError("chat refresh was not restored")
        baseline_form = None
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "system-settings", "error": str(error)})
    finally:
        if probe is not None and baseline_form is not None:
            try:
                captures.append(
                    probe.request(
                        "system-settings-cleanup",
                        "settings/system",
                        baseline_form,
                    )
                )
                cleanup = probe.request(
                    "system-settings-after-cleanup",
                    "settings/system",
                )
                captures.append(cleanup)
                if input_value(cleanup.body, FIELD) != baseline_value:
                    raise RuntimeError("system-settings cleanup mismatch")
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "system-settings-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("system-settings-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "system-settings-logout", "error": str(error)}
                )

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
    """Run a reversible system-settings discovery pass."""
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
