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

"""Capture a reversible RS2 WebAdmin gameplay-settings round trip."""

from __future__ import annotations

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
from webadmin_api_docs.tools.general_settings_roundtrip_probe import (
    general_settings_form,
)
from webadmin_api_docs.tools.general_settings_roundtrip_probe import input_value
from webadmin_api_docs.tools.probe_webadmin import Capture
from webadmin_api_docs.tools.probe_webadmin import Sanitizer
from webadmin_api_docs.tools.probe_webadmin import WebAdminProbe
from webadmin_api_docs.tools.probe_webadmin import write_capture

FIELD = "settings_FriendlyFireArtilleryPunishScale"
MIN_REMAINING_SECONDS = 60


def remaining_seconds(body: str) -> int | None:
    """Read the remaining match seconds from the Current page."""
    match = re.search(
        r"<dt>Time Limit</dt>\s*<dd>[^<]+<br\s*/>(\d+) seconds remaining",
        body,
        re.IGNORECASE,
    )
    return int(match.group(1)) if match else None


def changed_value(baseline: str) -> str:
    """Move the decimal field one step while remaining in range."""
    try:
        value = float(baseline)
    except ValueError as error:
        raise RuntimeError(f"gameplay setting was not numeric: {baseline}") from error
    changed = value + 0.1
    if changed > 10:
        changed = value - 0.1
    if changed < 0:
        raise RuntimeError("gameplay setting cannot be changed safely")
    return f"{changed:.4f}"


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
        logger.info("authenticating for gameplay-settings save and restore")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        timer = probe.request(
            "gameplay-settings-match-timer",
            "current",
        )
        captures.append(timer)
        seconds = remaining_seconds(timer.body)
        if seconds is None:
            raise RuntimeError("match timer was unavailable in the Current page")
        if seconds < MIN_REMAINING_SECONDS:
            raise RuntimeError(
                f"refusing gameplay write with {seconds} seconds left; "
                f"minimum safety window is {MIN_REMAINING_SECONDS}"
            )

        baseline = probe.request(
            "gameplay-settings-baseline",
            "settings/general/gameplay",
        )
        captures.append(baseline)
        baseline_form = general_settings_form(baseline.body)
        baseline_value = input_value(baseline.body, FIELD)
        changed_form = baseline_form.copy()
        changed_form[FIELD] = changed_value(baseline_value)

        logger.info(
            "changing {} from {} to {}",
            FIELD,
            baseline_value,
            changed_form[FIELD],
        )
        captures.append(
            probe.request(
                "gameplay-settings-change",
                "settings/general/gameplay",
                changed_form,
            )
        )
        after_change = probe.request(
            "gameplay-settings-after-change",
            "settings/general/gameplay",
        )
        captures.append(after_change)
        if input_value(after_change.body, FIELD) != changed_form[FIELD]:
            raise RuntimeError("gameplay setting did not match the submitted value")

        logger.info("restoring the exact gameplay-settings baseline")
        captures.append(
            probe.request(
                "gameplay-settings-restore",
                "settings/general/gameplay",
                baseline_form,
            )
        )
        after_restore = probe.request(
            "gameplay-settings-after-restore",
            "settings/general/gameplay",
        )
        captures.append(after_restore)
        if input_value(after_restore.body, FIELD) != baseline_value:
            raise RuntimeError("gameplay setting was not restored")
        baseline_form = None
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "gameplay-settings", "error": str(error)})
    finally:
        if probe is not None and baseline_form is not None:
            try:
                captures.append(
                    probe.request(
                        "gameplay-settings-cleanup",
                        "settings/general/gameplay",
                        baseline_form,
                    )
                )
                cleanup = probe.request(
                    "gameplay-settings-after-cleanup",
                    "settings/general/gameplay",
                )
                captures.append(cleanup)
                if input_value(cleanup.body, FIELD) != baseline_value:
                    raise RuntimeError("gameplay-settings cleanup mismatch")
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "gameplay-settings-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("gameplay-settings-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "gameplay-settings-logout", "error": str(error)}
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
    """Run a reversible gameplay-settings discovery pass."""
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
