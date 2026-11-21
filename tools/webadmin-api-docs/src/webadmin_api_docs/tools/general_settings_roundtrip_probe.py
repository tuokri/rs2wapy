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

"""Capture a reversible RS2 WebAdmin general-settings round trip."""

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
from webadmin_api_docs.tools.probe_webadmin import Capture
from webadmin_api_docs.tools.probe_webadmin import Sanitizer
from webadmin_api_docs.tools.probe_webadmin import WebAdminProbe
from webadmin_api_docs.tools.probe_webadmin import write_capture

INTERVAL_FIELD = "settings_ServerAdvertisementInterval"


def attribute(tag: str, name: str) -> str:
    """Read one HTML attribute without a browser DOM dependency."""
    match = re.search(
        rf'\b{re.escape(name)}=["\']([^"\']*)["\']',
        tag,
        re.IGNORECASE,
    )
    return html.unescape(match.group(1)) if match else ""


def general_settings_form(body: str) -> dict[str, str]:
    """Extract submitted general-settings controls from the live HTML."""
    form: dict[str, str] = {}

    for tag in re.findall(r"<input\b[^>]*>", body, re.IGNORECASE):
        name = attribute(tag, "name")
        if not name:
            continue
        input_type = attribute(tag, "type").lower()
        if input_type in {"radio", "checkbox"}:
            if not re.search(r"\bchecked(?:=|[\s>])", tag, re.IGNORECASE):
                continue
            form[name] = attribute(tag, "value") or "1"
            continue
        if input_type in {"submit", "button", "file"}:
            continue
        form[name] = attribute(tag, "value")

    for tag_match in re.finditer(
        r"<textarea\b([^>]*)>(.*?)</textarea>",
        body,
        re.IGNORECASE | re.DOTALL,
    ):
        name_match = re.search(
            r'\bname=["\']([^"\']+)["\']',
            tag_match.group(1),
            re.IGNORECASE,
        )
        if name_match:
            form[html.unescape(name_match.group(1))] = html.unescape(tag_match.group(2))

    for select_match in re.finditer(
        r"<select\b([^>]*)>(.*?)</select>",
        body,
        re.IGNORECASE | re.DOTALL,
    ):
        name_match = re.search(
            r'\bname=["\']([^"\']+)["\']',
            select_match.group(1),
            re.IGNORECASE,
        )
        if not name_match:
            continue
        name = html.unescape(name_match.group(1))
        selected_match = re.search(
            r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*\bselected(?:=["\'][^"\']*["\'])?',
            select_match.group(2),
            re.IGNORECASE,
        )
        if not selected_match:
            selected_match = re.search(
                r'<option\b[^>]*\bvalue=["\']([^"\']*)["\']',
                select_match.group(2),
                re.IGNORECASE,
            )
        if selected_match:
            form[name] = html.unescape(selected_match.group(1))

    form["action"] = "save"
    if "liveAdjust" not in form:
        form["liveAdjust"] = "1"
    return form


def input_value(body: str, name: str) -> str:
    """Read one live input value for verification."""
    match = re.search(
        rf'<input[^>]*\bname=["\']{re.escape(name)}["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    if not match:
        raise RuntimeError(f"general-settings page did not contain {name}")
    return html.unescape(match.group(1))


def changed_interval(baseline: str) -> str:
    """Choose a nearby reversible integer advertisement interval."""
    try:
        value = int(baseline)
    except ValueError as error:
        raise RuntimeError(
            f"advertisement interval was not an integer: {baseline}"
        ) from error
    if value < 9999:
        return str(value + 1)
    if value > 0:
        return str(value - 1)
    return "1"


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline_form: dict[str, str] | None = None
    baseline_interval = ""

    try:
        logger.info("authenticating for general-settings save and restore")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        baseline = probe.request(
            "general-settings-baseline",
            "settings/general",
        )
        captures.append(baseline)
        baseline_form = general_settings_form(baseline.body)
        baseline_interval = input_value(baseline.body, INTERVAL_FIELD)
        changed_form = baseline_form.copy()
        changed_form[INTERVAL_FIELD] = changed_interval(baseline_interval)

        logger.info(
            "changing advertisement interval from {} to {}",
            baseline_interval,
            changed_form[INTERVAL_FIELD],
        )
        captures.append(
            probe.request(
                "general-settings-change",
                "settings/general",
                changed_form,
            )
        )
        after_change = probe.request(
            "general-settings-after-change",
            "settings/general",
        )
        captures.append(after_change)
        if (
            input_value(after_change.body, INTERVAL_FIELD)
            != changed_form[INTERVAL_FIELD]
        ):
            raise RuntimeError(
                "advertisement interval did not match the submitted value"
            )

        logger.info("restoring the exact general-settings baseline")
        captures.append(
            probe.request(
                "general-settings-restore",
                "settings/general",
                baseline_form,
            )
        )
        after_restore = probe.request(
            "general-settings-after-restore",
            "settings/general",
        )
        captures.append(after_restore)
        if input_value(after_restore.body, INTERVAL_FIELD) != baseline_interval:
            raise RuntimeError("advertisement interval was not restored")
        baseline_form = None
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "general-settings", "error": str(error)})
    finally:
        if probe is not None and baseline_form is not None:
            try:
                captures.append(
                    probe.request(
                        "general-settings-cleanup",
                        "settings/general",
                        baseline_form,
                    )
                )
                cleanup = probe.request(
                    "general-settings-after-cleanup",
                    "settings/general",
                )
                captures.append(cleanup)
                if input_value(cleanup.body, INTERVAL_FIELD) != baseline_interval:
                    raise RuntimeError("general-settings cleanup interval mismatch")
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "general-settings-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("general-settings-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "general-settings-logout", "error": str(error)}
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
    """Run a reversible general-settings discovery pass."""
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
