#!/usr/bin/env python3

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

"""Save and restore the welcome-screen MOTD with form-shape verification."""

from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

import click
import httpx2
from multiadmin_probe import login
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger

RUN_MARKER = "mock-doc-20260926-welcome"
TEXT_FIELDS = (
    "BannerLink",
    "ClanMottoColor",
    "ServerMOTDColor",
    "WebLink",
    "WebLinkColor",
)
TEXTAREA_FIELDS = ("ClanMotto", "ServerMOTD")


def input_value(body: str, name: str) -> str:
    match = re.search(
        rf'<input[^>]*\bname=["\']{re.escape(name)}["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    if not match:
        raise RuntimeError(f"welcome page did not contain {name}")
    return html.unescape(match.group(1))


def textarea_value(body: str, name: str) -> str:
    match = re.search(
        rf'<textarea[^>]*\bname=["\']{re.escape(name)}["\'][^>]*>(.*?)</textarea>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise RuntimeError(f"welcome page did not contain {name}")
    return html.unescape(match.group(1))


def welcome_form(body: str) -> tuple[dict[str, str], bool]:
    form = {name: input_value(body, name) for name in TEXT_FIELDS}
    form.update({name: textarea_value(body, name) for name in TEXTAREA_FIELDS})
    toggle_match = re.search(
        r'<input[^>]*\bname=["\']tglWelcomeScreen["\'][^>]*>', body, re.IGNORECASE
    )
    if not toggle_match:
        raise RuntimeError("welcome page did not contain tglWelcomeScreen")
    enabled = "checked" in toggle_match.group(0).lower()
    # The page's hidden TBVal starts at 0 even when checked; current JavaScript
    # updates it before form submission, and the handler uses TBVal.
    form.update({"TBVal": "1" if enabled else "0", "liveAdjust": "1", "action": "save"})
    if enabled:
        form["tglWelcomeScreen"] = "1"
    return form, enabled


def verify_welcome(body: str, expected: dict[str, str], enabled: bool) -> None:
    observed, observed_enabled = welcome_form(body)
    for name in (*TEXT_FIELDS, *TEXTAREA_FIELDS):
        if observed[name] != expected[name]:
            raise RuntimeError(f"welcome {name} did not match the submitted value")
    if observed_enabled != enabled:
        raise RuntimeError("welcome-screen enabled state changed unexpectedly")


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline_form: dict[str, str] | None = None
    baseline_enabled = False
    try:
        logger.info("authenticating for welcome-settings save and restore")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        login_captures, authenticated = login(
            probe, "welcome", args.username, args.password, "sha1"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")

        baseline = probe.request("welcome-baseline", "settings/general/welcome")
        captures.append(baseline)
        baseline_form, baseline_enabled = welcome_form(baseline.body)
        if RUN_MARKER in baseline_form["ServerMOTD"]:
            raise RuntimeError("welcome marker already exists in the server MOTD")

        logger.info("saving and reading back a welcome MOTD marker")
        changed_form = baseline_form.copy()
        changed_form["ServerMOTD"] = RUN_MARKER
        captures.append(
            probe.request(
                "welcome-save-marker", "settings/general/welcome", changed_form
            )
        )
        after_save = probe.request("welcome-after-save", "settings/general/welcome")
        captures.append(after_save)
        verify_welcome(after_save.body, changed_form, baseline_enabled)

        logger.info("restoring the exact welcome-screen baseline")
        captures.append(
            probe.request("welcome-restore", "settings/general/welcome", baseline_form)
        )
        after_restore = probe.request(
            "welcome-after-restore", "settings/general/welcome"
        )
        captures.append(after_restore)
        verify_welcome(after_restore.body, baseline_form, baseline_enabled)
        baseline_form = None
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "welcome-settings", "error": str(error)})
    finally:
        if probe is not None and baseline_form is not None:
            try:
                captures.append(
                    probe.request(
                        "welcome-cleanup-restore",
                        "settings/general/welcome",
                        baseline_form,
                    )
                )
                cleanup = probe.request(
                    "welcome-after-cleanup", "settings/general/welcome"
                )
                captures.append(cleanup)
                verify_welcome(cleanup.body, baseline_form, baseline_enabled)
            except (
                OSError,
                RuntimeError,
                httpx2.RequestError,
            ) as error:
                failures.append(
                    {"route": "welcome-settings-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("welcome-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "welcome-logout", "error": str(error)})

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
    base_url: str, output: Path, username: str | None, password: str | None
) -> None:
    """Save and restore the welcome-screen MOTD with form-shape verification."""
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
