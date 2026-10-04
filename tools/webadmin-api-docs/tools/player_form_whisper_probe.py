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

"""Capture a harmless direct-form WebAdmin whisper without using the AJAX route."""

from __future__ import annotations

import json
import os
from pathlib import Path

import click
import httpx2
from player_action_probe import player_details
from player_non_disconnect_probe import player_actions
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger

RUN_MARKER = "ww"


def run(args: ToolArguments) -> int:
    """Send one harmless direct-form whisper and verify the target remains connected."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    try:
        logger.info("authenticating for the Current Players whisper form probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("form-whisper-before", "current/players")
        captures.append(before)
        player_key, _ = player_details(before, args.player_name)
        if "whisper" not in player_actions(before, args.player_name):
            raise RuntimeError("whisper action is not available")

        logger.info("sending harmless whisper through POST /current/players")
        captures.append(
            probe.request(
                "form-whisper-action",
                "current/players",
                {"action": "whisper", "playerkey": player_key, "__Input": RUN_MARKER},
            )
        )
        after = probe.request("form-whisper-after", "current/players")
        captures.append(after)
        if args.player_name not in after.body:
            raise RuntimeError("direct-form whisper disconnected the controlled player")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "form-whisper", "error": str(error)})
    finally:
        if probe is not None:
            try:
                captures.append(probe.request("form-whisper-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "form-whisper-logout", "error": str(error)})

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
@click.option("--player-name", required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str,
    output: Path,
    player_name: str,
    username: str | None,
    password: str | None,
) -> None:
    """Capture a harmless direct-form whisper for one controlled player."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                player_name=player_name,
                username=username or "",
                password=password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
