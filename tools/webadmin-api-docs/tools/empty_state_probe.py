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

"""Capture sanitized empty-server WebAdmin read and refresh responses."""

from __future__ import annotations

import json
import os
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

GAME_TYPES = {
    "skirmish": "ROGame.ROGameInfoSkirmish",
    "greenmen-skirmish": "GreenMenMod.GMGameInfoSkirmish",
    "supremacy": "ROGame.ROGameInfoSupremacy",
    "greenmen-supremacy": "GreenMenMod.GMGameInfoSupremacy",
    "territories": "ROGame.ROGameInfoTerritories",
    "greenmen-territories": "GreenMenMod.GMGameInfoTerritories",
}


def run(args: ToolArguments) -> int:
    if not all(
        (
            args.primary_username,
            args.primary_password,
            args.secondary_username,
            args.secondary_password,
        )
    ):
        logger.warning("primary and secondary account credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    try:
        logger.info("capturing empty-server dynamic map and mutator fragments")
        primary = WebAdminProbe(
            args.base_url, args.primary_username, args.primary_password
        )
        login_captures, authenticated = login(
            primary,
            "empty-primary",
            args.primary_username,
            args.primary_password,
            "sha1",
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("primary login was not authenticated")
        for label, game_type in GAME_TYPES.items():
            form = {"ajax": "1", "gametype": game_type}
            captures.append(
                primary.request(f"change-data-{label}", "current/change/data", form)
            )
            captures.append(
                primary.request(
                    f"change-update-{label}",
                    "current/change",
                    {"action": "update", "gametype": game_type},
                )
            )
        captures.extend(
            [
                primary.request(
                    "change-data-empty-gametype", "current/change/data", {"ajax": "1"}
                ),
                primary.request("data-post-gametypes", "data", {"type": "gametypes"}),
                primary.request("current-sort-name", "current?sortby=name&reverse="),
                primary.request(
                    "current-sort-name-reverse", "current?sortby=name&reverse=1"
                ),
                primary.request(
                    "players-sort-ping", "current/players?sortby=ping&reverse="
                ),
            ]
        )

        logger.info("capturing independent empty chat polls")
        secondary = WebAdminProbe(
            args.base_url, args.secondary_username, args.secondary_password
        )
        login_captures, authenticated = login(
            secondary,
            "empty-secondary",
            args.secondary_username,
            args.secondary_password,
            "sha1",
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("secondary login was not authenticated")
        captures.extend(
            [
                primary.request(
                    "chat-primary-poll", "current/chat/data", {"ajax": "1"}
                ),
                secondary.request(
                    "chat-secondary-poll", "current/chat/data", {"ajax": "1"}
                ),
                primary.request("empty-primary-logout", "logout"),
                secondary.request("empty-secondary-logout", "logout"),
            ]
        )
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "empty-state-probe", "error": str(error)})

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
@click.option("--primary-username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--primary-password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
@click.option(
    "--secondary-username", default=os.environ.get("RS2_WEBADMIN_SECONDARY_USERNAME")
)
@click.option(
    "--secondary-password", default=os.environ.get("RS2_WEBADMIN_SECONDARY_PASSWORD")
)
def main(
    base_url: str,
    output: Path,
    primary_username: str | None,
    primary_password: str | None,
    secondary_username: str | None,
    secondary_password: str | None,
) -> None:
    """Capture sanitized empty-server WebAdmin read and refresh responses."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                primary_username=primary_username or "",
                primary_password=primary_password or "",
                secondary_username=secondary_username or "",
                secondary_password=secondary_password or "",
            )
        )
    )


if __name__ == "__main__":
    main()
