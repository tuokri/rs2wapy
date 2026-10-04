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

"""Capture the irreversible WebAdmin squad-name reset with human restoration."""

from __future__ import annotations

import html
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import click
import httpx2
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger


@dataclass(frozen=True, slots=True)
class Squad:
    """A rendered squad row accepted by the reset form."""

    number: str
    name: str
    team: str


def first_squad(page: Capture) -> Squad:
    """Extract the first rendered squad action form from a squads page."""
    match = re.search(
        r'name=["\']squadnumber["\']\s+value=["\']([^"\']+).*?'
        r'name=["\']squadname["\']\s+value=["\']([^"\']*).*?'
        r'name=["\']squadteam["\']\s+value=["\']([^"\']+)',
        page.body,
        re.IGNORECASE | re.DOTALL,
    )
    if match is None:
        raise RuntimeError("no rendered squad reset form was found")
    return Squad(
        number=html.unescape(match.group(1)),
        name=html.unescape(match.group(2)),
        team=html.unescape(match.group(3)),
    )


def run(args: ToolArguments) -> int:
    """Reset one human-approved squad name and capture the changed state."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    try:
        logger.info("authenticating for the squad-name reset probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("squad-reset-before", "current/squads")
        captures.append(before)
        squad = first_squad(before)
        if not squad.name:
            raise RuntimeError("refusing to reset an already empty squad name")

        logger.info("submitting the human-approved squad-name reset")
        captures.append(
            probe.request(
                "squad-reset-action",
                "current/squads",
                {
                    "action": "resetsquadname",
                    "squadnumber": squad.number,
                    "squadname": squad.name,
                    "squadteam": squad.team,
                },
            )
        )
        after = probe.request("squad-reset-after", "current/squads")
        captures.append(after)
        reset_squad = first_squad(after)
        if reset_squad.name == squad.name:
            raise RuntimeError("squad name was unchanged after reset")
        captures.append(probe.request("squad-reset-logout", "logout"))
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "squad-reset", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("squad-reset-logout", "logout"))
            except (OSError, httpx2.RequestError) as logout_error:
                failures.append(
                    {"route": "squad-reset-logout", "error": str(logout_error)}
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
    """Capture one explicitly authorized squad-name reset."""
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
