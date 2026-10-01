#!/usr/bin/env python3
"""Capture a direct-form player team swap and restore the original team."""

from __future__ import annotations

import html
import json
import os
import re
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


def player_team(page: Capture, player_name: str) -> str:
    """Return the team cell rendered in the player's current-table row."""
    for row in re.findall(r"<tr[^>]*>(.*?)</tr>", page.body, re.IGNORECASE | re.DOTALL):
        if not re.search(
            rf'name=["\']__PlayerName_\d+["\'][^>]*value=["\']{re.escape(player_name)}["\']',
            row,
            re.IGNORECASE,
        ):
            continue
        cell_match = re.search(r"<td[^>]*>(.*?)</td>", row, re.IGNORECASE | re.DOTALL)
        if not cell_match:
            break
        return html.unescape(re.sub(r"<[^>]+>", "", cell_match.group(1))).strip()
    raise RuntimeError("controlled player did not have a readable team row")


def run(args: ToolArguments) -> int:
    """Swap the controlled player's team through the form endpoint and restore it."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    player_key = ""
    baseline_team = ""
    swap_succeeded = False

    try:
        logger.info("authenticating for the Current Players team-swap form probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        before = probe.request("form-swapteam-before", "current/players")
        captures.append(before)
        player_key, _ = player_details(before, args.player_name)
        baseline_team = player_team(before, args.player_name)
        if "swapteam" not in player_actions(before, args.player_name):
            raise RuntimeError("team-swap action is not available")

        logger.info("submitting swapteam through POST /current/players")
        captures.append(
            probe.request(
                "form-swapteam-action",
                "current/players",
                {"action": "swapteam", "playerkey": player_key},
            )
        )
        after_swap = probe.request("form-swapteam-after-action", "current/players")
        captures.append(after_swap)
        if args.player_name not in after_swap.body:
            raise RuntimeError(
                "team-swap form action disconnected the controlled player"
            )
        if player_team(after_swap, args.player_name) != baseline_team:
            swap_succeeded = True
            logger.info("form action changed the rendered player team")
        else:
            logger.info("form action did not change the rendered player team")
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "form-swapteam", "error": str(error)})
    finally:
        if probe is not None and player_key and swap_succeeded:
            try:
                logger.info("restoring the original team through POST /current/players")
                captures.append(
                    probe.request(
                        "form-swapteam-restore",
                        "current/players",
                        {"action": "swapteam", "playerkey": player_key},
                    )
                )
                final = probe.request("form-swapteam-final", "current/players")
                captures.append(final)
                if (
                    args.player_name not in final.body
                    or player_team(final, args.player_name) != baseline_team
                ):
                    failures.append(
                        {
                            "route": "current/players",
                            "error": "team baseline was not restored",
                        }
                    )
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append({"route": "form-swapteam-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("form-swapteam-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "form-swapteam-logout", "error": str(error)})

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
    """Capture a direct-form player team swap and restore the original team."""
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
