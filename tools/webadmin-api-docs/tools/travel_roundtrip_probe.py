#!/usr/bin/env python3
"""Capture an empty-server map-travel round trip with verified restoration."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
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

MAX_WAIT_SECONDS = 20
POLL_INTERVAL_SECONDS = 1


@dataclass(frozen=True, slots=True)
class ChangeState:
    game_type: str
    map_name: str
    mutator_group_count: str
    mutators: dict[str, str]
    url_extra: str
    maps: tuple[str, ...]

    def form(self, action: str, map_name: str | None = None) -> dict[str, str]:
        return {
            "action": action,
            "gametype": self.game_type,
            "map": map_name if map_name is not None else self.map_name,
            "mutatorGroupCount": self.mutator_group_count,
            "urlextra": self.url_extra,
            **self.mutators,
        }


def selected_value(body: str, select_id: str) -> tuple[str, tuple[str, ...]]:
    select_match = re.search(
        rf'<select[^>]*\bid=["\']{re.escape(select_id)}["\'][^>]*>(.*?)</select>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not select_match:
        raise RuntimeError(f"change page did not contain {select_id} select")
    options = re.findall(
        r'<option[^>]*\bvalue=["\']([^"\']+)["\']([^>]*)>',
        select_match.group(1),
        re.IGNORECASE,
    )
    selected = [
        value for value, attributes in options if "selected" in attributes.lower()
    ]
    if len(selected) != 1:
        raise RuntimeError(
            f"change page did not contain one selected {select_id} value"
        )
    return selected[0], tuple(value for value, _ in options)


def change_state(body: str) -> ChangeState:
    game_type, _ = selected_value(body, "gametype")
    map_name, maps = selected_value(body, "map")
    group_match = re.search(
        r'<input[^>]*\bname=["\']mutatorGroupCount["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    extra_match = re.search(
        r'<input[^>]*\bid=["\']urlextra["\'][^>]*\bvalue=["\']([^"\']*)',
        body,
        re.IGNORECASE,
    )
    if not group_match or not extra_match:
        raise RuntimeError("change page did not contain mutator or URL-extra fields")
    mutators = {
        name: value
        for name, value, attributes in re.findall(
            r'<input[^>]*\bname=["\'](mutgroup\d+)["\'][^>]*\bvalue=["\']([^"\']*)["\']([^>]*)>',
            body,
            re.IGNORECASE,
        )
        if "checked" in attributes.lower()
    }
    return ChangeState(
        game_type, map_name, group_match.group(1), mutators, extra_match.group(1), maps
    )


def has_no_players(body: str) -> bool:
    return bool(re.search(r"<em>There are no players</em>", body, re.IGNORECASE))


def wait_for_ready(probe: WebAdminProbe, captures: list[Capture], label: str) -> None:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    attempt = 0
    while True:
        attempt += 1
        check = probe.request(f"{label}-check-{attempt}", "current/change/check")
        captures.append(check)
        if check.status == 200 and check.body.strip() == "ok":
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"map travel did not become ready within {MAX_WAIT_SECONDS} seconds"
            )
        time.sleep(POLL_INTERVAL_SECONDS)


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline: ChangeState | None = None
    restore_required = False
    try:
        logger.info("authenticating for the empty-server travel round trip")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        # Server travel invalidates the session cookie. A short remembered
        # authentication lets the next request establish a fresh session.
        login_captures, authenticated = login(
            probe, "travel", args.username, args.password, "sha1", remember="1800"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")

        current = probe.request("travel-current-baseline", "current")
        captures.append(current)
        if not has_no_players(current.body):
            raise RuntimeError("refusing map travel because the server is not empty")

        baseline_page = probe.request("travel-change-baseline", "current/change")
        captures.append(baseline_page)
        baseline = change_state(baseline_page.body)
        target = next(
            (map_name for map_name in baseline.maps if map_name != baseline.map_name),
            None,
        )
        if target is None:
            raise RuntimeError("current game type did not expose an alternate map")

        logger.info("travelling to one alternate map")
        captures.append(
            probe.request(
                "travel-to-alternate", "current/change", baseline.form("change", target)
            )
        )
        restore_required = True
        wait_for_ready(probe, captures, "travel-alternate")
        alternate_page = probe.request(
            "travel-change-after-alternate", "current/change"
        )
        captures.append(alternate_page)
        alternate = change_state(alternate_page.body)
        if alternate.game_type != baseline.game_type or alternate.map_name != target:
            raise RuntimeError(
                "alternate travel did not reach the requested game and map"
            )

        logger.info("restoring the baseline game and map")
        captures.append(
            probe.request("travel-restore", "current/change", baseline.form("change"))
        )
        wait_for_ready(probe, captures, "travel-restore")
        restored_page = probe.request("travel-change-after-restore", "current/change")
        captures.append(restored_page)
        restored = change_state(restored_page.body)
        if restored != baseline:
            raise RuntimeError(
                "map travel did not restore the exact baseline selection"
            )
        restore_required = False
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "travel-roundtrip", "error": str(error)})
    finally:
        if probe is not None and baseline is not None and restore_required:
            try:
                logger.info("attempting map-travel cleanup")
                captures.append(
                    probe.request(
                        "travel-cleanup-restore",
                        "current/change",
                        baseline.form("change"),
                    )
                )
                wait_for_ready(probe, captures, "travel-cleanup")
                cleanup_page = probe.request(
                    "travel-change-after-cleanup", "current/change"
                )
                captures.append(cleanup_page)
                if change_state(cleanup_page.body) != baseline:
                    failures.append(
                        {
                            "route": "travel-cleanup",
                            "error": "baseline selection was not restored",
                        }
                    )
            except (
                OSError,
                RuntimeError,
                httpx2.RequestError,
            ) as error:
                failures.append({"route": "travel-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("travel-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "travel-logout", "error": str(error)})

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
    """Capture an empty-server map-travel round trip with verified restoration."""
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
