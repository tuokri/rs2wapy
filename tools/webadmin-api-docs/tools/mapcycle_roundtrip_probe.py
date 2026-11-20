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

"""Capture a reversible RS2 WebAdmin map-cycle round trip."""

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

TEST_MAP_CYCLE = "VNTE-HueCity\nVNTE-CuChi"


@dataclass(frozen=True, slots=True)
class MapCycleBaseline:
    active_index: int
    gametype: str
    mapcycle: str
    cycle_indexes: tuple[int, ...]


def selected_option(body: str, select_id: str) -> str:
    """Return the value of the selected option in a named select."""
    select_match = re.search(
        rf'<select\b[^>]*\bid=["\']{re.escape(select_id)}["\'][^>]*>(.*?)</select>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not select_match:
        return ""
    option_match = re.search(
        r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*selected=["\'][^"\']*["\']',
        select_match.group(1),
        re.IGNORECASE,
    )
    return html.unescape(option_match.group(1).strip()) if option_match else ""


def selected_gametype(body: str) -> str:
    """Return the selected map-list game type."""
    return selected_option(body, "gametype")


def mapcycle_text(body: str) -> str:
    """Extract the live map-cycle textarea and normalize line endings."""
    match = re.search(
        r'<textarea\b[^>]*\bname=["\']mapcycle["\'][^>]*>(.*?)</textarea>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return html.unescape(match.group(1)).replace("\r\n", "\n").replace("\r", "\n").strip()


def mapcycle_options(body: str) -> tuple[int, ...]:
    """Return integer map-cycle indexes exposed by the map-list selector."""
    select_match = re.search(
        r'<select\b[^>]*\bid=["\']maplistidx["\'][^>]*>(.*?)</select>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not select_match:
        return ()
    indexes: list[int] = []
    for value in re.findall(
        r'<option\b[^>]*\bvalue=["\'](-?\d+)["\']',
        select_match.group(1),
        re.IGNORECASE,
    ):
        index = int(value)
        if index >= 0:
            indexes.append(index)
    return tuple(dict.fromkeys(indexes))


def active_mapcycle_index(body: str) -> int | None:
    """Return the selected map-cycle index marked active."""
    select_match = re.search(
        r'<select\b[^>]*\bid=["\']maplistidx["\'][^>]*>(.*?)</select>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not select_match:
        return None
    for match in re.finditer(
        r'<option\b[^>]*\bvalue=["\'](-?\d+)["\'][^>]*>([^<]*?)</option>',
        select_match.group(1),
        re.IGNORECASE | re.DOTALL,
    ):
        label = html.unescape(match.group(2))
        if "(active)" in label.lower():
            return int(match.group(1))
    return None


def baseline_from(body: str) -> MapCycleBaseline:
    """Require an exact, active, editable map-cycle baseline."""
    active_index = active_mapcycle_index(body)
    gametype = selected_gametype(body)
    mapcycle = mapcycle_text(body)
    cycle_indexes = mapcycle_options(body)
    if active_index is None:
        raise RuntimeError("map-cycle baseline did not expose exactly one active cycle")
    if active_index not in cycle_indexes:
        raise RuntimeError("map-cycle active index was absent from the cycle selector")
    if not gametype:
        raise RuntimeError("map-cycle baseline did not expose a selected game type")
    if not mapcycle:
        raise RuntimeError("map-cycle baseline did not expose a non-empty cycle")
    return MapCycleBaseline(
        active_index=active_index,
        gametype=gametype,
        mapcycle=mapcycle,
        cycle_indexes=cycle_indexes,
    )


def contains_mapcycle(body: str, wanted: str) -> bool:
    """Compare rendered cycle text with one normalized value."""
    return mapcycle_text(body) == wanted


def cycle_index_for_test(body: str, baseline: MapCycleBaseline) -> int | None:
    """Identify the disposable cycle by content and a non-baseline index."""
    if not contains_mapcycle(body, TEST_MAP_CYCLE):
        return None
    for index in mapcycle_options(body):
        if index != baseline.active_index:
            return index
    return None


def run(args: ToolArguments) -> int:
    """Save, activate, restore, delete, and read back a disposable map cycle."""
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline: MapCycleBaseline | None = None
    test_index: int | None = None
    mutation_started = False

    try:
        logger.info("authenticating for the map-cycle round-trip probe")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())

        baseline_page = probe.request(
            "mapcycle-baseline",
            "settings/maplist",
        )
        captures.append(baseline_page)
        baseline = baseline_from(baseline_page.body)

        mutation_started = True
        logger.info("creating disposable map cycle")
        create = probe.request(
            "mapcycle-create",
            "settings/maplist",
            {
                "maplistidx": "-1",
                "gametype": baseline.gametype,
                "mapcycle": TEST_MAP_CYCLE,
                "action": "save",
            },
        )
        captures.append(create)

        after_create = probe.request(
            "mapcycle-after-create",
            "settings/maplist",
        )
        captures.append(after_create)
        test_index = cycle_index_for_test(after_create.body, baseline)
        if test_index is None:
            for index in mapcycle_options(after_create.body):
                if index != baseline.active_index:
                    test_page = probe.request(
                        "mapcycle-test-index-read",
                        "settings/maplist",
                        {"maplistidx": str(index)},
                    )
                    captures.append(test_page)
                    if contains_mapcycle(test_page.body, TEST_MAP_CYCLE):
                        test_index = index
                        break
        if test_index is None:
            raise RuntimeError("disposable map cycle was not exposed after save")

        activate = probe.request(
            "mapcycle-activate",
            "settings/maplist",
            {
                "maplistidx": str(test_index),
                "gametype": baseline.gametype,
                "mapcycle": TEST_MAP_CYCLE,
                "activate": "activate",
            },
        )
        captures.append(activate)
        after_activate = probe.request("mapcycle-after-activate", "settings/maplist")
        captures.append(after_activate)
        if active_mapcycle_index(after_activate.body) != test_index:
            raise RuntimeError("disposable map cycle did not become active")

        restore = probe.request(
            "mapcycle-restore-baseline",
            "settings/maplist",
            {
                "maplistidx": str(baseline.active_index),
                "gametype": baseline.gametype,
                "mapcycle": baseline.mapcycle,
                "activate": "activate",
            },
        )
        captures.append(restore)
        after_restore = probe.request("mapcycle-after-restore", "settings/maplist")
        captures.append(after_restore)
        if active_mapcycle_index(after_restore.body) != baseline.active_index:
            raise RuntimeError("baseline map cycle was not restored as active")
        if not contains_mapcycle(after_restore.body, baseline.mapcycle):
            raise RuntimeError("baseline map-cycle text was not restored")

        delete = probe.request(
            "mapcycle-delete-test",
            "settings/maplist",
            {
                "maplistidx": str(test_index),
                "gametype": baseline.gametype,
                "mapcycle": TEST_MAP_CYCLE,
                "delete": "doit",
            },
        )
        captures.append(delete)
        final = probe.request("mapcycle-final", "settings/maplist")
        captures.append(final)
        if active_mapcycle_index(final.body) != baseline.active_index:
            raise RuntimeError("active cycle changed after disposable cycle cleanup")
        if not contains_mapcycle(final.body, baseline.mapcycle):
            raise RuntimeError("baseline cycle text changed after disposable cycle cleanup")
        if TEST_MAP_CYCLE in final.body:
            raise RuntimeError("disposable map cycle remained after cleanup")
        test_index = None
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "settings-mapcycle", "error": str(error)})
    finally:
        if probe is not None and baseline is not None:
            try:
                if mutation_started:
                    cleanup_restore = probe.request(
                        "mapcycle-cleanup-restore",
                        "settings/maplist",
                        {
                            "maplistidx": str(baseline.active_index),
                            "gametype": baseline.gametype,
                            "mapcycle": baseline.mapcycle,
                            "activate": "activate",
                        },
                    )
                    captures.append(cleanup_restore)
                if mutation_started and test_index is not None:
                    cleanup_delete = probe.request(
                        "mapcycle-cleanup-delete",
                        "settings/maplist",
                        {
                            "maplistidx": str(test_index),
                            "gametype": baseline.gametype,
                            "mapcycle": TEST_MAP_CYCLE,
                            "delete": "doit",
                        },
                    )
                    captures.append(cleanup_delete)
                if mutation_started:
                    cleanup_final = probe.request(
                        "mapcycle-cleanup-final",
                        "settings/maplist",
                    )
                    captures.append(cleanup_final)
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append({"route": "settings-mapcycle-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("mapcycle-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "settings-mapcycle-logout", "error": str(error)})

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
    """Run a reversible live map-cycle discovery pass."""
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
