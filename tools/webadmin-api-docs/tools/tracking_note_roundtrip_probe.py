#!/usr/bin/env python3
"""Capture and restore one disposable note on an existing tracking record."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import click
import httpx2
from player_action_probe import player_details
from probe_webadmin import Capture
from probe_webadmin import Sanitizer
from probe_webadmin import WebAdminProbe
from probe_webadmin import info
from probe_webadmin import task
from probe_webadmin import warn
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status

RUN_MARKER = "mock-doc-20260930-note"


def note_count(details: Capture) -> int:
    """Read the note-count literal rendered for a tracking detail dialog."""
    match = re.search(r"var vNrOfNotes = (\d+);", details.body)
    if not match:
        raise RuntimeError("tracking details did not expose a note count")
    return int(match.group(1))


def marker_note_id(details: Capture) -> str:
    """Return the generated note ID only when the disposable marker is present."""
    match = re.search(
        rf"{re.escape(RUN_MARKER)}.*?id=\"__DeleteNote_([^\"]+)\"",
        details.body,
        re.DOTALL,
    )
    if not match:
        raise RuntimeError("tracking details did not expose the disposable note ID")
    return match.group(1)


def details_capture(probe: WebAdminProbe, name: str, unique_id: str) -> Capture:
    return probe.request(
        name,
        "policy/tracking",
        {"action": "showdetails", "uniqueid": unique_id},
    )


def run(args: ToolArguments) -> int:
    """Attach a disposable note and restore the tracking-record note baseline."""
    if not args.username or not args.password:
        warn("Administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    unique_id = ""
    note_submitted = False
    note_id = ""

    try:
        task("Authenticating for the tracking note round trip")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        captures.extend(probe.login())
        players = probe.request("tracking-note-before-players", "current/players")
        captures.append(players)
        _, unique_id = player_details(players, args.player_name)
        baseline_details = details_capture(
            probe, "tracking-note-baseline-details", unique_id
        )
        captures.append(baseline_details)
        if note_count(baseline_details) != 0:
            raise RuntimeError(
                "tracking record already has notes; refusing to change baseline"
            )

        task("Attaching one disposable tracking note")
        note_submitted = True
        captures.append(
            probe.request(
                "tracking-note-attach",
                "policy/tracking",
                {"action": "attachnote", "uniqueid": unique_id, "__Text": RUN_MARKER},
            )
        )
        after_attach = details_capture(probe, "tracking-note-after-attach", unique_id)
        captures.append(after_attach)
        if note_count(after_attach) != 1:
            raise RuntimeError("tracking note did not produce exactly one note")
        note_id = marker_note_id(after_attach)
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        failures.append({"route": "tracking-note", "error": str(error)})
    finally:
        if probe is not None and note_submitted and unique_id:
            try:
                if not note_id:
                    recovery_details = details_capture(
                        probe, "tracking-note-recovery-details", unique_id
                    )
                    captures.append(recovery_details)
                    note_id = marker_note_id(recovery_details)
                task("Removing the disposable tracking note")
                captures.append(
                    probe.request(
                        "tracking-note-delete",
                        "policy/tracking",
                        {
                            "action": "deletenote",
                            "uniqueid": unique_id,
                            "noteid": note_id,
                            "details": "1",
                        },
                    )
                )
                final_details = details_capture(
                    probe, "tracking-note-final-details", unique_id
                )
                captures.append(final_details)
                if RUN_MARKER in final_details.body or note_count(final_details) != 0:
                    failures.append(
                        {
                            "route": "policy/tracking",
                            "error": "tracking note baseline was not restored",
                        }
                    )
            except (OSError, RuntimeError, httpx2.RequestError) as error:
                failures.append({"route": "tracking-note-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("tracking-note-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "tracking-note-logout", "error": str(error)})

    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(args.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    if failures:
        for failure in failures:
            warn(f"{failure['route']}: {failure['error']}")
        return 1
    info(f"Wrote {len(entries)} sanitized captures to {args.output}")
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
    """Capture and restore one disposable note on an existing tracking record."""
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
