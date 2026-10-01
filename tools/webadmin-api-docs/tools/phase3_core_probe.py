#!/usr/bin/env python3
"""Run reversible no-player WebAdmin state probes with verified cleanup."""

from __future__ import annotations

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

SYNTHETIC_UNIQUE_ID = "0xDEADBEEF"
RUN_MARKER = "mock-doc-20260926-phase3"


def ban_ids(body: str) -> set[str]:
    return set(
        re.findall(
            r'name=["\']__UniqueId_\d+["\'][^>]*\bvalue=["\']([^"\']+)',
            body,
            re.IGNORECASE,
        )
    )


def notes_value(body: str) -> str:
    match = re.search(
        r'<textarea[^>]*\bid=["\']notes["\'][^>]*>(.*?)</textarea>',
        body,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        raise RuntimeError("current page did not contain the notes field")
    return match.group(1)


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning("administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline_notes: str | None = None
    created_ban_id: str | None = None
    baseline_ban_ids: set[str] = set()
    try:
        logger.info("authenticating for reversible phase-three probes")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        login_captures, authenticated = login(
            probe, "phase3-core", args.username, args.password, "sha1"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")

        current = probe.request("phase3-notes-baseline", "current")
        captures.append(current)
        baseline_notes = notes_value(current.body)
        if RUN_MARKER in baseline_notes:
            raise RuntimeError("run marker already exists in server notes")

        logger.info("saving and restoring server notes")
        captures.append(
            probe.request(
                "phase3-notes-save",
                "current/data",
                {"ajax": "1", "action": "save", "notes": RUN_MARKER},
            )
        )
        notes_after_save = probe.request("phase3-notes-after-save", "current")
        captures.append(notes_after_save)
        if notes_value(notes_after_save.body).rstrip("\r\n") != RUN_MARKER:
            raise RuntimeError("server notes did not contain the submitted marker")
        captures.append(
            probe.request(
                "phase3-notes-restore",
                "current/data",
                {"ajax": "1", "action": "save", "notes": baseline_notes},
            )
        )
        notes_after_restore = probe.request("phase3-notes-after-restore", "current")
        captures.append(notes_after_restore)
        if notes_value(notes_after_restore.body) != baseline_notes:
            raise RuntimeError("server notes were not restored")
        baseline_notes = None

        logger.info("submitting harmless console commands")
        captures.extend(
            [
                probe.request("phase3-console-baseline", "console"),
                probe.request("phase3-console-help", "console", {"command": "help"}),
                probe.request(
                    "phase3-console-status", "console", {"command": "status"}
                ),
            ]
        )

        logger.info("adding and revoking a synthetic ID ban")
        bans_before = probe.request("phase3-bans-baseline", "policy/bans")
        captures.append(bans_before)
        baseline_ban_ids = ban_ids(bans_before.body)
        captures.append(
            probe.request(
                "phase3-ban-add",
                "policy/bans",
                {
                    "action": "add",
                    "__IdType": "0",
                    "__UniqueId": SYNTHETIC_UNIQUE_ID,
                    "__Reason": RUN_MARKER,
                    "__ExpNumber": "1",
                    "__ExpUnit": "Hour",
                },
            )
        )
        bans_after_add = probe.request("phase3-bans-after-add", "policy/bans")
        captures.append(bans_after_add)
        new_ban_ids = ban_ids(bans_after_add.body) - baseline_ban_ids
        if len(new_ban_ids) != 1:
            raise RuntimeError(
                "synthetic ID ban did not create exactly one new ban row"
            )
        created_ban_id = new_ban_ids.pop()
        captures.append(
            probe.request(
                "phase3-ban-revoke",
                "policy/bans",
                {"action": "revoke", "uniqueid": created_ban_id},
            )
        )
        bans_after_revoke = probe.request("phase3-bans-after-revoke", "policy/bans")
        captures.append(bans_after_revoke)
        if ban_ids(bans_after_revoke.body) != baseline_ban_ids:
            raise RuntimeError("synthetic ID ban was not restored")
        created_ban_id = None
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "phase3-core", "error": str(error)})
    finally:
        if probe is not None and created_ban_id is not None:
            try:
                captures.append(
                    probe.request(
                        "phase3-ban-cleanup",
                        "policy/bans",
                        {"action": "revoke", "uniqueid": created_ban_id},
                    )
                )
                verify_bans = probe.request("phase3-bans-after-cleanup", "policy/bans")
                captures.append(verify_bans)
                if ban_ids(verify_bans.body) != baseline_ban_ids:
                    failures.append(
                        {
                            "route": "phase3-ban-cleanup",
                            "error": "ban state differs from baseline",
                        }
                    )
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "phase3-ban-cleanup", "error": str(error)})
        if probe is not None and baseline_notes is not None:
            try:
                captures.append(
                    probe.request(
                        "phase3-notes-cleanup",
                        "current/data",
                        {"ajax": "1", "action": "save", "notes": baseline_notes},
                    )
                )
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "phase3-notes-cleanup", "error": str(error)})
        if probe is not None:
            try:
                captures.append(probe.request("phase3-core-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append({"route": "phase3-core-logout", "error": str(error)})

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
    """Run reversible no-player WebAdmin state probes with verified cleanup."""
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
