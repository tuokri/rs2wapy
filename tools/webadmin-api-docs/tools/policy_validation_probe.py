#!/usr/bin/env python3
"""Probe safe IP-policy validation and update paths with verified cleanup."""

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
from probe_webadmin import info
from probe_webadmin import task
from probe_webadmin import warn
from probe_webadmin import write_capture

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status

TEST_NET_MASK = "192.0.2.240"


def policy_rows(body: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for row in re.findall(r"<tr>(.*?)</tr>", body, re.IGNORECASE | re.DOTALL):
        mask_match = re.search(
            r'name=["\']ipmask["\']\s+value=["\']([^"\']*)', row, re.IGNORECASE
        )
        index_match = re.search(
            r'name=["\']update["\']\s+value=["\'](\d+)', row, re.IGNORECASE
        )
        selected_match = re.search(
            r'<option\s+value=["\']([^"\']+)["\'][^>]*\bselected', row, re.IGNORECASE
        )
        if mask_match and index_match:
            rows.append(
                (
                    index_match.group(1),
                    mask_match.group(1),
                    selected_match.group(1) if selected_match else "",
                )
            )
    return rows


def target_rows(body: str) -> list[tuple[str, str, str]]:
    return [row for row in policy_rows(body) if row[1] == TEST_NET_MASK]


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        warn("Administrator credentials are required")
        return 2

    captures: list[Capture] = []
    failures: list[dict[str, str]] = []
    probe: WebAdminProbe | None = None
    baseline_count = 0
    target_created = False
    try:
        task("Authenticating for safe policy validation probes")
        probe = WebAdminProbe(args.base_url, args.username, args.password)
        login_captures, authenticated = login(
            probe, "policy-validation", args.username, args.password, "sha1"
        )
        captures.extend(login_captures)
        if not authenticated:
            raise RuntimeError("administrator login was not authenticated")

        baseline = probe.request("policy-validation-baseline", "policy")
        captures.append(baseline)
        baseline_count = len(policy_rows(baseline.body))
        if target_rows(baseline.body):
            raise RuntimeError("reserved documentation policy already exists")

        task("Submitting policy validation boundaries")
        invalid_mask = probe.request(
            "policy-invalid-mask",
            "policy",
            {"action": "add", "ipmask": "300.0.0.1", "policy": "ALLOW"},
        )
        captures.append(invalid_mask)
        if (
            target_rows(invalid_mask.body)
            or len(policy_rows(invalid_mask.body)) != baseline_count
        ):
            raise RuntimeError("invalid mask unexpectedly changed policy state")
        missing_policy = probe.request(
            "policy-missing-policy",
            "policy",
            {"action": "add", "ipmask": TEST_NET_MASK},
        )
        captures.append(missing_policy)
        if (
            target_rows(missing_policy.body)
            or len(policy_rows(missing_policy.body)) != baseline_count
        ):
            raise RuntimeError("missing policy unexpectedly changed policy state")

        task("Adding, updating, and deleting reserved documentation policies")
        captures.append(
            probe.request(
                "policy-validation-add",
                "policy",
                {"action": "add", "ipmask": TEST_NET_MASK, "policy": "ALLOW"},
            )
        )
        target_created = True
        after_add = probe.request("policy-validation-after-add", "policy")
        captures.append(after_add)
        added_rows = target_rows(after_add.body)
        if len(added_rows) != 1:
            raise RuntimeError("reserved policy add did not create exactly one row")

        captures.append(
            probe.request(
                "policy-validation-duplicate-add",
                "policy",
                {"action": "add", "ipmask": TEST_NET_MASK, "policy": "ALLOW"},
            )
        )
        after_duplicate = probe.request("policy-validation-after-duplicate", "policy")
        captures.append(after_duplicate)
        duplicate_rows = target_rows(after_duplicate.body)
        if len(duplicate_rows) != 2:
            raise RuntimeError("duplicate policy add did not create two rows")

        update_index = duplicate_rows[0][0]
        captures.append(
            probe.request(
                "policy-validation-update",
                "policy",
                {
                    "action": "modify",
                    "update": update_index,
                    "ipmask": TEST_NET_MASK,
                    "policy": "DENY",
                },
            )
        )
        after_update = probe.request("policy-validation-after-update", "policy")
        captures.append(after_update)
        updated_rows = target_rows(after_update.body)
        if len(updated_rows) != 2 or "DENY" not in {row[2] for row in updated_rows}:
            raise RuntimeError("policy update did not preserve rows and select DENY")

        delete_round = 0
        while True:
            delete_round += 1
            current = probe.request(
                f"policy-validation-before-delete-{delete_round}", "policy"
            )
            captures.append(current)
            rows = target_rows(current.body)
            if not rows:
                break
            captures.append(
                probe.request(
                    f"policy-validation-delete-{len(rows)}",
                    "policy",
                    {
                        "action": "modify",
                        "delete": rows[-1][0],
                        "ipmask": TEST_NET_MASK,
                        "policy": "ALLOW",
                    },
                )
            )
        restored = probe.request("policy-validation-after-delete", "policy")
        captures.append(restored)
        if (
            target_rows(restored.body)
            or len(policy_rows(restored.body)) != baseline_count
        ):
            raise RuntimeError("policy cleanup did not restore the baseline count")
        target_created = False
    except (
        OSError,
        RuntimeError,
        httpx2.RequestError,
    ) as error:
        failures.append({"route": "policy-validation", "error": str(error)})
    finally:
        if probe is not None and target_created:
            try:
                while True:
                    current = probe.request("policy-validation-cleanup-read", "policy")
                    captures.append(current)
                    rows = target_rows(current.body)
                    if not rows:
                        break
                    captures.append(
                        probe.request(
                            "policy-validation-cleanup-delete",
                            "policy",
                            {
                                "action": "modify",
                                "delete": rows[-1][0],
                                "ipmask": TEST_NET_MASK,
                                "policy": "ALLOW",
                            },
                        )
                    )
                final = probe.request("policy-validation-cleanup-final", "policy")
                captures.append(final)
                if (
                    target_rows(final.body)
                    or len(policy_rows(final.body)) != baseline_count
                ):
                    failures.append(
                        {
                            "route": "policy-validation-cleanup",
                            "error": "policy baseline was not restored",
                        }
                    )
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "policy-validation-cleanup", "error": str(error)}
                )
        if probe is not None:
            try:
                captures.append(probe.request("policy-validation-logout", "logout"))
            except (OSError, httpx2.RequestError) as error:
                failures.append(
                    {"route": "policy-validation-logout", "error": str(error)}
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
            warn(f"{failure['route']}: {failure['error']}")
        return 1
    info(f"Wrote {len(entries)} sanitized captures to {args.output}")
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option("--base-url", required=True)
@click.option("--output", type=click.Path(path_type=Path), required=True)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
def main(
    base_url: str, output: Path, username: str | None, password: str | None
) -> None:
    """Probe safe IP-policy validation and update paths with verified cleanup."""
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
