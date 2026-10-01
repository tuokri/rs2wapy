#!/usr/bin/env python3
"""Capture sanitized RS2 WebAdmin API evidence with httpx2."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import httpx2

from webadmin_api_docs.cli import CLICK_CONTEXT_SETTINGS
from webadmin_api_docs.cli import ToolArguments
from webadmin_api_docs.cli import exit_with_status
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.logging import logger

ROUTE_SEEDS = (
    "",
    "about",
    "data",
    "current",
    "current/data",
    "current/players",
    "current/players/data",
    "current/squads",
    "current/chat",
    "current/chat/data",
    "current/change",
    "current/change/data",
    "current/change/check",
    "current/workshoptool",
    "console",
    "policy",
    "policy/bans",
    "policy/hashbans",
    "policy/session",
    "policy/tracking",
    "policy/members",
    "settings",
    "settings/general",
    "settings/general/passwords",
    "settings/general/gameplay",
    "settings/general/welcome",
    "settings/gametypes",
    "settings/mutators",
    "settings/maplist",
    "settings/serveractors",
    "settings/system",
    "settings/campaign",
    "multiadmin",
)

SAFE_FORM_READS = {
    "current/data": {"ajax": "1"},
}

SENSITIVE_HEADERS = {"cookie", "authorization"}
VOLATILE_PATTERNS = (
    (re.compile(r'(sessionid=)"?[A-F0-9]{16,}"?', re.IGNORECASE), r"\1{{SESSION_ID}}"),
    (re.compile(r'(authcred=)"?[^;\"\s]+"?', re.IGNORECASE), r"\1{{AUTH_CRED}}"),
    (
        re.compile(r"(name=[\"']token[\"']\s+value=[\"'])[^\"']+", re.IGNORECASE),
        r"\1{{AUTH_FORM_TOKEN}}",
    ),
    (
        re.compile(
            r"(name=[\"']password_hash[\"']\s+value=[\"'])[^\"']*", re.IGNORECASE
        ),
        r"\1{{PASSWORD_HASH}}",
    ),
    (
        re.compile(r"(<span\s+class=[\"']username[\"']>)[^<]*", re.IGNORECASE),
        r"\1{{ADMIN_NAME}}",
    ),
    (
        re.compile(
            r"(name=[\"'](?:playerid|playerkey|uniqueid|__UniqueId_[^\"']+)[\"'][^>]*value=[\"'])[^\"']*",
            re.IGNORECASE,
        ),
        r"\1{{PLAYER_IDENTIFIER}}",
    ),
)


@dataclass(frozen=True, slots=True)
class Capture:
    name: str
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: str
    form: dict[str, str] | None = None


class WebAdminProbe:
    def __init__(self, base_url: str, username: str, password: str) -> None:
        normalized = base_url.rstrip("/") + "/"
        parsed = httpx2.URL(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.host:
            raise ValueError("base URL must include an HTTP(S) scheme and host")
        self.base_url = normalized
        self.username = username
        self.password = password
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.7",
            "User-Agent": "rs2-webadmin-doc-probe/1.0",
        }
        self.client = httpx2.Client(
            headers=self.headers,
            timeout=20,
            follow_redirects=True,
        )

    def url_for(self, route: str) -> str:
        return str(httpx2.URL(self.base_url).join(route.lstrip("/")))

    def request(
        self,
        name: str,
        route: str,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> Capture:
        url = self.url_for(route)
        method = "GET"
        if form is not None:
            method = "POST"
        response = self.client.request(
            method,
            url,
            data=form,
            headers=headers,
        )
        return Capture(
            name=name,
            method=method,
            url=str(response.url),
            status=response.status_code,
            headers=response_headers(response.headers),
            body=response.content.decode(
                self.encoding_from(response.headers.get("content-type")), "replace"
            ),
            form=form,
        )

    @staticmethod
    def encoding_from(content_type: str | None) -> str:
        if content_type:
            match = re.search(r"charset=([^; ]+)", content_type, re.IGNORECASE)
            if match:
                return match.group(1)
        return "utf-8"

    def login(self) -> list[Capture]:
        landing = self.request("login-page", "")
        token_match = re.search(
            r'<input[^>]+name=["\']token["\'][^>]+value=["\']([^"\']+)',
            landing.body,
            re.IGNORECASE,
        )
        if not token_match:
            raise RuntimeError("login page did not contain an authentication token")
        algorithm_match = re.search(r'var\s+hashAlg\s*=\s*"([^"]*)"', landing.body)
        algorithm = algorithm_match.group(1).lower() if algorithm_match else ""
        if algorithm == "sha1":
            digest = hashlib.sha1(
                (self.password + self.username).encode("utf-8")
            ).hexdigest()
            password_hash = f"$sha1${digest}"
            password = ""
        elif not algorithm:
            password_hash = ""
            password = self.password
        else:
            raise RuntimeError(
                f"unsupported advertised password hash algorithm: {algorithm}"
            )
        login = self.request(
            "login-submit",
            "",
            {
                "username": self.username,
                "password": password,
                "password_hash": password_hash,
                "token": token_match.group(1),
            },
        )
        title_match = re.search(
            r"<title>(.*?)</title>", login.body, re.IGNORECASE | re.DOTALL
        )
        title = (
            re.sub(r"\s+", " ", title_match.group(1)).strip()
            if title_match
            else "(missing)"
        )
        if "Login" in title:
            raise RuntimeError(f"login did not produce an authenticated page: {title}")
        return [landing, login]

    def discover_routes(self, page: str) -> list[str]:
        routes = set(ROUTE_SEEDS)
        base = httpx2.URL(self.base_url)
        for href in re.findall(r'href=["\']([^"\']+)', page, re.IGNORECASE):
            absolute = base.join(html.unescape(href))
            if (
                absolute.scheme == base.scheme
                and absolute.host == base.host
                and absolute.port == base.port
            ):
                relative = absolute.path.removeprefix(base.path).strip("/")
                if relative and not relative.startswith("images/"):
                    routes.add(relative)
        routes.discard("logout")
        return sorted(routes)

    def send_chat_probe(self, marker: str) -> list[Capture]:
        form = {"ajax": "1", "message": marker, "teamsay": "-1"}
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.url_for("current/chat"),
        }
        return [
            self.request("chat-post", "current/chat", form, headers),
            self.request("chat-data-after-post", "current/chat/data", form, headers),
        ]

    def run_policy_roundtrip(self, ip_mask: str) -> list[Capture]:
        """Add and remove a documentation-only policy entry in one session."""
        added = self.request(
            "policy-add",
            "policy",
            {"action": "add", "ipmask": ip_mask, "policy": "ALLOW"},
        )
        row_match = re.search(
            rf'<tr>.*?name=["\']ipmask["\']\s+value=["\']{re.escape(ip_mask)}["\'].*?name=["\']delete["\']\s+value=["\'](\d+)["\']',
            added.body,
            re.IGNORECASE | re.DOTALL,
        )
        if not row_match:
            raise RuntimeError("policy add did not expose a removable policy row")
        deleted = self.request(
            "policy-delete",
            "policy",
            {
                "action": "modify",
                "delete": row_match.group(1),
                "ipmask": ip_mask,
                "policy": "ALLOW",
            },
        )
        restored = self.request("policy-after-delete", "policy")
        if ip_mask in restored.body:
            raise RuntimeError("policy delete did not restore the policy list")
        return [added, deleted, restored]


class Sanitizer:
    """Replace live identifiers with stable aliases for one capture run."""

    input_value_pattern = re.compile(
        r"(?P<prefix><input\b[^>]*\bname=(?P<quote>[\"'])(?P<name>[^\"']+)(?P=quote)[^>]*\bvalue=(?P<value_quote>[\"']))(?P<value>[^\"']*)(?P<suffix>(?P=value_quote))",
        re.IGNORECASE,
    )
    ipv4_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    unique_id_pattern = re.compile(r"\b(?:0x[0-9a-f]{8,}|\d{15,20})\b", re.IGNORECASE)
    player_table_pattern = re.compile(
        r'(<table\b[^>]*\bid=["\']players["\'][^>]*>)(.*?</table>)',
        re.IGNORECASE | re.DOTALL,
    )
    player_row_name_pattern = re.compile(
        r"(<tr\b[^>]*>\s*<td\b[^>]*>.*?</td>\s*<td\b[^>]*>)([^<]*?)(</td>)",
        re.IGNORECASE | re.DOTALL,
    )
    player_key_attribute_pattern = re.compile(
        r'(\bplayerkey=["\'])([^"\']+)', re.IGNORECASE
    )
    admin_select_pattern = re.compile(
        r'<select\b[^>]*\bid=["\']adminidlist["\'][^>]*>(.*?)</select>',
        re.IGNORECASE | re.DOTALL,
    )
    admin_option_pattern = re.compile(
        r'<option\b[^>]*\bvalue=["\']([^"\']*)["\'][^>]*>',
        re.IGNORECASE,
    )

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.aliases: dict[str, dict[str, str]] = {}

    def alias(self, category: str, value: str) -> str:
        if not value:
            return value
        aliases = self.aliases.setdefault(category, {})
        if value not in aliases:
            aliases[value] = f"{{{{{category}_{len(aliases) + 1}}}}}"
        return aliases[value]

    @staticmethod
    def category_for_field(name: str) -> str | None:
        field = name.lower()
        if field in {
            "username",
            "password",
            "password_hash",
            "token",
            "adminpw1",
            "adminpw2",
            "gamepw1",
            "gamepw2",
        }:
            return "REDACTED"
        if field in {"adminid", "newadminid"}:
            return "ADMIN"
        if field == "displayname":
            return "ADMIN_DISPLAY"
        if "playername" in field or field in {"playername", "membername"}:
            return "PLAYER"
        if "playerkey" in field or "squadkey" in field:
            return "PLAYER_KEY"
        if "playerid" in field or field == "squadid":
            return "PLAYER_ID"
        if "uniqueid" in field or field == "uniqueid":
            return "UNIQUE_ID"
        if field == "noteid":
            return "NOTE_ID"
        if field == "ipmask":
            return "IP_ADDRESS"
        if field == "settings_servername":
            return "SERVER_NAME"
        return None

    def sanitize_field_value(self, name: str, value: str) -> str:
        category = self.category_for_field(name)
        if category == "REDACTED":
            return "{{REDACTED}}"
        if category == "IP_ADDRESS" and value == "*":
            return value
        if category:
            return self.alias(category, value)
        return value

    def collect_named_aliases(self, value: str) -> None:
        for match in self.input_value_pattern.finditer(value):
            category = self.category_for_field(match.group("name"))
            if (
                category
                and category != "REDACTED"
                and not (category == "IP_ADDRESS" and match.group("value") == "*")
            ):
                self.alias(category, match.group("value"))

    def collect_player_table_aliases(self, value: str) -> None:
        """Alias plain-text player-name cells outside hidden form inputs."""
        for table in self.player_table_pattern.finditer(value):
            for row in self.player_row_name_pattern.finditer(table.group(2)):
                name = html.unescape(row.group(2).strip())
                if name:
                    self.alias("PLAYER", name)

    def collect_admin_aliases(self, value: str) -> None:
        for select in self.admin_select_pattern.finditer(value):
            for option in self.admin_option_pattern.finditer(select.group(1)):
                admin_id = html.unescape(option.group(1).strip())
                if admin_id:
                    self.alias("ADMIN", admin_id)

    def sanitize_text(self, value: str) -> str:
        self.collect_named_aliases(value)
        self.collect_player_table_aliases(value)
        self.collect_admin_aliases(value)
        value = value.replace(self.base_url, "{{BASE_URL}}")
        for pattern, replacement in VOLATILE_PATTERNS:
            value = pattern.sub(replacement, value)

        def replace_input(match: re.Match[str]) -> str:
            sanitized = self.sanitize_field_value(
                match.group("name"), match.group("value")
            )
            return match.group("prefix") + sanitized + match.group("suffix")

        value = self.input_value_pattern.sub(replace_input, value)
        value = self.player_key_attribute_pattern.sub(
            lambda match: match.group(1) + self.alias("PLAYER_KEY", match.group(2)),
            value,
        )
        for player_name, alias in self.aliases.get("PLAYER", {}).items():
            value = value.replace(player_name, alias)
        for admin_name, alias in self.aliases.get("ADMIN", {}).items():
            value = re.sub(
                rf"(?<![\w-]){re.escape(admin_name)}(?![\w-])",
                alias,
                value,
            )
        value = self.unique_id_pattern.sub(
            lambda match: self.alias("UNIQUE_ID", match.group(0)), value
        )
        value = self.ipv4_pattern.sub(
            lambda match: self.alias("IP_ADDRESS", match.group(0)), value
        )
        return value

    def sanitize_form(self, form: dict[str, str] | None) -> dict[str, str]:
        return {
            name: self.sanitize_field_value(name, value)
            for name, value in (form or {}).items()
        }


def response_headers(headers: httpx2.Headers) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_key, raw_value in headers.raw:
        key = raw_key.decode("ascii")
        value = raw_value.decode("iso-8859-1")
        if key.lower() == "set-cookie" and key in result:
            result[key] = f"{result[key]}\n{value}"
        else:
            result[key] = value
    return result


def sanitize_set_cookie(value: str, sanitizer: Sanitizer) -> str:
    return "\n".join(
        sanitize_single_set_cookie(line, sanitizer) for line in value.splitlines()
    )


def sanitize_single_set_cookie(value: str, sanitizer: Sanitizer) -> str:
    name, separator, remainder = value.partition("=")
    if not separator:
        return "{{REDACTED}}"
    _, attributes_separator, attributes = remainder.partition(";")
    sanitized = f"{name}={{{{REDACTED}}}}"
    if attributes_separator:
        sanitized += ";" + sanitizer.sanitize_text(attributes)
    return sanitized


def sanitize_headers(headers: dict[str, str], sanitizer: Sanitizer) -> dict[str, str]:
    sanitized_headers: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            sanitized_headers[key] = "{{REDACTED}}"
        elif key.lower() == "set-cookie":
            sanitized_headers[key] = sanitize_set_cookie(value, sanitizer)
        else:
            sanitized_headers[key] = sanitizer.sanitize_text(value)
    return sanitized_headers


def safe_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def write_capture(
    output_dir: Path, capture: Capture, sanitizer: Sanitizer
) -> dict[str, Any]:
    stem = safe_name(capture.name)
    suffix = (
        ".html" if "<html" in capture.body.lower() or "<" in capture.body else ".txt"
    )
    body_file = f"{stem}{suffix}"
    request_file = f"{stem}.request.json"
    body = sanitizer.sanitize_text(capture.body)
    (output_dir / body_file).write_text(body, encoding="utf-8")
    request_data = {
        "method": capture.method,
        "url": sanitizer.sanitize_text(capture.url),
        "form": sanitizer.sanitize_form(capture.form),
    }
    (output_dir / request_file).write_text(
        json.dumps(request_data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "name": capture.name,
        "method": capture.method,
        "url": sanitizer.sanitize_text(capture.url),
        "status": capture.status,
        "headers": sanitize_headers(capture.headers, sanitizer),
        "request": request_file,
        "response": body_file,
    }


def run(args: ToolArguments) -> int:
    if not args.username or not args.password:
        logger.warning(
            "username and password are required through options or environment variables"
        )
        return 2
    logger.info("authenticating with WebAdmin")
    probe = WebAdminProbe(args.base_url, args.username, args.password)
    failures: list[dict[str, str]] = []
    try:
        captures = probe.login()
        authenticated_home = probe.request("authenticated-home", "")
        captures.append(authenticated_home)
        routes = probe.discover_routes(authenticated_home.body)
        logger.info("capturing {} route candidates", len(routes))
        for route in routes:
            try:
                form = SAFE_FORM_READS.get(route)
                name = f"{'post' if form else 'get'}-{route or 'root'}"
                captures.append(probe.request(name, route, form))
            except (OSError, httpx2.RequestError) as error:
                logger.warning("route '{}' failed: {}", route or "/", error)
                failures.append({"route": route or "/", "error": str(error)})
        if args.write_chat:
            logger.info("posting authorized chat probe")
            captures.extend(
                probe.send_chat_probe("RS2 WebAdmin documentation probe {{TIMESTAMP}}")
            )
        if args.policy_roundtrip:
            logger.info("running reversible access-policy probe")
            captures.extend(probe.run_policy_roundtrip("203.0.113.251"))
        captures.append(probe.request("logout", "logout"))
    except (OSError, RuntimeError, httpx2.RequestError) as error:
        logger.error("probe error: {}", error)
        return 1
    args.output.mkdir(parents=True, exist_ok=True)
    sanitizer = Sanitizer(probe.base_url)
    entries = [write_capture(args.output, capture, sanitizer) for capture in captures]
    (args.output / "index.json").write_text(
        json.dumps({"captures": entries, "failures": failures}, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info("wrote {} sanitized captures to '{}'", len(entries), args.output)
    return 0


@click.command(context_settings=CLICK_CONTEXT_SETTINGS)
@click.option(
    "--base-url", required=True, help="WebAdmin base URL, including /ServerAdmin/"
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    required=True,
    help="Directory for sanitized captures",
)
@click.option("--username", default=os.environ.get("RS2_WEBADMIN_USERNAME"))
@click.option("--password", default=os.environ.get("RS2_WEBADMIN_PASSWORD"))
@click.option(
    "--write-chat", is_flag=True, help="Post one marked all-team chat message"
)
@click.option(
    "--policy-roundtrip",
    is_flag=True,
    help="Add and remove one reserved documentation policy entry",
)
def main(
    base_url: str,
    output: Path,
    username: str | None,
    password: str | None,
    write_chat: bool,
    policy_roundtrip: bool,
) -> None:
    """Capture sanitized RS2 WebAdmin API evidence."""
    configure_logging()
    exit_with_status(
        run(
            ToolArguments(
                base_url=base_url,
                output=output,
                username=username or "",
                password=password or "",
                write_chat=write_chat,
                policy_roundtrip=policy_roundtrip,
            )
        )
    )


if __name__ == "__main__":
    main()
