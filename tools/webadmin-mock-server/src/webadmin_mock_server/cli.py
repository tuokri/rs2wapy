"""Click entrypoint for running the standalone mock server."""

from __future__ import annotations

from functools import partial

import click
from sanic import Sanic
from sanic.worker.loader import AppLoader

from webadmin_mock_server.app import create_mock_server
from webadmin_mock_server.logging import configure_logging
from webadmin_mock_server.logging import logger

CLI_APP_NAME = "rs2_webadmin_mock_cli"


def _create_cli_app(*, debug_panel: bool) -> Sanic:
    """Create one deterministically named CLI app for Sanic worker loading."""
    configure_logging()
    return create_mock_server(enable_debug_panel=debug_panel, app_name=CLI_APP_NAME).app


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host interface to bind")
@click.option("--port", default=8081, show_default=True, type=click.IntRange(1, 65535))
@click.option("--debug-panel", is_flag=True, help="Enable the non-WebAdmin debug panel")
@click.option("--reload", is_flag=True, help="Enable Sanic auto-reload for source changes")
def main(host: str, port: int, debug_panel: bool, reload: bool) -> None:
    """Run an empty seeded RS2 WebAdmin mock server."""
    if reload:
        app_loader = AppLoader(factory=partial(_create_cli_app, debug_panel=debug_panel))
        app = app_loader.load()
        logger.info("starting mock server at '{}:{}' with auto-reload: {}", host, port, reload)
        app.prepare(host=host, port=port, dev=True, access_log=True, auto_reload=True)
        Sanic.serve(primary=app, app_loader=app_loader)
        return

    app = _create_cli_app(debug_panel=debug_panel)
    logger.info("starting mock server at '{}:{}' with auto-reload: {}", host, port, reload)
    app.run(host=host, port=port, access_log=True, single_process=True)
