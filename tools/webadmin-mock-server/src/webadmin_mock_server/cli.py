"""Click entrypoint for running the standalone mock server."""

from __future__ import annotations

import click

from webadmin_mock_server.app import create_mock_server
from webadmin_mock_server.logging import configure_logging
from webadmin_mock_server.logging import logger


@click.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Host interface to bind")
@click.option("--port", default=8081, show_default=True, type=click.IntRange(1, 65535))
@click.option("--debug-panel", is_flag=True, help="Enable the non-WebAdmin debug panel")
def main(host: str, port: int, debug_panel: bool) -> None:
    """Run an empty seeded RS2 WebAdmin mock server."""
    configure_logging()
    logger.info("starting mock server at '{}:{}'", host, port)
    server = create_mock_server(enable_debug_panel=debug_panel)
    server.app.run(host=host, port=port, single_process=True)
