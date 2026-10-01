"""WebAdmin API documentation and discovery utilities."""

from __future__ import annotations

import click
from loguru import logger

from webadmin_api_docs.logging import LogLevel
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.sources import sources


@click.group(invoke_without_command=True)
@click.option(
    "--log-level",
    default="INFO",
    show_default=True,
    help="Console logging level",
)
@click.pass_context
def main(context: click.Context, log_level: LogLevel) -> None:
    """Configure project logging and direct users to the discovery tools."""
    configure_logging(log_level)
    if context.invoked_subcommand is None:
        logger.info("Use a documented tool in tools/ to run a discovery probe")


main.add_command(sources)
