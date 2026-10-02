# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
        logger.info("use a documented tool in 'tools/' to run a discovery probe")


main.add_command(sources)
