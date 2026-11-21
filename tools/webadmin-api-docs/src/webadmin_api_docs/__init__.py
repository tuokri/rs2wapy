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

import importlib
import pkgutil

import click
from loguru import logger

from webadmin_api_docs import tools
from webadmin_api_docs.logging import LogLevel
from webadmin_api_docs.logging import configure_logging
from webadmin_api_docs.sources import sources


class DiscoveryGroup(click.Group):
    """Click group that imports discovery probe modules only when selected."""

    def discovery_names(self) -> list[str]:
        names: list[str] = []
        for module_info in pkgutil.iter_modules(tools.__path__):
            if module_info.name == "synthetic_pagination_probe":
                names.append("synthetic")
            else:
                names.append(module_info.name.replace("_", "-"))
        return sorted(set(names))

    def list_commands(self, ctx: click.Context) -> list[str]:
        names = super().list_commands(ctx)
        names.extend(self.discovery_names())
        return sorted(set(names))

    def get_command(
        self,
        ctx: click.Context,
        cmd_name: str,
    ) -> click.Command | None:
        command = super().get_command(ctx, cmd_name)
        if command is not None:
            return command

        module_name = (
            "synthetic_pagination_probe"
            if cmd_name == "synthetic"
            else cmd_name.replace("-", "_")
        )
        try:
            module = importlib.import_module(
                f"webadmin_api_docs.tools.{module_name}"
            )
        except ModuleNotFoundError:
            return None
        if module_name == "synthetic_pagination_probe":
            command = getattr(module, "cli", None)
        else:
            command = getattr(module, "main", None)
        if isinstance(command, click.Command):
            return command
        return None


@click.group(cls=DiscoveryGroup, invoke_without_command=True)
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
        logger.info("use a documented discovery probe module to run a live check")


main.add_command(sources)
