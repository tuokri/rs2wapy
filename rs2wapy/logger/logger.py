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

import sys
from pathlib import Path
from typing import TypeAlias

from loguru import logger

LogLevel: TypeAlias = str | int

_default_log_dir = Path().resolve()
_log_file = _default_log_dir / "rs2wapy.log"

# Disable logging unless enabled specifically.
_PACKAGE_NAME = __name__.split(".", maxsplit=1)[0]
logger.disable(_PACKAGE_NAME)

log_format = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> |"
    " <level>{level: <8}</level> | {process.id: <8} |"
    " <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan>"
    " - <level>{message}</level>"
)

stdout_handler_id = logger.add(
    sys.stdout,
    format=log_format,
)

log_file_handler_id = logger.add(
    _log_file,
    rotation="50 MB",
    retention=5,
    format=log_format,
    enqueue=True,
)


def _normalize_level(level: LogLevel) -> str | int:
    if isinstance(level, bool):
        raise TypeError("level must be str or int")

    if isinstance(level, int):
        return level

    value = level.strip()
    if not value:
        raise ValueError("level cannot be empty")

    if value.lstrip("+-").isdigit():
        return int(value)

    name = value.upper()
    logger.level(name)  # Standard loguru validation.
    return name


def configure_logging(
    level: LogLevel = "INFO",
    # log_file_config
) -> None:
    pass
