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

"""Shared Loguru configuration for WebAdmin documentation tooling."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

type LogLevel = str | int

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIRECTORY = _PROJECT_ROOT / "logs"
_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level:<8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)


def normalize_level(level: LogLevel) -> str | int:
    """Validate and normalize a Loguru level supplied by a CLI or caller."""
    if isinstance(level, bool):
        raise TypeError("level must be a string or integer")
    if isinstance(level, int):
        return level

    normalized = level.strip()
    if not normalized:
        raise ValueError("level cannot be empty")
    if normalized.lstrip("+-").isdigit():
        return int(normalized)

    normalized = normalized.upper()
    logger.level(normalized)
    return normalized


def configure_logging(level: LogLevel = "INFO") -> None:
    """Called once in application entry point."""
    normalized_level = normalize_level(level)
    _LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)

    logger.remove()  # Replace Loguru's default sink.
    logger.add(
        sys.stdout,
        format=_LOG_FORMAT,
        level=normalized_level,
    )
    logger.add(
        _LOG_DIRECTORY / "webadmin-api-docs.log",
        format=_LOG_FORMAT,
        level="DEBUG",
        rotation="50 MB",
        retention=5,
        enqueue=True,
        colorize=False,
    )
