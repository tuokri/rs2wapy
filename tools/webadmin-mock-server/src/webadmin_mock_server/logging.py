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

"""Loguru setup for the standalone mock-server CLI."""

from __future__ import annotations

import logging
import sys

from loguru import logger


class _SanicAccessLogHandler(logging.Handler):
    """Forward Sanic's standard-library access records to the Loguru sink."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit one Sanic access record through the configured Loguru logger."""
        host = getattr(record, "host", "-")
        request = getattr(record, "request", "-")
        status = getattr(record, "status", "-")
        byte_count = getattr(record, "byte", "-")
        duration = getattr(record, "duration", "-")
        logger.log(
            record.levelname,
            "sanic access | {} | {} | {} | {} bytes | {}",
            host,
            request,
            status,
            byte_count,
            duration,
        )


def configure_logging() -> None:
    """Configure the CLI log sink once before the Sanic server starts."""
    logger.remove()
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level:<8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
        "<level>{message}</level>",
    )
    sanic_access_logger = logging.getLogger("sanic.access")
    sanic_access_logger.handlers = [_SanicAccessLogHandler()]
    sanic_access_logger.propagate = False
    sanic_access_logger.setLevel(logging.INFO)
