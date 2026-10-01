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
