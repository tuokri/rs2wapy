"""Loguru setup for the standalone mock-server CLI."""

from __future__ import annotations

import sys

from loguru import logger


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
