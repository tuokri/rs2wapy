"""Shared Loguru configuration for WebAdmin documentation tooling."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

type LogLevel = str | int

_PACKAGE_NAME = "webadmin_api_docs"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOG_DIRECTORY = _PROJECT_ROOT / "logs"
_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level:<8}</level> | "
    "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
    "<level>{message}</level>"
)
_configured = False


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
    """Configure console and rotating project-log sinks exactly once."""
    global _configured
    if _configured:
        return

    normalized_level = normalize_level(level)
    _LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)
    logger.remove()
    logger.add(sys.stdout, format=_LOG_FORMAT, level=normalized_level)
    logger.add(
        _LOG_DIRECTORY / "webadmin-api-docs.log",
        format=_LOG_FORMAT,
        level="DEBUG",
        rotation="50 MB",
        retention=5,
        enqueue=True,
    )
    _configured = True


def _ensure_configured() -> None:
    if not _configured:
        configure_logging()


def info(message: str) -> None:
    """Emit an informational progress message."""
    _ensure_configured()
    logger.info(message)


def task(message: str) -> None:
    """Emit the next unit of work as an informational message."""
    _ensure_configured()
    logger.info("Task: {}", message)


def warn(message: str) -> None:
    """Emit a warning or error-condition message."""
    _ensure_configured()
    logger.warning(message)
