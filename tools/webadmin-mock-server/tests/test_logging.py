"""Logging integration checks for the standalone mock server."""

from __future__ import annotations

import logging

from webadmin_mock_server.logging import _SanicAccessLogHandler
from webadmin_mock_server.logging import configure_logging


def test_configure_logging_routes_sanic_access_logs_to_loguru() -> None:
    configure_logging()

    sanic_access_logger = logging.getLogger("sanic.access")

    assert sanic_access_logger.propagate is False
    assert sanic_access_logger.level == logging.INFO
    assert len(sanic_access_logger.handlers) == 1
    assert isinstance(sanic_access_logger.handlers[0], _SanicAccessLogHandler)
