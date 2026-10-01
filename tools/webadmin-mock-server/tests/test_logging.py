"""Logging integration checks for the standalone mock server."""

from __future__ import annotations

import logging

from loguru import logger

from webadmin_mock_server.logging import _SanicAccessLogHandler
from webadmin_mock_server.logging import configure_logging


def test_configure_logging_routes_sanic_access_logs_to_loguru() -> None:
    configure_logging()

    sanic_access_logger = logging.getLogger("sanic.access")

    assert sanic_access_logger.propagate is False
    assert sanic_access_logger.level == logging.INFO
    assert len(sanic_access_logger.handlers) == 1
    assert isinstance(sanic_access_logger.handlers[0], _SanicAccessLogHandler)


def test_sanic_access_log_handler_renders_structured_access_data() -> None:
    messages: list[str] = []
    handler_id = logger.add(messages.append, format="{message}")
    record = logging.LogRecord("sanic.access", logging.INFO, __file__, 1, "", (), None)
    record.host = "127.0.0.1"
    record.request = "GET /__debug__/"
    record.status = 200
    record.byte = 1234
    record.duration = "3.4ms"

    try:
        _SanicAccessLogHandler().emit(record)
    finally:
        logger.remove(handler_id)

    assert messages == [
        "sanic access | 127.0.0.1 | GET /__debug__/ | 200 | 1234 bytes | 3.4ms\n"
    ]
