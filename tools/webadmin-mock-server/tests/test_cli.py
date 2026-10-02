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

"""CLI configuration checks for the standalone mock server."""

from __future__ import annotations

from collections.abc import Callable

from click.testing import CliRunner
from pytest import MonkeyPatch

from webadmin_mock_server import cli


class _FakeApp:
    def __init__(self) -> None:
        self.prepare_kwargs: dict[str, str | int | bool] | None = None
        self.run_kwargs: dict[str, str | int | bool] | None = None

    def prepare(self, **kwargs: str | int | bool) -> None:
        self.prepare_kwargs = kwargs

    def run(self, **kwargs: str | int | bool) -> None:
        self.run_kwargs = kwargs


class _FakeAppLoader:
    def __init__(self, *, factory: Callable[[], _FakeApp]) -> None:
        self.factory = factory

    def load(self) -> _FakeApp:
        return self.factory()


def test_cli_enables_access_logs_without_auto_reload(monkeypatch: MonkeyPatch) -> None:
    app = _FakeApp()
    debug_panel_enabled: list[bool] = []

    def create_app(*, debug_panel: bool) -> _FakeApp:
        debug_panel_enabled.append(debug_panel)
        return app

    monkeypatch.setattr(cli, "_create_cli_app", create_app)

    result = CliRunner().invoke(cli.main, ["--host", "0.0.0.0", "--port", "9081"])

    assert result.exit_code == 0
    assert debug_panel_enabled == [False]
    assert app.run_kwargs == {
        "host": "0.0.0.0",
        "port": 9081,
        "access_log": True,
        "single_process": True,
    }


def test_cli_uses_an_app_loader_for_sanic_auto_reload(monkeypatch: MonkeyPatch) -> None:
    app = _FakeApp()
    served: dict[str, object] = {}

    def create_app(*, debug_panel: bool) -> _FakeApp:
        assert debug_panel is True
        return app

    def serve(*, primary: _FakeApp, app_loader: _FakeAppLoader) -> None:
        served["primary"] = primary
        served["app_loader"] = app_loader

    monkeypatch.setattr(cli, "_create_cli_app", create_app)
    monkeypatch.setattr(cli, "AppLoader", _FakeAppLoader)
    monkeypatch.setattr(cli.Sanic, "serve", serve)

    result = CliRunner().invoke(cli.main, ["--debug-panel", "--reload"])

    assert result.exit_code == 0
    assert app.prepare_kwargs == {
        "host": "127.0.0.1",
        "port": 8081,
        "dev": True,
        "access_log": True,
        "auto_reload": True,
    }
    assert served["primary"] is app
    assert isinstance(served["app_loader"], _FakeAppLoader)
