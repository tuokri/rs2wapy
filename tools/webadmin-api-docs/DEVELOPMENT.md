# Development conventions

## Environment and validation

This is a Python 3.14+ standalone `uv` project. It is an editable
development-only rs2wapy dependency, but it retains its own lockfile and
virtual environment. From this directory, prepare it with:

```bash
uv python install 3.14
uv sync --all-groups --python 3.14
```

Use `uv run` for all project commands; do not activate or commit a virtual
environment. At each meaningful checkpoint, run:

```bash
uv run mypy .
uv run ruff check .
uv run python tools/verify_docs.py
```

The fixture verifier is offline and may also be run through `uv run` once the
environment is available. Do not perform live-server discovery merely to
validate a code-only change.

## Python and CLI style

- Write modern Python with complete, precise type hints. Prefer builtin generic
  forms such as `list[str]`, `dict[str, str]`, `str | None`, dataclasses, and
  `pathlib.Path`.
- Use `@dataclass(slots=True)` for project dataclasses unless dynamic
  attributes or weak references are an explicit requirement.
- Resolve a type error in code first. A type-ignore needs a narrowly scoped
  justification only where a supported type model is impractical.
- All command-line interfaces use Click, not `argparse`. Preserve existing
  long option names, required/default behavior, environment fallbacks, and
  exit statuses when evolving a tool. Keep options explicit, typed,
  documented, and safe by default.
- Keep command behavior reproducible: credentials come from explicit options
  or environment variables and are never logged or written to fixtures.
- Use `httpx2` for HTTP clients. The discovery probes are deliberately
  synchronous and use `httpx2.Client`; use `httpx2.AsyncClient` only where
  concurrent I/O makes the surrounding workflow materially clearer. Do not
  introduce `urllib` or `http.client` transport code.

## Logging

Use `webadmin_api_docs.logging` for all tool and package logging. Its lazy
configuration writes formatted output to the console and a rotating
`logs/webadmin-api-docs.log` file. The logs directory is intentionally ignored
by Git.

Import `logger` and `configure_logging` from `webadmin_api_docs.logging`.
Each CLI entrypoint calls `configure_logging()` once before it begins its work.
Use direct Loguru methods such as `logger.info()`, `logger.warning()`, and
`logger.error()` for operational output; their positional formatting is lazy.
Do not use `print()` for operational output.
Never send credentials, cookies, hashes, player identifiers, IP addresses, or
raw server responses to a log sink.

Log and exception messages should start non-capitalized. E.g.:
Log and exception messages should be compact and to-the-point.
```python
logger.error("Oh no, download failed! Something bad happened!")  # Bad!
logger.error("download error: {}: {}", code, msg)  # Good!
```

State intent before firing off I/O. E.g.:
```python
logger.info("downloading '{}'", some_url)
download_stuff(some_url)

logger.info("reading '{}'", some_path)
_ = some_path.read_text()

logger.info("removing '{}'", some_path)
some_path.unlink()
```

Wrap logged paths with `''`. E.g.:
```python
logger.info("using external web-assets source: '{}'", plan.web_assets_dir)  # Good!
logger.info("using external web-assets source: {}", plan.web_assets_dir)  # Bad!
```

Exception messages should be informational. E.g.:
```python
raise SourceConfigurationError("DepotDownloader archive hash does not match its pin")  # Bad!
raise SourceConfigurationError(
  "DepotDownloader archive hash does not match its pin:"
  f" expected: {expected_hash}"
  f", actual: {actual_hash}"
)  # Good!
```

## Discovery safety

The live server remains the compatibility authority. Preserve the runbook
checkpoint, use sanitized captures only, and complete each documented cleanup
and fresh-state verification before beginning another mutation.
