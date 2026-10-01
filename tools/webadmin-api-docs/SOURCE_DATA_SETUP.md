# Optional Source-Data Setup

**Date:** 2026-10-01 (UTC)

The documentation tools can use two optional source-data inputs:

- RS2 dedicated-server WebAdmin templates and browser assets
- licensed RS2 SDK UnrealScript sources

Neither is committed to this repository or required to run a future mock.

## One-command setup

Supply the licensed SDK source root on first use:

```bash
uv run webadmin-api-docs sources setup --sdk-sources-dir /path/to/sdk-scripts
```

The SDK directory must contain `WebAdmin/Classes` and `ROGame/Classes`. Setup
fails before downloading anything when the SDK path is absent or invalid.

Unless an external web-assets root is configured, setup downloads only the
bundled `ServerAdmin/` and `images/` subtrees from the anonymous RS2 dedicated
server depot into ignored `.source-data/rs2-server-web/`. A valid cache is
reused on later calls.

Use `--force` to refresh project-managed downloads:

```bash
uv run webadmin-api-docs sources setup --force
```

`--force` never modifies the user-supplied SDK or an external web-assets
directory. An explicit SDK path overrides the cached path and is saved after a
successful setup.

## External assets and status

If the bundled assets already exist outside the checkout, configure their root
(the directory directly containing `ServerAdmin/` and `images/`):

```bash
uv run webadmin-api-docs sources configure --web-assets-dir /path/to/web-assets
uv run webadmin-api-docs sources configure --sdk-sources-dir /path/to/sdk-scripts
uv run webadmin-api-docs sources status
```

Validated external paths are saved in ignored
`.webadmin-api-docs.local.toml`; start from
[`source-data.example.toml`](source-data.example.toml) when configuring paths
manually. The project never records local paths in Git.

## Downloader integrity

The default downloader is a pinned DepotDownloader release. The project stores
reviewed SHA-256 values for each supported archive and its extracted executable.
Setup verifies both hashes, archive contents, and the reported version before
caching the executable. A later release requires a deliberate code review that
updates the version, URLs, hashes, and tests together.

`--depot-downloader PATH` is an operator trust override and requires
`--allow-unverified-downloader`. It is intended only when the operator has
independently verified that executable.

The SDK is not downloaded automatically because it requires a game license.
