# Changelog

All notable AntiOS v2 changes are documented here.

The format follows Keep a Changelog principles. AntiOS v2 is currently pre-release software.

## [2.0.0a1] - 2026-09-30

### Added

- New Python 3.11+ package architecture.
- `scan` for read-only Windows inventory.
- `doctor` for runtime, TPM, Secure Boot and Registry-read diagnostics.
- `plan`, `backup`, `apply` and `restore` workflows.
- Dry-run behavior by default.
- Before/After change tables and JSON output modes.
- Explicit Registry write allowlist.
- Computer renaming through `SetComputerNameExW`.
- Backup schema with computer-name restoration support.
- TOML configuration and optional file logging.
- `version` and config management commands.
- Windows/Linux CI across Python 3.11, 3.12 and 3.13.
- PyInstaller portable Windows executable.
- Portable install/uninstall PowerShell helpers.
- SHA-256 checksum generation.
- GitHub build provenance attestation support.
- CodeQL and Dependabot configuration.
- Public security and contribution documentation.

### Changed

- Legacy v1 files were removed from the current v2 tree.
- Windows identity values outside the narrow v2 allowlist are read-only.
- Hostname changes no longer use direct Registry edits.

### Security

- Restore filters untrusted backup entries against the allowlist.
- File logging avoids generated/scanned identity values.
- Release artifacts are checksummed and built in GitHub Actions.

[2.0.0a1]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.1
