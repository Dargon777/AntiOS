# Changelog

All notable AntiOS v2 changes are documented here.

The format follows Keep a Changelog principles. AntiOS v2 is currently pre-release software.

## [2.0.0a9] - 2026-10-01

### Added

- Read-only **Storage Cleanup** dashboard page.
- Folder picker with background scanning, progress reporting and cancellation.
- Exact duplicate-file detection using size pre-filtering, quick fingerprints and full SHA-256 verification.
- Potential duplicate-space savings calculation.
- Old large-file candidates based on last-modified time.
- Installer/archive candidates for common package and archive formats.
- Empty-file candidates.
- Open-containing-folder action from cleanup results.
- Storage cleanup results in exported JSON reports.
- `storage-scan` / `cleanup-scan` CLI command with configurable thresholds.
- Storage Cleanup localization across all seven supported languages.

### Safety

- Storage Cleanup is read-only and never deletes files automatically.
- Symlinks are not followed during recursive scans.
- AntiOS explicitly does not label files “unused” from Windows last-access timestamps; old-file candidates use last-modified time only.

## [2.0.0a8] - 2026-10-01

### Added

- GUI quick-action strip for Windows Security, Startup Apps and Storage.
- Dashboard keyboard shortcuts: `F5`, `Ctrl+E`, and `Ctrl+1…4`.
- Visible application version/channel in the dashboard sidebar.
- Hover/focus states for navigation and action buttons.
- Optional Azure Artifact Signing integration for direct-download EXE releases.
- Authenticode verification gate before packaging when signing is enabled.
- Dedicated GUI-only Microsoft Store MSIX manifest/template.
- Reproducible Store MSIX build script.
- Store-package CI workflow with Partner Center identity inputs.
- Windows signing and Store packaging documentation.

### Changed

- Dashboard window sizing, spacing and header actions were refined for a more native desktop feel.
- Store packaging excludes the advanced CLI and ships the read-only GUI only.
- Release build metadata now records whether the direct-download binaries were signed.

### Security

- Production code signing uses GitHub OIDC with Azure Artifact Signing; no long-lived Azure client secret is required.
- Self-signed certificates remain explicitly limited to development/testing.

## [2.0.0a7] - 2026-10-01

### Added

- Finnish (`fi`) localization.
- Polish (`pl`) localization.
- Mongolian (`mn`) localization using modern Mongolian Cyrillic.
- Automatic locale detection for `fi-FI`, `pl-PL` and `mn-MN`.
- Finnish, Polish and Mongolian quick-start README files.
- Localization tests expanded from four to seven supported languages.

### Changed

- Dashboard language selector now exposes seven languages.
- `quick-check --lang` and `dashboard --lang` accept `fi`, `pl` and `mn`.
- Windows release ZIP now includes all seven language quick-start guides.

## [2.0.0a6] - 2026-09-30

### Added

- Four-language localization: English, Russian, Spanish and Simplified Chinese.
- Automatic UI language detection from the user/system locale.
- Live dashboard language switcher without restarting or rescanning.
- Localized health-check details, actions, status badges and dynamic values.
- Localized `quick-check` CLI output with `--lang`.
- `--lang` support for launching the dashboard from the CLI.
- English fallback for unsupported locales and missing translation keys.
- Russian, Spanish and Simplified Chinese quick-start README files.
- Tests that enforce full translation-key coverage across all four languages.

## [2.0.0a5] - 2026-09-30

### Changed

- Rebuilt the dashboard around a modern dark card-based layout.
- Replaced native notebook tabs with a persistent left navigation rail.
- Added a large overall-status hero card and separate OK/Review/Warning counters.
- Replaced the Overview table with colored health-check cards and contextual actions.
- Added dedicated Security cards for Defender, BitLocker, Secure Boot and TPM.
- Restyled the Startup Apps table for the dark interface.
- Reworked the System page into structured cards.
- Added dark Windows title-bar integration when supported.
- Added Windows DPI-awareness for sharper rendering on scaled displays.
- Kept the dashboard read-only; the release is a presentation redesign only.

## [2.0.0a4] - 2026-09-30

### Added

- Transparent no-telemetry privacy policy.
- Project support/feedback guide.
- Dashboard links for bug reports, feature requests, GitHub, support and privacy.
- Telemetry-free static landing page source.
- Manually triggered GitHub Pages deployment workflow.
- GitHub funding configuration for future Sponsors support.

### Changed

- README now leads with download, privacy, feedback and trust.
- Windows release ZIP includes privacy and support documentation.
- Growth work intentionally avoids adding telemetry or a paywall before real user feedback exists.

## [2.0.0a3] - 2026-09-30

### Added

- Consumer-oriented `quick-check` / `check` command.
- Read-only Microsoft Defender status check.
- Read-only BitLocker/device-encryption status check.
- System-drive free-space check.
- Common Windows pending-restart detection.
- Common startup-app inventory from Run/RunOnce keys and Startup folders.
- New Tkinter-based Windows Health & Privacy dashboard.
- Separate windowed `AntiOS-GUI.exe` portable binary.
- Installed `antios-gui` Python GUI entry point.
- JSON report export from the dashboard.
- Buttons to open Windows Security, Startup Apps and Storage settings.
- Start Menu shortcut creation in the user-scope installer.
- Optional desktop shortcut.

### Changed

- README and package metadata now lead with the consumer Health & Privacy use case.
- Release ZIP now includes both GUI and CLI executables.
- Installer installs both executables while advanced CLI changes remain opt-in.
- Startup inventory no longer depends on WMI enumeration privileges.

### Safety

- The GUI exposes read-only diagnostics only.
- System-changing identity operations remain CLI-only and dry-run by default.

## [2.0.0a2] - 2026-09-30

### Added

- Apache License 2.0 for the current AntiOS v2 source tree.
- `NOTICE` with provenance clarification for historical legacy material.
- Code of Conduct.
- Python wheel and source-distribution builds in release CI.
- `twine check` validation for Python distributions.
- Clean-wheel installation and smoke test.
- GitHub provenance attestations for Windows and Python release artifacts.
- Python wheel and source distribution attached to GitHub pre-releases.

### Changed

- Public release ZIP now includes `LICENSE`, `NOTICE` and `CODE_OF_CONDUCT.md`.
- Package metadata now exposes SPDX license expression `Apache-2.0`.
- Release documentation now distinguishes the licensed current v2 tree from historical third-party material.

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

[2.0.0a9]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.9
[2.0.0a8]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.8
[2.0.0a7]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.7\n[2.0.0a6]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.6
[2.0.0a5]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.5
[2.0.0a4]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.4
[2.0.0a3]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.3\n[2.0.0a2]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.2
[2.0.0a1]: https://github.com/Dargon777/AntiOS/releases/tag/v2.0.0-alpha.1
