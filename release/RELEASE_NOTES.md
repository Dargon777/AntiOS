# AntiOS v2.0.0 alpha 1

This is the first public AntiOS v2 preview.

AntiOS v2 is a rewrite focused on transparent, reversible Windows system-identity and privacy-lab workflows rather than broad fingerprint spoofing.

## What is included

- read-only Windows system inventory;
- TPM and Secure Boot diagnostics;
- human-readable and JSON output;
- dry-run identity planning;
- backup/apply/restore workflows;
- safe computer renaming through the Windows API;
- TOML configuration;
- optional privacy-conscious logging;
- single-file Windows portable executable;
- installer/uninstaller PowerShell helpers;
- SHA-256 checksum and GitHub provenance attestation.

## What is intentionally not included

AntiOS v2 does not provide anti-cheat, ban, licensing, hardware/storage serial, MAC-address, telemetry/update-ID or similar evasion/bypass capabilities.

## Windows warning

The alpha executable is not Authenticode-signed. Windows SmartScreen may therefore show an unknown-publisher warning even when the downloaded file matches the published SHA-256 and GitHub provenance attestation.

## Verify

Compare the downloaded ZIP against `AntiOS-windows-x64.zip.sha256`.

For the GitHub build provenance attestation, users with a current GitHub CLI can verify the artifact with `gh attestation verify` against this repository.
