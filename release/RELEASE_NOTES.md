# AntiOS v2.0.0 alpha 2

Alpha 2 is the recommended public preview.

It keeps the same narrow, reversible AntiOS v2 safety model and finishes the public open-source release layer.

## New in alpha 2

- AntiOS v2 is licensed under the Apache License 2.0.
- The release includes LICENSE and NOTICE files.
- Python wheel and source distribution are published alongside the Windows ZIP.
- Python package metadata declares SPDX `Apache-2.0`.
- Wheel and sdist are validated with `twine check`.
- CI installs the built wheel into a clean virtual environment and smoke-tests it.
- Windows ZIP, wheel and source distribution receive GitHub build provenance attestations.
- A project Code of Conduct is included.

## Historical provenance

The Apache-2.0 license applies to the current AntiOS v2 source tree and contributions unless a file states otherwise.

The repository history contains legacy third-party material from the historical upstream repository. Apache-2.0 adoption for v2 does not retroactively relicense historical material for which the v2 contributors do not hold the necessary rights.

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
- Python wheel and source distribution;
- SHA-256 checksum and GitHub provenance attestations.

## What is intentionally not included

AntiOS v2 does not provide anti-cheat, ban, licensing, hardware/storage serial, MAC-address, telemetry/update-ID or similar evasion/bypass capabilities.

## Windows warning

The alpha executable is not Authenticode-signed. Windows SmartScreen may therefore show an unknown-publisher warning even when the downloaded file matches the published SHA-256 and GitHub provenance attestation.

## Verify

Compare the Windows ZIP against `AntiOS-windows-x64.zip.sha256`.

With a current GitHub CLI, release artifacts can be verified against this repository with `gh attestation verify`.
