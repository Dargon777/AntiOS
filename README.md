# AntiOS v2

A small Windows privacy/system-identity lab focused on **transparent, reversible and auditable** operations.

AntiOS v2 is a rewrite of the project. The current v2 tree does not contain the legacy v1 fingerprint-spoofing implementation; that code remains only in the repository history.

> **Pre-release:** 2.0.0 alpha 2. Use dry-run first and keep backups.

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Download

Public builds are published on the GitHub Releases page:

https://github.com/Dargon777/AntiOS/releases

The Windows release contains:

```text
AntiOS.exe
install.ps1
uninstall.ps1
README.md
SECURITY.md
CHANGELOG.md
CODE_OF_CONDUCT.md
LICENSE
NOTICE
BUILD_INFO.txt
```

The release also publishes a Python wheel and source distribution.

A matching `AntiOS-windows-x64.zip.sha256` file is published beside the ZIP.

The executable is currently **not Authenticode-signed**, so Windows SmartScreen may show an unknown-publisher warning. Verify the checksum and GitHub build provenance before running it.

## Verify a release

### SHA-256

PowerShell:

```powershell
(Get-FileHash .\AntiOS-windows-x64.zip -Algorithm SHA256).Hash.ToLower()
Get-Content .\AntiOS-windows-x64.zip.sha256
```

The values should match.

### GitHub build provenance

Release archives built from `master` receive GitHub artifact attestations.

With a current GitHub CLI:

```powershell
gh attestation verify .\AntiOS-windows-x64.zip --repo Dargon777/AntiOS
```

Python distributions published with the release are attested as well.

## Quick start

Portable:

```powershell
.\AntiOS.exe --version
.\AntiOS.exe scan
.\AntiOS.exe doctor
```

Source install:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
antios --version
antios doctor
```

Install a release wheel:

```powershell
python -m pip install .\antios-2.0.0a2-py3-none-any.whl
antios --version
```

## Safety model

AntiOS v2 deliberately keeps its write surface small.

Writable state:

- `RegisteredOwner` through the Windows Registry;
- computer name through the supported Windows `SetComputerNameExW` API.

Read-only / out of scope:

- `MachineGuid`;
- `ProductId`;
- hardware and storage serials;
- MAC-address changes;
- Windows telemetry/update identifiers;
- anti-cheat, ban or licensing bypasses.

Additional safeguards:

- system changes are **dry-run by default**;
- a real `apply` creates a backup first;
- backup files are treated as untrusted input;
- restore only accepts explicit allowlisted Registry targets;
- computer names are validated before use;
- identity values and fingerprint data are intentionally excluded from file logs.

## Commands

### Version

```powershell
antios --version
antios version
antios version --json
```

### Scan

Read-only inventory:

```powershell
antios scan
```

JSON:

```powershell
antios scan --json
```

The scan includes Windows generation/edition/build, architecture, processor, TPM, Secure Boot and documented Registry identity metadata.

### Doctor

```powershell
antios doctor
antios doctor --json
```

`doctor` reports OK / INFO / NOTE / WARN checks. Actual warnings return a non-zero exit status for automation.

### Plan

```powershell
antios plan
```

Explicit values:

```powershell
antios plan --computer-name LAB-PC --registered-owner "Lab User"
```

### Apply

Preview only:

```powershell
antios apply
```

Real apply from an Administrator terminal:

```powershell
antios apply --yes
```

Choose a backup path:

```powershell
antios apply --yes --backup .\backups\before-change.json
```

Computer-name changes require a Windows restart before all components observe the new name.

### Backup

```powershell
antios backup
antios backup .\backups\manual.json
```

### Restore

Preview:

```powershell
antios restore antios-backup.json
```

Real restore:

```powershell
antios restore antios-backup.json --yes
```

### Configuration

Create a per-user config:

```powershell
antios config init
```

Show effective config:

```powershell
antios config show
```

On Windows the default path is:

```text
%APPDATA%\AntiOS\antios.toml
```

Example:

```toml
[general]
computer_name_prefix = "LAB"
backup_path = "antios-backup.json"
color = "auto"

[logging]
level = "INFO"
file = ""
```

Use a one-off config:

```powershell
antios --config .\lab.toml doctor
```

Disable ANSI colors with `--no-color` or the conventional `NO_COLOR` environment variable.

## Logging

File logging is disabled by default.

Enable it for one command:

```powershell
antios --log-file .\antios.log doctor
```

The logger records operational metadata such as command name, dry-run state, change count and backup path. It does not log scanned/generated identity values or backup contents.

## Portable install

From the extracted release ZIP:

```powershell
.\install.ps1
```

This installs to:

```text
%LOCALAPPDATA%\Programs\AntiOS
```

Add it to your **user** PATH only when requested:

```powershell
.\install.ps1 -AddToPath
```

Uninstall:

```powershell
.\uninstall.ps1
```

Remove the directory from user PATH too:

```powershell
.\uninstall.ps1 -RemoveFromPath
```

## Development

Run tests:

```powershell
python -m pip install pytest
python -m pip install -e .
python -m pytest
```

Build Python distributions:

```powershell
python -m pip install build twine
python -m build
python -m twine check dist/*
```

Build the portable executable locally on Windows:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --console --name AntiOS antios_entry.py
.\dist\AntiOS.exe --version
```

CI currently validates:

- Windows latest × Python 3.11 / 3.12 / 3.13;
- Ubuntu latest × Python 3.11 / 3.12 / 3.13;
- wheel and source-distribution metadata;
- installation from the built wheel;
- PyInstaller Windows build;
- executable smoke tests;
- CodeQL analysis;
- release version synchronization.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CHANGELOG.md](CHANGELOG.md).

## Release process

`release/VERSION` must match `antios.__version__`.

The Windows release workflow builds and tests every PR. When a release-ready commit lands on `master`, it:

1. validates package/release version synchronization;
2. runs the test suite;
3. builds and validates wheel + sdist;
4. installs and smoke-tests the built wheel;
5. builds `AntiOS.exe`;
6. smoke-tests the executable itself;
7. packages the Windows ZIP;
8. creates SHA-256 checksums;
9. creates GitHub build provenance for release artifacts;
10. publishes the pre-release if the tag in `release/TAG` does not already exist.

## License

The current AntiOS v2 source tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The repository is historically a fork. Legacy v1 material remains in Git history only; adopting Apache-2.0 for the current v2 rewrite does not retroactively relicense historical third-party material for which the v2 contributors do not hold the necessary rights.
