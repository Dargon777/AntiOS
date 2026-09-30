# AntiOS v2

A small Windows privacy/system-identity lab focused on **transparent, reversible and auditable** operations.

AntiOS v2 is a rewrite of the project. The current v2 tree does not contain the legacy v1 fingerprint-spoofing implementation; that code remains only in the repository history.

> **Pre-release:** 2.0.0 alpha 1. Use dry-run first and keep backups.

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)

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
BUILD_INFO.txt
```

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

Release archives built from `master` receive a GitHub artifact attestation.

With a current GitHub CLI:

```powershell
gh attestation verify .\AntiOS-windows-x64.zip --repo Dargon777/AntiOS
```

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

Build the portable executable locally on Windows:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --console --name AntiOS antios_entry.py
.\dist\AntiOS.exe --version
```

CI currently validates:

- Windows latest × Python 3.11 / 3.12 / 3.13;
- Ubuntu latest × Python 3.11 / 3.12 / 3.13;
- PyInstaller Windows build;
- executable smoke tests;
- CodeQL analysis;
- release version synchronization.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

## Release process

`release/VERSION` must match `antios.__version__`.

The Windows release workflow builds and tests every PR. When the release-ready commit lands on `master`, it:

1. builds the portable executable;
2. smoke-tests the executable itself;
3. packages the ZIP;
4. creates SHA-256 checksums;
5. creates GitHub build provenance;
6. publishes the alpha release if the tag in `release/TAG` does not already exist.

## License

No open-source license has been selected for AntiOS v2 yet. Until the repository owner adds one, do not assume permission to redistribute or incorporate the source into other projects.

The repository is historically a fork, but the current v2 tree contains only the rewritten v2 implementation; legacy v1 remains in Git history.
