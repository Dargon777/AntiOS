# AntiOS

**Windows Health, Privacy & Diagnostics — with a friendly dashboard and an auditable advanced CLI.**

AntiOS is designed to answer a simple question first: **“Does anything on my Windows PC need attention?”**

> **Pre-release:** 2.0.0 alpha 3

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## For most people

1. Open the latest GitHub Release.
2. Download `AntiOS-windows-x64.zip`.
3. Extract it.
4. Double-click **`AntiOS-GUI.exe`**.

Latest releases:

https://github.com/Dargon777/AntiOS/releases

The dashboard is read-only. It does not change Windows settings by itself.

No Administrator elevation is required just to open the dashboard. Individual status checks may be unavailable when Windows, firmware or security policy does not expose them.

## What the dashboard checks

AntiOS currently shows:

- Microsoft Defender antivirus and real-time protection;
- BitLocker/device-encryption status;
- Secure Boot;
- TPM presence/readiness;
- system-drive free space;
- common Windows pending-restart markers;
- common startup applications;
- Windows edition, version and build;
- architecture, processor and uptime.

Results are grouped into simple states:

- **OK** — nothing obvious needs attention;
- **Review** — worth looking at, but not necessarily a problem;
- **Warning** — something important may need attention;
- **Info** — a check is informational or unavailable.

AntiOS does not pretend that a single health score can describe an entire PC. It shows the individual checks and why each result was produced.

## Dashboard actions

The GUI can open the relevant built-in Windows pages for:

- Windows Security;
- Startup Apps;
- Storage.

It can also export the collected report to JSON.

## Install

The release ZIP contains:

```text
AntiOS-GUI.exe
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

To install for the current Windows user and create a Start Menu shortcut:

```powershell
.\install.ps1
```

Optional desktop shortcut:

```powershell
.\install.ps1 -DesktopShortcut
```

Optional CLI PATH entry:

```powershell
.\install.ps1 -AddToPath
```

Both switches can be combined.

Uninstall:

```powershell
.\uninstall.ps1
```

Remove the PATH entry too:

```powershell
.\uninstall.ps1 -RemoveFromPath
```

## Quick Check from the terminal

For a compact consumer-oriented check:

```powershell
.\AntiOS.exe quick-check
```

Short alias:

```powershell
.\AntiOS.exe check
```

Machine-readable:

```powershell
.\AntiOS.exe quick-check --json
```

## Advanced CLI

The CLI retains the technical AntiOS v2 functionality.

### System inventory

```powershell
antios scan
antios scan --json
```

### Technical diagnostics

```powershell
antios doctor
antios doctor --json
```

### Reversible metadata plan

```powershell
antios plan
```

Preview changes:

```powershell
antios apply
```

A preview does not write anything.

Real apply requires an Administrator terminal and explicitly supplied `--yes`:

```powershell
antios apply --yes
```

A backup is written before a real apply.

Restore preview:

```powershell
antios restore antios-backup.json
```

Real restore:

```powershell
antios restore antios-backup.json --yes
```

## Safety model

The consumer dashboard is read-only.

The advanced CLI deliberately keeps its write surface narrow.

Writable state:

- `RegisteredOwner` through the Windows Registry;
- computer name through the supported Windows `SetComputerNameExW` API.

Read-only / out of scope:

- `MachineGuid`;
- `ProductId`;
- hardware and storage serial changes;
- MAC-address changes;
- Windows telemetry/update identifier changes;
- anti-cheat, ban or licensing bypasses.

Additional safeguards:

- writes are dry-run by default;
- real apply creates a backup first;
- backup files are treated as untrusted input;
- restore only accepts explicit allowlisted Registry targets;
- computer names are validated before use;
- logs exclude scanned/generated identity values and backup contents.

## Verify downloads

The Windows ZIP is published with a SHA-256 checksum.

```powershell
(Get-FileHash .\AntiOS-windows-x64.zip -Algorithm SHA256).Hash.ToLower()
Get-Content .\AntiOS-windows-x64.zip.sha256
```

GitHub provenance:

```powershell
gh attestation verify .\AntiOS-windows-x64.zip --repo Dargon777/AntiOS
```

The executables are not Authenticode-signed yet, so Windows SmartScreen may show an unknown-publisher warning.

## Python installation

AntiOS releases also include a wheel and source distribution.

```powershell
python -m pip install .\antios-2.0.0a3-py3-none-any.whl
antios-gui
```

CLI:

```powershell
antios quick-check
```

## Configuration

Create the default per-user config:

```powershell
antios config init
```

Show effective configuration:

```powershell
antios config show
```

Windows default location:

```text
%APPDATA%\AntiOS\antios.toml
```

## Development

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip pytest
python -m pip install -e .
python -m pytest
```

Build Python distributions:

```powershell
python -m pip install build twine
python -m build
python -m twine check dist/*
```

Build both Windows executables:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --console --name AntiOS antios_entry.py
pyinstaller --clean --noconfirm --onefile --windowed --name AntiOS-GUI antios_gui_entry.py
.\dist\AntiOS.exe --version
.\dist\AntiOS-GUI.exe --self-test
```

CI validates:

- Windows latest × Python 3.11 / 3.12 / 3.13;
- Ubuntu latest × Python 3.11 / 3.12 / 3.13;
- CodeQL;
- wheel and source-distribution metadata;
- Apache LICENSE/NOTICE inside Python distributions;
- clean wheel installation;
- installed GUI entry-point self-test;
- CLI PyInstaller executable;
- GUI PyInstaller executable;
- executable smoke tests;
- release version synchronization;
- GitHub provenance attestations on master releases.

## License

The current AntiOS v2 source tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The repository is historically a fork. Legacy v1 material remains in Git history only; Apache-2.0 for the current v2 rewrite does not retroactively relicense historical third-party material for which the v2 contributors do not hold the necessary rights.

See also [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CHANGELOG.md](CHANGELOG.md).
