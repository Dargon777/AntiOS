# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md)

**Windows Health, Privacy & Diagnostics — a friendly read-only dashboard with an auditable advanced CLI.**

AntiOS answers one simple question first: **does anything on this Windows PC need attention?**

> **Pre-release:** 2.0.0 alpha 6

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Download

**Recommended for most people:** download the latest Windows ZIP, extract it and double-click **`AntiOS-GUI.exe`**.

https://github.com/Dargon777/AntiOS/releases

The dashboard is read-only and does not require Administrator elevation just to open.

### Why people may find it useful

AntiOS checks common things that are scattered across different Windows screens:

- Microsoft Defender and real-time protection;
- BitLocker/device encryption;
- Secure Boot and TPM;
- free space on the system drive;
- common pending-restart markers;
- common startup applications;
- Windows edition, version and build;
- architecture, processor and uptime.

Results use simple **OK / Review / Warning / Info** states and keep the underlying detail visible. Alpha 5 adds a redesigned dark dashboard with sidebar navigation, status cards, colored badges and dedicated Security/System views.

AntiOS deliberately avoids a fake all-knowing “PC health score”.

## Privacy

**No automatic telemetry.**

AntiOS performs its checks locally. It does not automatically upload health results, startup entries, Windows identifiers, exported reports or other diagnostic data.

Read the policy: [PRIVACY.md](PRIVACY.md)

## Help shape AntiOS

The project is still early, so real user feedback matters more than adding a paywall.

- [Report a problem](https://github.com/Dargon777/AntiOS/issues/new?template=bug_report.yml)
- [Suggest a feature](https://github.com/Dargon777/AntiOS/issues/new?template=feature_request.yml)
- [View releases](https://github.com/Dargon777/AntiOS/releases)
- [Support the project](SUPPORT.md)
- [Star / share / contribute](https://github.com/Dargon777/AntiOS)

The GUI exposes the same feedback, project, privacy and support links directly from the dashboard.

## What the dashboard can do

The GUI can open the relevant built-in Windows pages for:

- Windows Security;
- Startup Apps;
- Storage.

It can export the collected report to JSON for your own use.

Review an exported report before posting it publicly: it may contain local system information such as your computer name, Windows build and startup entries.

## Install

The Windows release contains:

```text
AntiOS-GUI.exe
AntiOS.exe
install.ps1
uninstall.ps1
README.md
PRIVACY.md
SUPPORT.md
SECURITY.md
CHANGELOG.md
CODE_OF_CONDUCT.md
LICENSE
NOTICE
BUILD_INFO.txt
```

Install for the current Windows user and create a Start Menu shortcut:

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

Uninstall:

```powershell
.\uninstall.ps1
```

## Quick Check from the terminal

```powershell
.\AntiOS.exe quick-check
```

Short alias:

```powershell
.\AntiOS.exe check
```

JSON:

```powershell
.\AntiOS.exe quick-check --json
```

## Advanced CLI

Technical system inventory:

```powershell
antios scan
antios scan --json
```

Technical diagnostics:

```powershell
antios doctor
antios doctor --json
```

Generate a reversible metadata plan:

```powershell
antios plan
```

Preview changes without writing:

```powershell
antios apply
```

Real apply requires an Administrator terminal and explicit `--yes`:

```powershell
antios apply --yes
```

A backup is created before a real apply.

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

The advanced CLI keeps its write surface intentionally narrow.

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

Safeguards:

- writes are dry-run by default;
- real apply creates a backup first;
- backup files are treated as untrusted input;
- restore accepts only explicit allowlisted Registry targets;
- computer names are validated before use;
- logs exclude scanned/generated identity values and backup contents.

## Verify downloads

SHA-256:

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

Releases also include a wheel and source distribution.

```powershell
python -m pip install .\antios-2.0.0a6-py3-none-any.whl
antios-gui
```

CLI:

```powershell
antios quick-check
```

## Project landing page

A telemetry-free static landing page lives in `docs/index.html`.

A manually triggered GitHub Pages workflow is included in `.github/workflows/pages.yml`. Once GitHub Pages is enabled for the repository with **GitHub Actions** as the source, that workflow can publish the site.

## Development

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip pytest
python -m pip install -e .
python -m pytest
```

Build both Windows executables:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --console --name AntiOS antios_entry.py
pyinstaller --clean --noconfirm --onefile --windowed --name AntiOS-GUI antios_gui_entry.py
```

CI validates Windows/Linux Python matrices, CodeQL, wheel/sdist metadata, clean wheel installation, GUI entry points, both PyInstaller executables, smoke tests, release metadata and provenance attestations.

## License

The current AntiOS v2 source tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The repository is historically a fork. Legacy v1 material remains in Git history only; Apache-2.0 for the current v2 rewrite does not retroactively relicense historical third-party material for which the v2 contributors do not hold the necessary rights.

See also [PRIVACY.md](PRIVACY.md), [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CHANGELOG.md](CHANGELOG.md).
