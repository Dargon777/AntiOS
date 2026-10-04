# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md) · [Suomi](README.fi.md) · [Polski](README.pl.md) · [Монгол](README.mn.md)

**On-demand antivirus scanning, encrypted quarantine and Windows Health, Privacy & Diagnostics.**

AntiOS answers one simple question first: **does anything on this Windows PC need attention?**

> **Pre-release:** 2.0.0 alpha 12

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Download

**Recommended for most people:** download the latest Windows ZIP, extract it and double-click **`AntiOS-GUI.exe`**.

https://github.com/Dargon777/AntiOS/releases

Windows executables request Administrator consent at startup. Cancelling UAC cancels launch. Extract the entire archive: keep `_gui` and `_cli` beside the EXE files. Quarantine and restore still require explicit confirmation.

## Antivirus

Open **Antivirus** from the sidebar or press `Ctrl+6`:

- Scan a selected file or folder without changing its contents.
- Choose Windows AMSI or an independent local ClamAV engine, alongside local SHA-256 signatures.
- Inspect detections, skipped files, access errors and incomplete coverage.
- Encrypt and isolate a selected detection in current-user Windows DPAPI quarantine.
- Restore selected quarantined items without overwriting existing files.
- Run Defender quick/full scans or update its signatures after confirmation.
- Export a JSON scan report.
- Explore the separate [experimental native Windows filter/service](native/README.md); source and lab tooling only, not part of the release package.
- Run the optional [resident Guard](docs/GUARD.md) for automatic post-write checks in selected folders, with explicit opt-in quarantine.

The current production-core work includes independent ClamAV detection, encrypted quarantine, an optional post-write Resident Guard, a managed ClamAV service/update lifecycle, verified Windows service ownership for the ClamD loopback peer, and an experimental native execute-open minifilter. It is **not yet a certified primary Windows antivirus replacement**; see the [readiness gates](docs/DEFENDER_REPLACEMENT.md). AntiOS does not disable Defender or fake Windows Security registration. The built-in local database contains only the EICAR test hash; [ClamAV integration](docs/CLAMAV.md) supplies independent official signatures and archive/file-format analysis. Default limits are 32 MiB per file and 100,000 files, with skipped files and failed provider calls explicitly reported.

Details, CLI examples, exit codes and quarantine recovery: [docs/ANTIVIRUS.md](docs/ANTIVIRUS.md).

### Why people may find it useful

AntiOS checks common things that are scattered across different Windows screens:

- Microsoft Defender and real-time protection;
- BitLocker/device encryption;
- Secure Boot and TPM;
- free space on the system drive;
- common pending-restart markers;
- common startup applications;
- Windows edition, version and build;
- architecture, processor and uptime;
- duplicate files and potential duplicate-space savings;
- old large files, installers/archives and empty-file cleanup candidates.

Windows health results use simple **OK / Review / Warning / Info** states and keep the underlying detail visible. The Settings hub preserves language, theme and Storage Cleanup preferences. These checks describe Windows health settings; a completed health check is not a malware scan.

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
protection-engine.ps1
guard-startup.ps1
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

Managed independent ClamAV backend (preview first):

```powershell
.\protection-engine.ps1 -ClamAVDirectory "C:\staging\clamav-1.5.x.win.x64"
.\protection-engine.ps1 -ClamAVDirectory "C:\staging\clamav-1.5.x.win.x64" -Apply
.\AntiOS.exe protection-status
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

Antivirus stack status:

```powershell
antios protection-status
antios protection-status --json
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

Health and Storage Cleanup checks are read-only. Antivirus file scans are read-only; quarantine, restore and Defender actions require explicit confirmation. The antivirus does not change exclusions or disable any protection setting.

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

## Windows trust and SmartScreen

For Microsoft Store distribution, AntiOS now includes a dedicated GUI-only MSIX packaging path. The Store signs accepted packages with Microsoft's trusted certificate.

For direct GitHub downloads, the release workflow supports optional Azure Artifact Signing. Once the repository is connected to an Artifact Signing account, both EXE files are Authenticode-signed and verified before the ZIP is built.

See [docs/SIGNING.md](docs/SIGNING.md) and [store/README.md](store/README.md).

Reserved Microsoft Store product: [AntiOS](https://apps.microsoft.com/detail/9P7V8BKW2KG9) (`9P7V8BKW2KG9`).

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
python -m pip install .\antios-2.0.0a12-py3-none-any.whl
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
pyinstaller --clean --noconfirm --onedir --contents-directory _cli --uac-admin --version-file release/windows-cli-version.txt --console --name AntiOS antios_entry.py
pyinstaller --clean --noconfirm --onedir --contents-directory _gui --uac-admin --version-file release/windows-gui-version.txt --windowed --name AntiOS-GUI antios_gui_entry.py
```

CI validates Windows/Linux Python matrices, CodeQL, wheel/sdist metadata, clean wheel installation, GUI entry points, both PyInstaller executables, smoke tests, release metadata and provenance attestations.

## License

The current AntiOS v2 source tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

The repository is historically a fork. Legacy v1 material remains in Git history only; Apache-2.0 for the current v2 rewrite does not retroactively relicense historical third-party material for which the v2 contributors do not hold the necessary rights.

See also [PRIVACY.md](PRIVACY.md), [SUPPORT.md](SUPPORT.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and [CHANGELOG.md](CHANGELOG.md).
