# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md) · [Suomi](README.fi.md) · [Polski](README.pl.md) · [Монгол](README.mn.md)

**Resident protection, independent antivirus scanning, encrypted quarantine and Windows Health diagnostics.**

**Supported Windows target:** Windows 10 22H2 x64 (build 19045) and newer Windows 11 builds. Older Windows 10 releases and 32-bit Windows are unsupported.

AntiOS answers one simple question first: **does anything on this Windows PC need attention?**

> **Pre-release:** 2.0.0 alpha 27

[![Tests](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/python-v2.yml)
[![Windows portable](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/windows-release.yml)
[![CodeQL](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dargon777/AntiOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Download

**Recommended for most people:** download **`AntiOS-Setup.exe`** from the latest release and run it.

https://github.com/Dargon777/AntiOS/releases

Setup requests Administrator consent, installs AntiOS to **`C:\\Program Files\\AntiOS`**, and now prepares the managed ClamAV service and signature updater automatically. On a normal same-user UAC install it also enables Resident Guard for common user folders. The ZIP remains a portable/developer fallback.

## Antivirus

Open **Antivirus** from the sidebar or press `Ctrl+6`:

- Scan a selected file or folder without changing its contents.
- AntiOS uses its managed ClamAV engine automatically; provider details, local signatures and Defender compatibility tools stay under Advanced.
- Inspect detections, skipped files, access errors and incomplete coverage.
- Encrypt and isolate a selected detection in current-user Windows DPAPI quarantine.
- Restore selected quarantined items without overwriting existing files.
- Run Defender quick/full scans or update its signatures after confirmation.
- Run in a documented [layered coexistence mode](docs/COEXISTENCE.md): Defender stays configured as-is while AntiOS remains an independent companion layer.
- The Windows native tree includes a signed-gated x64 AMSI companion provider so AntiOS can add an independent AMSI scanning layer without claiming the primary Windows antivirus slot.
- Export a JSON scan report.
- Explore the separate [experimental native Windows filter/service](native/README.md); source and lab tooling only, not part of the release package.
- Run the optional [resident Guard](docs/GUARD.md) for automatic post-write checks in selected folders, with explicit opt-in quarantine.
- On a same-user Setup, Guard now covers Downloads, Desktop, Documents, the user Temp directory and the user Startup folder; executable/script-like writes use a short 200 ms settle path and are still revalidated if they continue changing.
- Guard also includes a bounded, detection-only [behavior correlation layer](docs/BEHAVIOR.md): it correlates watched file changes with new Windows process starts, suspicious parent→interpreter chains, recent-write→execution transitions and mass file changes. Behavioral signals are journaled and shown in the Antivirus UI, but never quarantine files or terminate processes on their own.
- A separate explainable [RiskContext fusion layer](docs/RISK.md) combines scanner verdict, fresh path-specific behavior, file origin and native pre-execution state. Only a confirmed scanner threat is eligible for automatic enforcement; behavior/origin alone remain review-only.
- A bounded [Incident Graph](docs/INCIDENTS.md) connects related writes, process ancestry, behavior findings and RiskContext verdicts into one local attack chain. Ordinary process starts do not create incidents, and the graph never expands automatic enforcement.
- The Antivirus page includes a structured [Incident Viewer](docs/INCIDENT_VIEWER.md) that deduplicates recent incident snapshots and renders the selected graph as a causal tree with node evidence instead of a raw JSON popup.
- Incident Viewer includes a conservative [Response Center](docs/INCIDENT_RESPONSE.md): rescan linked files, open their location, export a local report, and isolate only freshly confirmed scanner threats after explicit confirmation and quarantine revalidation.

The current production-core work includes independent ClamAV detection, encrypted quarantine, an optional post-write Resident Guard with bounded behavior correlation and incident graphs, a managed ClamAV service/update lifecycle, verified Windows service ownership for the ClamD loopback peer, and an experimental native execute-open minifilter. It is **not yet a certified primary Windows antivirus replacement**; see the [readiness gates](docs/DEFENDER_REPLACEMENT.md). AntiOS does not disable Defender or fake Windows Security registration. The built-in local database contains only the EICAR test hash; [ClamAV integration](docs/CLAMAV.md) supplies independent official signatures and archive/file-format analysis. Default limits are 32 MiB per file and 100,000 files, with skipped files and failed provider calls explicitly reported.

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
- explicit multi-select cleanup with permanent deletion or a verified backup-before-delete workflow.

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

For normal Windows installation, run:

```text
AntiOS-Setup.exe
```

The installer uses a stable machine-wide location:

```text
C:\Program Files\AntiOS
```

It creates **AntiOS** on the desktop, adds Start Menu shortcuts, registers the install location with Windows, and appears in **Settings → Apps → Installed apps** with a standard uninstaller. Running a newer AntiOS Setup upgrades the same installation directory.

The ZIP release is kept as a portable/developer fallback and still includes the PowerShell install helpers. See [docs/INSTALLER.md](docs/INSTALLER.md) for the installer layout and upgrade/uninstall behavior.

Protection is prepared automatically by Setup. Useful checks:

```powershell
.\AntiOS.exe protection-status
.\AntiOS.exe protection-repair
.\AntiOS.exe protection-repair --yes --update-signatures
```

The lower-level ClamAV scripts remain available for development and managed deployments.

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

antios coexistence-status
antios coexistence-status --json
```

Check for an AntiOS update:

```powershell
antios update
antios update --download-only
```

Automatic update installation requires a valid Authenticode-signed Setup. Until direct-download signing is enabled, AntiOS intentionally refuses `antios update --yes`.

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

Health checks and Storage Cleanup scans are read-only. Storage Cleanup deletion, antivirus quarantine/restore and Defender actions are explicit write operations that require confirmation. The antivirus does not change exclusions or disable any protection setting.

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
python -m pip install .\antios-2.0.0a27-py3-none-any.whl
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
