# AntiOS

AntiOS is being modernized.

The `v2-modernization` branch contains a new Python 3.11+ implementation focused on **auditable, reversible Windows privacy/system-lab workflows**. The original 2019 implementation remains at the repository root for historical reference.

> v2 is intentionally narrow: it does not implement anti-cheat, ban, licensing, hardware-serial, storage-serial or network-adapter identity bypasses.

## AntiOS v2

### Highlights

- read-only Windows inventory with `scan`;
- Windows 10/11 generation detection from the actual build number;
- edition, version, full build, architecture and processor reporting;
- read-only TPM and Secure Boot status;
- `doctor` checks with OK / INFO / NOTE / WARN results;
- human-readable output by default and `--json` for scripting;
- reversible `plan`, `backup`, `apply` and `restore` workflows;
- dry-run by default;
- Before/After tables for changes;
- restart markers for computer-name changes;
- computer rename through Windows `SetComputerNameExW`, not direct registry editing;
- strict mutable Registry allowlist;
- backup files treated as untrusted input during restore;
- TOML configuration;
- optional privacy-conscious file logging;
- Python tests across Windows/Linux on 3.11, 3.12 and 3.13;
- tested Windows portable `.exe` build via PyInstaller.

## Install from source

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Check the installation:

```powershell
antios version
antios doctor
```

## Portable Windows build

The `AntiOS v2 Windows portable` GitHub Actions workflow builds a single-file `AntiOS.exe`, runs the full test suite, then smoke-tests the executable itself.

The resulting artifact contains:

```text
AntiOS.exe
install.ps1
uninstall.ps1
README.md
```

A SHA-256 checksum file is produced alongside the ZIP.

For tag names matching `v2.*`, the workflow is prepared to create a GitHub release containing the ZIP and checksum. Merely merging the branch does **not** publish a release.

### Optional user-scope install

From the extracted portable ZIP:

```powershell
.\install.ps1
```

This copies `AntiOS.exe` to:

```text
%LOCALAPPDATA%\Programs\AntiOS
```

To also add that directory to your **user** PATH:

```powershell
.\install.ps1 -AddToPath
```

PATH is not changed unless `-AddToPath` is explicitly supplied.

Uninstall:

```powershell
.\uninstall.ps1
```

To also remove the directory from user PATH:

```powershell
.\uninstall.ps1 -RemoveFromPath
```

## Commands

### Version

```powershell
antios version
antios version --json
```

### Scan

Human-readable read-only system scan:

```powershell
antios scan
```

Machine-readable output:

```powershell
antios scan --json
```

The scan currently covers:

- computer name and current user;
- architecture and processor;
- Windows generation, product, edition, display version and full build;
- installation type and registered owner;
- Secure Boot;
- TPM present/ready/enabled/activated state, vendor and version;
- a documented set of Registry identity values in read-only mode.

### Doctor

```powershell
antios doctor
antios doctor --json
```

`doctor` also checks runtime compatibility and Registry-read failures. Informational/advisory findings do not make the command fail; actual warnings return a non-zero status for automation.

### Plan

Generate a proposed identity:

```powershell
antios plan
```

Specify values explicitly:

```powershell
antios plan --computer-name LAB-PC --registered-owner "Lab User"
```

### Apply

Preview only:

```powershell
antios apply
```

The default output is a Before/After table. No system values are written unless `--yes` is present.

Preview explicit values:

```powershell
antios apply --computer-name LAB-PC --registered-owner "Lab User"
```

JSON:

```powershell
antios apply --json
```

Real apply from an Administrator terminal:

```powershell
antios apply --yes
```

A backup is written **before** a real apply. Override its path with:

```powershell
antios apply --yes --backup .\backups\before-change.json
```

A computer-name change requires a Windows restart before every component observes the new name.

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

Real restore from an Administrator terminal:

```powershell
antios restore antios-backup.json --yes
```

Machine-readable preview/result:

```powershell
antios restore antios-backup.json --json
```

## Configuration

Show the effective configuration:

```powershell
antios config show
antios config show --json
```

Create the default config:

```powershell
antios config init
```

Overwrite it intentionally:

```powershell
antios config init --force
```

On Windows, the default location is:

```text
%APPDATA%\AntiOS\antios.toml
```

Example:

```toml
[general]
computer_name_prefix = "LAB"
backup_path = "antios-backup.json"
color = "auto" # auto | always | never

[logging]
level = "INFO"
file = "" # empty disables file logging
```

Use a different config for one invocation:

```powershell
antios --config .\lab.toml doctor
```

Disable ANSI colors:

```powershell
antios --no-color scan
```

The conventional `NO_COLOR` environment variable is also respected.

## Logging

File logging is off by default.

Enable it in config:

```toml
[logging]
level = "INFO"
file = "C:\\Temp\\antios.log"
```

Or for one command:

```powershell
antios --log-file .\antios.log doctor
```

The v2 logger records operational metadata such as command name, dry-run state, change count and backup path. It intentionally does **not** log generated identity values or scanned fingerprint values.

## Safety model

Registry writes are currently limited to:

- `RegisteredOwner`.

Computer renaming is handled separately through the supported Windows `SetComputerNameExW` API.

Read-only values such as `MachineGuid`, `ProductId`, Windows build data and the configured/active computer-name Registry values are inventory only.

Computer names are conservatively validated:

- letters, digits and hyphens only;
- no leading/trailing hyphen;
- not digits-only;
- maximum 15 characters in v2.

Backup restore does not trust arbitrary Registry paths from the backup JSON: only v2's explicit mutable allowlist can be restored.

## START_V2.bat

`START_V2.bat` performs:

1. `scan`
2. `doctor`

It makes no changes.

## Legacy v1 (2019)

The original scripts directly modify a much broader set of Windows/system identifiers and do not have the v2 safety guarantees.

If you are studying the old implementation, use a disposable VM.

Legacy entry point:

```powershell
python generate_fingerprint.py --help
```

## Development

Run tests:

```powershell
python -m pip install pytest
python -m pytest
```

Build the portable executable locally on Windows:

```powershell
python -m pip install pyinstaller
pyinstaller --clean --noconfirm --onefile --console --name AntiOS antios_entry.py
.\dist\AntiOS.exe version
```

## Licensing note

This repository is a fork of `vektort13/AntiOS`, and the upstream repository does not currently expose a recognized license through GitHub metadata. AntiOS v2 therefore does not claim a package license in `pyproject.toml`; licensing/provenance should be clarified before treating the repository as redistributable software.
