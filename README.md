# AntiOS

AntiOS is being modernized.

## AntiOS v2 (recommended)

The `v2-modernization` branch contains a new Python 3.11+ implementation focused on **auditable, reversible Windows privacy/system-lab workflows**.

The original 2019 code is still present at the repository root for historical reference, but it directly edits a large set of Windows identifiers and does not create backups. It is **not** the recommended entry point on modern Windows.

### What v2 does

- reads a documented set of Windows identity metadata with `scan`;
- detects Windows 10/11 from the actual build number and reports edition/version/build;
- reports architecture, processor, TPM state and Secure Boot state in read-only mode;
- includes `doctor` with OK/info/advisory/warning checks;
- prints human-readable reports by default, with `--json` for scripting;
- generates a small reversible metadata plan with `plan`;
- shows a Before/After change table before `apply` and `restore`;
- defaults all writes to **dry-run**;
- creates a backup immediately before a real `apply`;
- changes the computer name through the supported Windows `SetComputerNameExW` API rather than direct registry edits;
- restores only an explicit allowlist of v2-managed registry values plus the backed-up computer name;
- refuses to modify read-only identifiers such as `MachineGuid` and `ProductId`;
- tests the core logic without requiring a real registry;
- runs CI on Python 3.11, 3.12 and 3.13 on Windows and Linux.

AntiOS v2 intentionally does **not** implement anti-cheat, ban, licensing, hardware-serial, storage-serial or network-adapter identity bypasses.

### Install for development

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

### Commands

Human-readable, read-only system scan:

```powershell
antios scan
```

Machine-readable scan:

```powershell
antios scan --json
```

Run diagnostics:

```powershell
antios doctor
```

Machine-readable diagnostics:

```powershell
antios doctor --json
```

The scan/doctor flow currently covers:

- host/user/architecture/processor;
- Windows generation, product, edition, display version and full build;
- installation type and registered owner;
- Secure Boot state;
- TPM present/ready/enabled/activated state, vendor and version;
- a documented set of registry identity values in read-only mode;
- Python/runtime compatibility and registry-read warnings.

Generate a proposed metadata identity:

```powershell
antios plan
```

Preview changes (no writes):

```powershell
antios apply
```

The default output is a compact Before/After table. Computer-name changes are marked as requiring a Windows restart.

Preview explicit values:

```powershell
antios apply --computer-name LAB-PC --registered-owner "Lab User"
```

Use JSON output when scripting:

```powershell
antios apply --json
```

Apply for real (Administrator terminal required). A backup is written first:

```powershell
antios apply --yes --backup antios-backup.json
```

Preview a restore:

```powershell
antios restore antios-backup.json
```

Restore for real:

```powershell
antios restore antios-backup.json --yes
```

Use `--json` on restore for machine-readable output.

You can also run `START_V2.bat`; it performs a read-only scan and doctor check and makes no changes.

## Safety model

v2 uses a hardcoded mutable allowlist. Backup files are treated as untrusted input: `restore` ignores registry paths that are not part of that allowlist. This prevents a crafted backup file from turning the restore command into arbitrary registry writes.

The currently writable state is intentionally narrow:

- `RegisteredOwner` through the Windows Registry;
- computer name through the Windows `SetComputerNameExW` API.

Computer names are validated conservatively (letters, digits and hyphens, maximum 15 characters in v2). A rename is staged by Windows and requires a restart before all components observe the new name.

Other identifiers can be displayed by `scan` but are read-only from v2.

## Legacy v1 (2019)

The original scripts require an old Windows/Python environment and directly change many registry/system identifiers, including build metadata, product IDs, telemetry IDs, MAC/volume-related data and GUIDs.

If you are studying the old implementation, use a disposable VM. It does not have the v2 backup/restore guarantees.

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
