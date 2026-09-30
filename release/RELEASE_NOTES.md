# AntiOS v2.0.0 alpha 3

Alpha 3 turns AntiOS from a mostly technical CLI into a more approachable Windows Health & Privacy utility.

## New for everyday users

- New **AntiOS-GUI.exe** desktop dashboard.
- One-click read-only health/privacy overview.
- Friendly **Quick Check** with OK / Review / Warning states.
- Microsoft Defender and real-time protection status.
- BitLocker/device-encryption status.
- Storage free-space check.
- Pending-restart detection.
- Startup application inventory.
- Secure Boot and TPM overview.
- Buttons that open the relevant Windows Security, Startup Apps and Storage settings pages.
- JSON report export from the GUI.
- Start Menu shortcut created by the installer.
- Optional desktop shortcut.
- New CLI command: `antios quick-check` (alias: `antios check`).
- New installed GUI command: `antios-gui`.

## Safety

The new dashboard is read-only. It does not expose system-changing actions.

Advanced identity changes remain in the CLI and keep the existing dry-run, backup and allowlist safeguards.

AntiOS v2 still does not provide anti-cheat, ban, licensing, hardware/storage serial, MAC/network identity, telemetry/update-ID or similar bypass functionality.

## Distribution

The release contains:

- `AntiOS-GUI.exe` — recommended for most users;
- `AntiOS.exe` — advanced CLI;
- installer/uninstaller PowerShell helpers;
- Python wheel and source distribution;
- Apache-2.0 LICENSE and NOTICE;
- SHA-256 checksum;
- GitHub provenance attestations.

## Windows warning

The executables are not Authenticode-signed yet, so Windows SmartScreen may show an unknown-publisher warning. Verify the published checksum and GitHub provenance if desired.
