# AntiOS v2.0.0 alpha 14

Alpha 14 replaces the manual ZIP-first Windows experience with a conventional installable application while keeping the portable package available.

## Windows Setup

- New single-file `AntiOS-Setup.exe` installer built with NSIS.
- Requests Administrator consent and installs AntiOS per-machine to `C:\Program Files\AntiOS` by default.
- Creates an AntiOS desktop shortcut automatically plus Start Menu shortcuts for the GUI, CLI and uninstaller.
- Registers AntiOS in Windows Installed Apps with publisher, version, icon, install location and quiet-uninstall metadata.
- Registers `AntiOS-GUI.exe` through Windows App Paths and stores the canonical install directory under `HKLM\Software\DargonITP\AntiOS`.
- Re-running a newer Setup reuses the registered installation directory and replaces the application payload in place.
- Existing Resident Guard is stopped before files are replaced.
- Uninstall stops Resident Guard, removes its startup task, removes shortcuts and application files, while deliberately preserving user settings/quarantine data outside Program Files.

## Release pipeline

- Release CI stages a deterministic installer payload from the same tested CLI, GUI and Guard builds used by the portable package.
- CI installs the generated Setup silently into an isolated directory, verifies the installed CLI/GUI, Windows registry entry and desktop shortcut, then runs the generated uninstaller and verifies cleanup.
- When Artifact Signing is enabled, application executables are signed before installer staging, then the finished Setup is signed separately.
- GitHub releases now publish `AntiOS-Setup.exe` and its SHA-256 checksum alongside the portable ZIP and Python distributions.

## Existing alpha 13 functionality

- Managed ClamAV remains the default antivirus path with verified Windows ClamD peer identity.
- Storage Cleanup retains explicit permanent deletion and SHA-256-verified backup-before-delete modes.
- Resident Guard, encrypted quarantine, health/privacy diagnostics and the experimental native boundary remain available as before.

## Safety and scope

The installer does not hide AntiOS, bypass Windows installation controls, disable Defender or silently enable system persistence. Its install location, shortcuts, uninstall registration and files are conventional and visible to the user. The experimental native driver remains outside the normal release package pending its separate production gates.
