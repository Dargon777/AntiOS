# AntiOS Windows Setup

AntiOS alpha 14 adds a conventional machine-wide Windows installer.

## User flow

1. Download `AntiOS-Setup.exe` from the GitHub release.
2. Run it and approve the Windows UAC prompt.
3. Setup installs AntiOS to `C:\Program Files\AntiOS` by default.
4. AntiOS is available from the desktop and Start Menu.
5. Remove it later from **Settings > Apps > Installed apps** or from the Start Menu uninstall shortcut.

The portable ZIP remains available for testing and development, but normal users should use Setup.

## Installed layout

The installer deploys the same tested onedir builds used by the portable release:

- `AntiOS-GUI.exe` and `_gui`
- `AntiOS.exe` and `_cli`
- `AntiOS-Guard.exe` and `_guard`
- Guard/protection management PowerShell scripts
- ClamAV configuration templates
- project documentation and license files

User settings, quarantine and other per-user state are not stored in Program Files and are intentionally preserved by a normal uninstall.

## Windows integration

Setup writes the canonical install location to:

`HKLM\Software\DargonITP\AntiOS`

It also registers `AntiOS-GUI.exe` with Windows App Paths and creates a normal uninstall entry under the Windows uninstall registry.

Desktop and Start Menu shortcuts are machine-wide so the install remains visible and usable regardless of which administrator credentials satisfied UAC.

## Upgrades

The installer uses the registered install directory when an existing AntiOS installation is found. It requests Resident Guard shutdown before replacing files, then installs the new payload in place.

The current installer does not silently migrate the older per-user PowerShell installation under `%LOCALAPPDATA%\Programs\AntiOS`. That legacy path can be removed with its matching `uninstall.ps1` after the new Setup installation is verified.

## Uninstall

The generated uninstaller:

- stops Resident Guard if present;
- removes its configured startup task;
- removes AntiOS application files;
- removes desktop and Start Menu shortcuts;
- removes machine-wide install/App Paths/uninstall registry entries.

It intentionally does not purge per-user settings or quarantine data.

## Release validation

Windows CI compiles Setup with NSIS and performs an isolated silent installation. The job verifies:

- GUI, CLI, Guard and generated uninstaller exist;
- Windows stores the expected install directory;
- the common desktop shortcut exists;
- installed CLI and GUI self-tests execute;
- silent uninstall removes application files and the desktop shortcut.

When repository Artifact Signing is enabled, the application executables are signed before installer staging and the completed Setup is signed separately.
