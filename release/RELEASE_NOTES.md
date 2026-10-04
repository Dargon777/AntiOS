# AntiOS v2.0.0 alpha 15

Alpha 15 gives AntiOS its production-facing visual identity and wires protection state directly into the Windows tray.

## Branding

- The green primary AntiOS emblem is embedded into the CLI, GUI and Resident Guard executables.
- Desktop and Start Menu shortcuts inherit the primary green application icon.
- `AntiOS-Setup.exe` and the generated uninstaller use the same primary icon.
- The running AntiOS dashboard uses the dedicated red taskbar/window icon and a stable Windows AppUserModelID.
- Windows icon resources are generated as multi-size ICO files during CI for crisp shell rendering from 16 px through 256 px.

## Resident Guard tray status

- The frozen Windows Resident Guard now owns a system-tray icon while it is running.
- Green tray state means Guard is actively monitoring or scanning.
- Red tray state means protection is starting, needs attention, is degraded, failed or stopped.
- Tray state follows the Guard's real protection-state transitions rather than a separate cosmetic flag.
- Tray rendering is best-effort: any tray/backend failure is contained and never stops the protection loop.

## Packaging and validation

- Source PNG artwork is packaged with the Python distribution and explicitly bundled into the GUI/Guard PyInstaller payloads.
- Windows CI verifies generated ICO resources and checks that frozen runtime branding assets are present.
- The Setup build receives the generated primary ICO directly so installer branding cannot silently fall back to the NSIS default.

## Existing protection

Alpha 15 keeps the independent ClamAV default engine, verified ClamD service identity, Resident Guard, encrypted quarantine, actionable Storage Cleanup and the conventional machine-wide Windows Setup introduced in earlier alphas.
