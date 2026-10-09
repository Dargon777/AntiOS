# AntiOS v2.0.0 alpha 27

Alpha 27 adds a proper Windows logon experience for the AntiOS Control Center and introduces the first validated hardened Windows build path.

## Control Center autostart

AntiOS can now start with Windows without opening a normal window on the desktop.

- a dedicated **AntiOS Control Center** Scheduled Task starts `AntiOS-GUI.exe --background` at the current user's logon;
- the task runs separately from Resident Guard, so disabling the Control Center startup does **not** disable resident protection;
- fresh installer deployments enable Control Center startup by default;
- upgrades preserve the user's existing choice instead of forcing startup back on;
- Settings now exposes **Start AntiOS with Windows (notification area)**;
- disabling the option unregisters only the Control Center task;
- uninstall removes the task cleanly;
- background startup hides the root window before UI construction, avoiding a visible startup flash;
- if the notification-area component cannot start, AntiOS falls back to showing the normal window instead of disappearing.

Unsigned alpha builds may register startup only when the executable is the machine-installed AntiOS-GUI.exe in a protected install directory. Signed builds use normal Authenticode validation.

## Code hardening groundwork

A parallel Windows build now compiles AntiOS CLI, GUI and Resident Guard with Nuitka standalone, MSVC and LTO.

CI verifies that the hardened binaries:

- build successfully on Windows;
- start the CLI, GUI and Guard;
- contain no loose AntiOS `.py` or `.pyc` files;
- retain Windows metadata and package resources;
- produce a SHA-256 hardening manifest.

This hardened path is intentionally kept parallel to the established release pipeline for now. It raises reverse-engineering cost but is not described as encryption or absolute secrecy.

## Open-core boundary

The public AntiOS v2 tree remains Apache-2.0. Already published source cannot be made secret retroactively.

Future proprietary technology such as CBF scoring, Business/EDR fleet correlation, commercial policy and cloud-side logic should live outside the public source tree behind a narrow signed interface.

## Compatibility

Windows 10 22H2 x64 (build 19045) and newer Windows 11 builds remain the supported desktop target.
