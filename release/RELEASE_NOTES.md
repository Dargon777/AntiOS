# AntiOS v2.0.0 alpha 23

Alpha 23 is a Guard lifecycle hotfix for installed Windows builds.

## Guard state is now truthful

A stale Guard heartbeat marked as `unresponsive` is no longer treated as an
active running Guard by the Antivirus UI. The action changes back to
**Start Guard** instead of offering to stop a process that is already gone.

After AntiOS requests Resident Guard startup, it now verifies that the Guard
actually becomes active and starts publishing a live heartbeat. If startup does
not succeed, AntiOS reports a startup failure instead of leaving the UI in a
permanent `unresponsive` state.

## Stop/uninstall fix

The installed `guard-startup.ps1` no longer evaluates the default
`AntiOS-Guard.exe` path before processing `-Uninstall`. This fixes the
PowerShell `Join-Path` / empty `$PSScriptRoot` failure seen when disabling a
stale Resident Guard.

A Windows regression test now executes the uninstall path without
`-Executable` so this exact failure is covered by CI.

Microsoft Defender configuration is unchanged.
