# AntiOS v2.0.0 alpha 22

Alpha 22 fixes the installed resident-protection lifecycle and makes application
updates usable from the desktop UI.

## Resident protection starts with Windows

The Antivirus Guard control now manages the persistent per-user scheduled task
instead of launching a one-off folder monitor. When resident protection is
enabled, an installed AntiOS self-checks the managed ClamAV runtime at startup,
repairs a stopped or stale repairable engine, refreshes signatures when needed,
and restores the Resident Guard task.

Stopping Resident Guard from the Antivirus page now also disables its persistent
logon task. Starting it again recreates the task and starts protection
immediately. The advanced Antivirus panel also exposes an explicit
**Repair protection** action.

This remains layered companion protection: Microsoft Defender is not disabled or
reconfigured, and AntiOS still does not claim the primary Windows Security
Center antivirus slot.

## Desktop updater

Settings now contains an Updates section with:

- automatic GitHub release checking and download for installed builds;
- a manual **Check for updates** action;
- a manual **Download update** action;
- persistent automatic-update preference;
- a per-release local update cache.

Downloaded Setup files are checked against the release checksum and GitHub asset
digest. On Windows AntiOS also inspects Authenticode. Unattended installation is
scheduled only when the Setup signature is valid; unsigned builds may be
downloaded and verified but are not silently installed.

## Reliability

Alpha 22 adds regression coverage for persistent Resident Guard configuration,
resident preference persistence and repeated updater-cache downloads.
