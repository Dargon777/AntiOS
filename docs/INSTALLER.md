# AntiOS Windows Setup

The normal Windows install is a single `AntiOS-Setup.exe`.

Setup installs AntiOS to `C:\Program Files\AntiOS`, creates the desktop and
Start Menu shortcuts, registers the app in Windows Installed Apps, and then
prepares the managed antivirus engine.

## Protection bootstrap

On a normal install, Setup uses the pinned ClamAV Windows x64 manifest shipped
with AntiOS. It downloads the official package, verifies its expected size and
SHA-256, and the lower-level engine installer requires valid matching
Authenticode signatures on `clamd.exe` and `freshclam.exe`.

The managed engine is installed under:

```text
C:\Program Files\AntiOS\ClamAV
```

Its databases/configuration live under:

```text
C:\ProgramData\AntiOS-ClamAV
```

ClamD runs as an own-process LocalSystem service. FreshClam runs at startup and
every two hours.

If the engine is already managed by AntiOS, an application upgrade repairs the
known service/ACL/task state and refreshes signatures instead of downloading the
full ClamAV package again.

A failed network/bootstrap step does not roll back the application install.
AntiOS records the bootstrap exit code so `protection-status` can surface the
problem, and the user can run:

```powershell
AntiOS.exe protection-repair --yes --update-signatures
```

## Resident Guard first run

After a successful engine bootstrap, Setup enables Guard for Downloads, Desktop
and Documents when the elevated UAC identity is the same as the active
interactive Windows user.

If another administrator account was used for UAC, Guard setup is deliberately
deferred. This avoids creating a per-user scheduled task and policy under the
wrong profile.

## Upgrades

Setup reuses the registered AntiOS installation directory, stops an existing
Guard before replacing files, then updates the same installation.

The legacy per-user PowerShell install under
`%LOCALAPPDATA%\Programs\AntiOS` is not silently migrated.

## Uninstall

Uninstall stops/removes Resident Guard startup, removes the AntiOS-managed ClamD
service/FreshClam task/runtime, then removes the application files, shortcuts and
machine registration.

Per-user AntiOS settings and quarantine are deliberately preserved.

## CI mode

`/NOENGINE=1` skips engine bootstrap. It exists for packaging/install smoke
tests and controlled development; it is not the normal user install path.

Release CI uses that switch so every pull request does not download the large
official ClamAV package. The bootstrap script itself is syntax-checked and its
pinned manifest/preview output is validated separately.

The full official-package install/update/removal path belongs in an elevated
Windows acceptance run because it creates real services and scheduled tasks.
