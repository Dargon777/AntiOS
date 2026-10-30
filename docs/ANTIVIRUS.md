# AntiOS antivirus — alpha 27

AntiOS uses the managed **ClamAV** engine as its normal scan path. Windows AMSI
is kept as an explicit compatibility mode; AntiOS does not silently fall back
from one engine to the other.

The released Windows app combines:

- on-demand file/folder scanning;
- a managed ClamD service with official FreshClam database updates;
- Resident Guard for selected-folder post-write monitoring;
- encrypted quarantine;
- a separately deployed experimental native minifilter/broker for pre-execution
  enforcement research.

The native driver is not bundled into the normal Setup and AntiOS still does not
claim Windows Security Center primary-antivirus registration.

## Normal Windows setup

`AntiOS-Setup.exe` installs the app and then bootstraps the pinned official
ClamAV x64 package. AntiOS verifies the ZIP's exact size and SHA-256
against the version pinned in its own installer. The engine then re-verifies
the ZIP and compares extracted `clamd.exe` and `freshclam.exe` byte-for-byte
against their archived copies before executing them. Their SHA-256 fingerprints
are recorded in an ACL-protected `engine-trust.json` under the managed engine
directory, and checked again during repair. Modified binaries or a mismatched
receipt fail closed. This is **pinned artifact trust anchored in the authentic
AntiOS release**, not separate Cisco Talos GPG verification. The pinned digest
for ClamAV 1.5.4 matches Cisco Talos's official GitHub release metadata.

Arbitrary manually selected ClamAV directories still require valid, matching
Authenticode signatures. There is no general unsigned-executable bypass.
An official release ZIP can be authenticated without assuming every portable
PE inside it independently carries Authenticode. Future vendor key pinning,
GPG detached-signature verification, rollovers and real Windows service
acceptance are separate release gates.

The managed runtime is placed under `Program Files\AntiOS\ClamAV`. Databases,
configuration and temporary engine data live under
`ProgramData\AntiOS-ClamAV` with administrator/SYSTEM write access. FreshClam
runs at startup and every two hours.

On a normal UAC elevation where the elevated identity is the same interactive
user, Setup also enables Resident Guard for that user's Downloads, Desktop and
Documents folders. If different administrator credentials were supplied to UAC,
Guard setup is deliberately deferred instead of configuring the wrong account.

Check or repair the stack:

```powershell
AntiOS.exe protection-status
AntiOS.exe protection-repair
AntiOS.exe protection-repair --yes --update-signatures
```

A privileged repair snapshots the current ACLs on the installed engine and
database folders, the existing FreshClam scheduled-task XML, and ClamD's
startup mode/service DACL/description *before* changing them. If a subsequent
operation fails, AntiOS attempts to restore owned resources and remove a
newly created service/task; rollback refuses to touch a service or task whose
ownership cannot be confirmed. A rollback failure is reported and still leaves
the original repair operation unsuccessful. Windows may prevent recovery after
external concurrent changes, access denial or a crash, so **this is best-effort
rollback, not an atomic transaction**.

For a successful maintenance operation, the PowerShell JSON result contains
`maintenance_verified_after: true` only after independently re-reading SCM
service identity/running/autostart state and the FreshClam task executable.
This field does **not** imply active real-time protection: the dashboard/Guard
separately verify the ClamD loopback peer, signature database freshness and
actual scan readiness before showing a healthy state.

Repair resets the managed engine/data ACLs, ClamD service policy and FreshClam
scheduled task. It refuses to take over an ambiguous `clamd` service whose
account/path does not match the AntiOS-managed runtime.

## On-demand scanning

```powershell
AntiOS.exe virus-scan "C:\Users\Me\Downloads"
AntiOS.exe virus-scan "C:\Users\Me\Downloads" --workers 4
AntiOS.exe virus-scan "C:\Users\Me\Downloads" --no-cache
AntiOS.exe virus-scan sample.exe --engine amsi
```

ClamD scans use bounded concurrency: 4 workers by default and at most 8.
AMSI remains sequential.

Clean ClamAV results can be reused for unchanged files. Cache identity includes
the file identity/size/mtime, exact ClamAV database/version identity and local
signature set. A cache hit is **not** trusted from metadata alone: AntiOS
re-reads the file through its stable-file path and verifies SHA-256 before
skipping the repeat ClamD submission. Engine/database or signature changes
therefore invalidate old results automatically.

AntiOS never follows symlinks/junctions during a scan, reports inaccessible and
oversized inputs, and does not execute scanned files. The quarantine directory
is excluded from ordinary scans.

## Coverage and verdicts

A clean verdict requires complete provider coverage. AntiOS reports an
incomplete scan instead of "clean" when the engine is unavailable, databases are
stale/unknown, the verified Windows ClamD peer requirement fails, limits are
hit, files are skipped, or the scan is cancelled.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Complete provider coverage with no findings |
| 1 | Threat/review finding |
| 2 | Invalid input or command failure |
| 3 | No finding, but coverage was incomplete/limited |

ClamAV heuristic/PUA-style findings remain review items rather than automatic
quarantine decisions.

## Resident Guard

Resident Guard watches explicitly selected user folders and submits changed
files to the trusted managed ClamD service. It is post-write protection; it is
not equivalent to kernel pre-execution interception.

The tray state follows the actual Guard state. A tray failure is cosmetic and
cannot stop the protection loop.

The dashboard and its logon task run as the interactive user (asInvoker /
Limited), not permanently as administrator. Scanning and the user's DPAPI
quarantine therefore stay under that user's identity. A missing/damaged
machine-wide ClamD installation is **not** silently repaired during background
startup. Clicking Repair protection explicitly asks Windows to elevate the separate
installed AntiOS CLI for an allowlisted repair/bootstrap operation. The GUI
waits for its **real Windows process handle** and checks its exit code
(6-minute limit for repair, 20-minute limit for initial bootstrap). Even exit
code zero is not enough: the GUI independently re-reads verified ClamD and
database state and **does not start Guard or claim completion if this check
fails**. A timeout does not terminate the administrator's installation; the
result is explicitly unverified until the user refreshes protection status.
No elevated output or IPC data is trusted from user-writable files.

Automatic privileged repair from user-writable portable directories is not
supported. Before elevating the managed CLI, AntiOS additionally checks that
neither the executable nor the directory chain up to Program Files grants
unprivileged principals NTFS write/delete/ownership permissions. A missing or
unverifiable ACL fails closed; ordinary GUI monitoring remains usable.
The installer and command-line utility retain their privileged operations.
Re-register an older Highest logon task as Limited when reconciling
the startup preference.

Setup rejects an existing installation directory that is a junction or
reparse point, before running old lifecycle scripts. The Windows NSIS installer
now stages the **complete application payload** (including its new uninstaller)
under `_antios_next`, validates required entries, and only then stops the old
Guard and begins activation. For each known application file/directory, an old
item is renamed into `_antios_previous` before the new item is renamed into
place, on the same filesystem. On a detected activation failure, the installer
attempts to undo all completed moves. A failed preflight or extraction does
not replace any previous application file, and a failed activation cannot
register the new version. Neither the live `ClamAV` service directory nor
ProgramData or user DPAPI quarantine is part of the application-file swap.

This is **application-file rollback, not full atomic upgrade**. During the
sequence of renames there is a short mixed-version interval. A sudden power
loss, an inability to restore a locked file, or a failed post-activation engine
bootstrap can still leave a partially updated installation. On an incomplete
rollback the installer preserves `_antios_next` and `_antios_previous`
for manual recovery; the next upgrade refuses to overwrite them.
The installed service/task lifecycle and Windows registry are not yet covered
by a full transaction. Do not manually run executables from incomplete
installation trees. Full crash-safe recovery with authenticated old-version
fallback remains a separate release gate.

The NSIS uninstaller deletes only paths listed in a build-generated manifest of
the exact shipped application files. It checks the installed root and the
packaged subdirectories for Windows reparse points before running privileged
maintenance scripts. Runtime subdirectories are removed **without recursive
deletion**: unexpected files or user-added folders remain untouched. The
installation root is removed only if empty. Known Start Menu shortcuts are
removed individually rather than recursively deleting a possibly shared menu
folder. The managed ClamAV service and its data are handled by their dedicated
uninstall script; a failure there may leave managed files for investigation.
Current-user settings, history and DPAPI quarantine are not deleted by the
application uninstaller.

## Quarantine

Only a confirmed threat is eligible for quarantine.

The normal vault is current-user DPAPI protected. On Windows its directory ACL
is hardened to the current user, SYSTEM and Administrators with inherited access
removed. The encrypted record authenticates metadata and content together;
restore verifies the stored SHA-256 and never overwrites an existing path.

Verify the whole vault:

```powershell
AntiOS.exe quarantine verify
AntiOS.exe quarantine verify --json
```

A failed integrity check is reported and the item is not restored.

## AntiOS updates

```powershell
AntiOS.exe update
AntiOS.exe update --download-only
AntiOS.exe update --yes
```

Update discovery uses AntiOS GitHub releases. Downloaded Setup files are checked
against the release SHA-256 (and GitHub asset digest when present).

Installation is stricter: `--yes` requires a **valid Authenticode signature
from exactly the same signing certificate as the installed, signed AntiOS.exe**
in the registered Program Files installation directory. A valid but unrelated
publisher signature is insufficient. The dashboard can still *download* a
release without a verified local signer, but it never enables one-click installation.

The dashboard may check and download updates automatically, but **never installs
one without explicit confirmation**. After choosing Install update, it closes
and hands the installer to a fixed PowerShell command (not a writable .ps1 file
in the update cache). That command waits at most 120 seconds for AntiOS to exit
and then re-verifies SHA-256, Authenticode status and the exact certificate
thumbprint before launching Setup. During this final verification and execution,
a read-only open file handle prevents an ordinary same-user process from replacing
or rewriting the selected Setup file. Setup's actual exit code is checked.

**Signer rotation:** a new leaf certificate (including an automatically renewed
Trusted Signing certificate) is intentionally not accepted for silent/automatic
updates yet, even if issued to the same legal publisher. Manual, independently
verified signed installer upgrade is required before a new certificate becomes
the locally trusted reference. Unsigned developer/portable installations cannot
use unattended setup updates. A full transactional installer rollback is still
a separate release gate; this change does not claim to provide it.

## Native pre-execution boundary

The experimental Windows minifilter is kept outside the normal release package.
Its VM acceptance test now checks three separate paths with harmless lab
fixtures:

1. an execute-access open;
2. actual `CreateProcess`;
3. `SEC_IMAGE` image-section mapping.

Enforcement is not production-ready until the driver has a Microsoft-assigned
altitude, production signing, Driver Verifier/HVCI acceptance and the remaining
Windows antimalware integration/certification gates.

## Local signatures

AntiOS also supports an optional schema-1 SHA-256 list. The built-in list
contains only the inert EICAR test hash; it is not an independent malware feed.

```json
{
  "schema": 1,
  "sha256": {
    "64_HEXADECIMAL_CHARACTERS_HERE": "Detection label"
  }
}
```

## Default limits

- 32 MiB per file by default; CLI permits up to 256 MiB.
- 100,000 files by default; CLI permits up to 1,000,000.
- directory traversal is bounded separately;
- no symlink/junction traversal;
- no overwrite on quarantine restore.

ClamAV archive/file-format analysis is controlled by the managed ClamD
configuration. AntiOS does not claim boot-sector, memory or kernel scanning from
the Python scanner.


## Defender coexistence

AntiOS can run as an independent companion while Microsoft Defender remains
active. `protection-status` reads Defender state without modifying preferences,
then reports whether the current machine is actually in layered mode.

Resident Guard treats Windows sharing/lock violations as bounded transient
conflicts: it retries up to three times, while preserving file-identity
revalidation. Persistent conflicts remain visible as coverage errors. AntiOS
never adds Defender exclusions, never disables Defender and never fakes Windows
Security Center registration to obtain this behavior.

See [COEXISTENCE.md](COEXISTENCE.md) for the contract and failure model.
