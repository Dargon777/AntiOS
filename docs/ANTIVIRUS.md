# AntiOS antivirus — alpha 16

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
ClamAV x64 package. Before the engine is installed, AntiOS verifies the package
size and SHA-256 and the Authenticode signatures of `clamd.exe` and
`freshclam.exe`.

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

Automatic installation is stricter: `--yes` requires a **valid Authenticode
signature** immediately after download and re-checks both SHA-256 and
Authenticode again after the current AntiOS process exits, just before launching
Setup. Until release signing is enabled, automatic installation intentionally
refuses to run an unsigned Setup.

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
