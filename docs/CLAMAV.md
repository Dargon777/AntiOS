# Managed ClamAV engine

ClamAV is AntiOS's default independent content-scanning engine. It supplies its
own signatures, archive/file-format parsers and daemon; AntiOS supplies safe
file traversal, verified local transport, reports, Resident Guard and quarantine.

AMSI remains an explicit compatibility mode. AntiOS does not silently fall back
to another engine when ClamAV fails.

## Setup path

Normal users no longer need to stage ClamAV manually. `AntiOS-Setup.exe`
bootstraps the pinned official Windows x64 package after installing AntiOS.

Alpha 16 pins:

- ClamAV 1.5.4 x64;
- the official Cisco-Talos GitHub release URL;
- package size;
- SHA-256
  `0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395`.

Before installation, the bootstrap checks the package hash and then
`protection-engine.ps1` requires valid matching Authenticode signatures on
`clamd.exe` and `freshclam.exe`.

The engine is installed to:

```text
C:\Program Files\AntiOS\ClamAV
```

Configuration, databases and temporary data are stored under:

```text
C:\ProgramData\AntiOS-ClamAV
```

The data tree is writable only by SYSTEM/Administrators. ClamD runs as an
own-process LocalSystem service. FreshClam is a SYSTEM scheduled task that runs
at startup and every two hours.

The bootstrap does not disable Defender and does not install the experimental
AntiOS kernel filter.

## Manual/bootstrap commands

Preview the pinned package:

```powershell
.\protection-bootstrap.ps1 -Json
```

Install it:

```powershell
.\protection-bootstrap.ps1 -Apply
```

A reviewed local copy of the exact pinned ZIP can be used instead:

```powershell
.\protection-bootstrap.ps1 -PackagePath C:\staging\clamav-1.5.4.win.x64.zip -Apply
```

The local archive is still required to match the pinned size and SHA-256.

The lower-level engine installer remains available for development/enterprise
staging:

```powershell
.\protection-engine.ps1 -ClamAVDirectory C:\staging\clamav-1.5.4.win.x64
.\protection-engine.ps1 -ClamAVDirectory C:\staging\clamav-1.5.4.win.x64 -Apply
```

## Repair

```powershell
AntiOS.exe protection-repair
AntiOS.exe protection-repair --yes
AntiOS.exe protection-repair --yes --update-signatures
```

Repair can restore the known AntiOS ACLs, automatic ClamD service policy and
FreshClam task, and can refresh signatures. It refuses to "repair" an existing
service if its account, service type or executable path indicates that it is not
the AntiOS-managed ClamD instance.

## Trusted loopback peer

ClamD TCP has no protocol authentication. On Windows, normal AntiOS protection
therefore does more than connect to `127.0.0.1:3310`.

For every trusted request AntiOS:

1. resolves the configured ClamD SCM service;
2. requires an own-process LocalSystem service;
3. reads its PID;
4. connects only to loopback;
5. verifies that the server side of that exact established TCP connection
   belongs to the expected service PID;
6. checks that the service PID did not change before accepting the reply.

If this identity check is required and cannot be proven, AntiOS reports
incomplete coverage instead of a clean verdict.

This is a boundary against ordinary-user port impersonation. It is not intended
to defend against an administrator or code already injected into the trusted
engine process.

## Database freshness

The ClamD VERSION response is recorded in scan reports. A database older than
seven days, an unknown date, or a date more than one day in the future cannot
produce a complete clean verdict.

FreshClam contacts the official ClamAV update infrastructure independently of
the local scanning connection.

## Scanning and cache

AntiOS sends content using ClamD INSTREAM; it never tells ClamD to open or
delete the original path.

Alpha 16 uses up to four concurrent ClamD requests by default, bounded to eight.
Each request still has its own socket and deadline.

The clean-file cache is versioned by file identity, the exact ClamAV
version/database identity and the local signature set. Metadata is only a cache
lookup hint: a hit is re-read and SHA-256 verified before the repeat ClamD
submission is skipped.

## Real-time scope

ClamAV itself does not provide a Windows file-system interception layer for
AntiOS.

Resident Guard adds selected-folder **post-write** scanning.

The separate experimental AntiOS minifilter/native broker can enforce before
execution in a lab deployment, but it is not part of the normal Setup and is
not yet a production/certified Windows primary-antivirus path.

## Validation

CI covers protocol framing, deadlines, malformed responses, archive behavior,
database freshness, Windows service/PID binding, packaging and the Python scan
cache.

The native filter remains subject to separate Windows VM acceptance, including
real `CreateProcess` and `SEC_IMAGE` mapping tests, Driver Verifier/HVCI,
production driver signing and a Microsoft-assigned minifilter altitude.
