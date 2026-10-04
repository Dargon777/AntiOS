# AntiOS v2.0.0 alpha 16

Alpha 16 is mostly about making the antivirus side behave like an installed
product instead of a collection of pieces you have to assemble yourself.

## Protection is prepared by Setup

A normal `AntiOS-Setup.exe` install now bootstraps the managed ClamAV engine
automatically. AntiOS downloads the pinned official Windows x64 package, verifies
its SHA-256, requires valid matching Authenticode signatures on `clamd.exe` and
`freshclam.exe`, then installs the ClamD service and recurring FreshClam
signature updates.

When UAC is approved by the same Windows user who is currently logged in, Setup
also enables Resident Guard for Downloads, Desktop and Documents. If a different
administrator account was used for elevation, that per-user step is deferred
rather than being configured under the wrong profile.

There is also a new repair path:

```powershell
AntiOS.exe protection-repair
AntiOS.exe protection-repair --yes --update-signatures
```

It can restore the known service policy, protected ACLs and updater task, but
will refuse to take ownership of an ambiguous third-party ClamD service.

## Faster repeated scans

ClamD scans can now use four bounded parallel requests by default (up to eight).

AntiOS also caches clean results, but a cache hit is not trusted from timestamps
alone: the file is opened through the normal stable-file path and SHA-256 is
checked again before the repeat ClamD submission is skipped. Changing the file,
ClamAV/database identity or local signature set invalidates the old result.

## Safer recovery and updating

The Windows quarantine vault now removes inherited access and restricts itself to
the current user, SYSTEM and Administrators. `quarantine verify` checks every
stored item's authenticated payload and SHA-256 without restoring it.

AntiOS can now check GitHub releases and download a newer Setup. Automatic
installation is deliberately stricter: it requires a valid Authenticode
signature and re-checks both the file hash and signature immediately before
launching the installer.

Direct-download signing is **not enabled yet**, so `AntiOS.exe update --yes`
will currently refuse to auto-install an unsigned release. That is intentional;
`update` and `update --download-only` still work for discovery and
hash-verified downloads.

## Native protection work

The experimental minifilter remains outside the normal Setup. Its Windows VM
acceptance test now requires separate evidence for execute-open, real
`CreateProcess`, and `SEC_IMAGE` image-section mapping.

This is a stricter test, not a certification claim. Production deployment still
needs Microsoft-assigned minifilter altitude, signed-driver/Driver Verifier/HVCI
acceptance, and the external Windows antimalware integration gates.
