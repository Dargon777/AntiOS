# Independent on-demand scanning with ClamAV

AntiOS can now use ClamAV instead of Windows AMSI. This separates file detection
from Defender: ClamAV supplies its own engine, official signatures, archive and
file-format parsers. AntiOS supplies traversal, safe snapshot reads, reports,
manual quarantine and GUI cancellation. ClamAV is the default AntiOS scan path;
AMSI remains an explicit compatibility mode, with no silent fallback between
engines on failure. On Windows, ordinary AntiOS scans require the configured
trusted ClamD SCM peer before file bytes are sent.

This is **not Windows real-time protection**. There is no filesystem interception,
Windows Security Center registration, boot/memory protection or replacement for
Defender. Do not disable the installed resident antivirus. ClamAV's Linux
on-access component does not provide that capability on Windows.

## Windows managed-engine setup

For the production path, AntiOS no longer treats an arbitrary process listening
on TCP 3310 as a trusted resident engine. Use an official/reviewed x64 ClamAV
package, then let the included setup script create an administrator-controlled
runtime:

```powershell
.\protection-engine.ps1 -ClamAVDirectory "C:\staging\clamav-1.5.x.win.x64"
# review the preview, signer and destinations
.\protection-engine.ps1 -ClamAVDirectory "C:\staging\clamav-1.5.x.win.x64" -Apply
```

The script is preview-only unless `-Apply` is supplied. It does **not** disable
Defender and does not install the experimental AntiOS kernel filter. It:

1. refuses to overwrite another machine-wide ClamAV installation or existing
   `clamd` service;
2. rejects reparse points in the source tree and, by default, requires valid
   matching Authenticode signatures on `clamd.exe` and `freshclam.exe`;
3. copies the reviewed runtime to `%ProgramFiles%\AntiOS\ClamAV` under a
   protected ACL;
4. stores configuration, signatures and temporary files under
   `%ProgramData%\AntiOS-ClamAV` with SYSTEM/Administrators-only write access;
5. bootstraps the official signature database with FreshClam;
6. installs the ClamAV `clamd` own-process LocalSystem service, restricts its
   service-control ACL and configures automatic startup;
7. creates a SYSTEM scheduled task that checks for official signature updates
   every two hours; FreshClam notifies ClamD after an update;
8. writes the administrator-owned AntiOS engine-service binding used by both
   on-demand scans and Resident Guard to verify the server PID behind the exact
   loopback TCP connection.

Remove only this managed runtime with:

```powershell
.\protection-engine.ps1 -Uninstall       # preview
.\protection-engine.ps1 -Uninstall -Apply
```

The remover does not touch AntiOS quarantine or unrelated ClamAV installs.

If you manage ClamAV through enterprise tooling instead, configure an own-process
LocalSystem service and pass its SCM name explicitly to Guard with
`--engine-service`, set `ANTIOS_CLAMD_SERVICE`, or configure the documented
AntiOS registry binding. Ordinary on-demand CLI scanning may still connect to an
unverified loopback ClamD for diagnostics, but on Windows such a scan is reported
as **incomplete** and cannot become a clean resident-protection verdict.

Check the whole stack at any time:

```powershell
.\AntiOS.exe protection-status
.\AntiOS.exe protection-status --json
```

## Coverage and failure handling

- Content goes only to `127.0.0.1:3310`, using ClamD INSTREAM. File names are never
  passed as protocol commands. No file content is uploaded by this client.
  FreshClam separately contacts the official signature service.
- ClamD TCP itself is unauthenticated. For Windows resident protection, AntiOS
  queries the configured SCM service, requires a running own-process LocalSystem
  service, connects only to 127.0.0.1, and matches the **server side of that exact
  established TCP connection** to the service PID before sending commands or file
  bytes. The SCM PID is checked again before accepting the reply. If no trusted
  service binding exists, Windows coverage remains incomplete rather than clean.
  This protects against ordinary-user port impersonation; it is not a boundary
  against administrators or code injected into the trusted engine.
- Reports record the ClamAV version, database version/date and freshness status.
  A database older than seven days, an unknown date (including custom-only test
  databases) or a date over one day in the future cannot produce exit code 0.
  This check depends on the computer clock and daemon VERSION response. On the
  managed Windows path, process authenticity is checked separately against SCM
  ownership of the live connection.
- Keep `OfficialDatabaseOnly`, archive scanning and limit/encryption alerts from
  the provided configuration. AntiOS cannot inspect the daemon's effective
  configuration over this protocol. Disabled parsers/exclusions can reduce
  coverage without a protocol error. `clamav-and-signatures` means all selected
  input buffers were processed under the daemon's policy, not that every nested
  object was proven safe.
- Each request has a total 30-second deadline and a 4096-byte response cap.
  Protocol errors and timeouts produce incomplete coverage. After the first
  scan error, provider calls stop for that run; exact-hash scans continue.
- The GUI Stop button terminates its worker and preserves partial results. It
  does not kill the shared ClamD daemon; an already submitted buffer may finish
  there, bounded by the daemon's own limits.
- `Heuristics.*` and `PUA.*` detections are review items with limited coverage. Archive bombs
  and encrypted archives must not appear as ordinary malware eligible for
  quarantine. Normal threat detections keep their ClamAV signature labels.
- A detection result remains subject to false positives and false negatives.
  This integration is not an independent malware detection effectiveness audit.

## Validation

`tests/test_clamav.py` checks actual loopback protocol framing with inert fixtures,
fragmentation, malformed replies, byte limits, deadlines and database freshness.
`tests/test_clamav_integration.py` starts a real daemon with a benign custom rule,
checks detection inside a ZIP and confirms archive-limit review behavior. CI
requires the daemon for that integration job. Custom test rules are never shipped
as a production malware feed. The existing Windows workflows define GUI/DPAPI and frozen-package checks;
they have not yet run for this branch. A real Windows ClamD/official-database and
installed-MSIX acceptance test is still required before promoting this feature.

References: [protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html),
[signature updates](https://docs.clamav.net/manual/Usage/SignatureManagement.html),
[configuration](https://docs.clamav.net/manual/Usage/Configuration.html),
[scanning](https://docs.clamav.net/manual/Usage/Scanning.html).

## Branch validation

This production-core branch adds Windows SCM peer verification, managed engine
lifecycle, signature-update scheduling, Guard policy binding and aggregate
`protection-status`. GitHub CI remains the acceptance authority for the branch;
installed-service, official-database and native-driver VM tests are still required
before a public claim of primary real-time antivirus protection.
