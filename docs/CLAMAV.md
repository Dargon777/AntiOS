# Independent on-demand scanning with ClamAV

AntiOS can now use ClamAV instead of Windows AMSI. This separates file detection
from Defender: ClamAV supplies its own engine, official signatures, archive and
file-format parsers. AntiOS supplies traversal, safe snapshot reads, reports,
manual quarantine and GUI cancellation. The default remains AMSI; selection is
explicit, with no silent switch to a different engine on failure.

This is **not Windows real-time protection**. There is no filesystem interception,
Windows Security Center registration, boot/memory protection or replacement for
Defender. Do not disable the installed resident antivirus. ClamAV's Linux
on-access component does not provide that capability on Windows.

## Windows setup

1. Install a supported x64 release from [ClamAV](https://www.clamav.net/downloads).
   Use its documented installation procedure. ClamAV is a separate installation,
   not bundled with AntiOS, the PyInstaller ZIP or the Store MSIX.
2. In an administrator-managed location create
   `C:\ProgramData\AntiOS-ClamAV\database` and `C:\ProgramData\AntiOS-ClamAV\tmp`.
   Permit writes only to administrators and the account running ClamAV. Keep
   binaries and configuration protected too. Avoid Downloads as an install path.
3. Copy [clamd.conf.example](../config/clamav/clamd.conf.example) and
   [freshclam.conf.example](../config/clamav/freshclam.conf.example) into the
   ClamAV installation as `clamd.conf` and `freshclam.conf`. Review paths against
   the installed version's examples. Do not add path exclusions or `VirusEvent`
   hooks; AntiOS expects read-only detection. Do not expose port 3310 to the LAN.
4. From the ClamAV installation run the official updater:

   ```powershell
   .\freshclam.exe --config-file=.\freshclam.conf
   if ($LASTEXITCODE -ne 0) { throw "ClamAV database update failed" }
   .\clamd.exe --config-file=.\clamd.conf
   ```

   Leave this daemon running. In another terminal, keep automatic updates
   running with `freshclam.exe --daemon --config-file=.\freshclam.conf`.
   Arrange startup of these processes using the supported deployment mechanism
   for your ClamAV distribution. AntiOS does not install a Windows service.
   ClamD checks for database changes every ten minutes with this example config.
5. In AntiOS Antivirus choose **clamav**, then select and scan a file or folder.
   Or use:

   ```powershell
   .\AntiOS.exe virus-scan "C:\Users\Me\Downloads" --engine clamav --json
   .\AntiOS.exe quarantine add "C:\Users\Me\Downloads\sample.exe" --engine clamav
   ```

   Quarantine previews until `--yes` is supplied. Only confirmed threat findings
   qualify; heuristic or encrypted-content warnings do not.

## Coverage and failure handling

- Content goes only to `127.0.0.1:3310`, using ClamD INSTREAM. File names are never
  passed as protocol commands. No file content is uploaded by this client.
  FreshClam separately contacts the official signature service.
- TCP is unauthenticated, even on loopback. A compromised local account can
  interfere with the daemon. This transport is not a tamper-protection boundary.
- Reports record the ClamAV version, database version/date and freshness status.
  A database older than seven days, an unknown date (including custom-only test
  databases) or a date over one day in the future cannot produce exit code 0.
  This check depends on the computer clock and daemon VERSION response; it does
  not attest to the authenticity of the running process.
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

## Recorded local validation (2026-10-03)

- Ubuntu 24.04, Python 3.12.14, ClamAV 1.5.3, Tk 9.0 under Xvfb.
- Full suite: **184 passed, 2 skipped**. The skips are native Windows AMSI and DPAPI.
- Real ClamD detected an inert custom signature in plain text and inside a ZIP;
  the archive expansion limit produced a review finding and limited coverage.
- GUI checks cover all seven locales, theme rebuild during a scan, engine
  selection, cancellation and visible results/actions at 960 x 650. Long
  settings scroll independently of the result table and scan/stop buttons.
- Windows ClamD, official database downloads, installed MSIX and Windows frozen
  packaging remain release acceptance gates. No detection-rate claim follows
  from these functional tests.
- Changes are local: the GitHub tree-creation request was rejected before a
  branch or PR could be published. No new CI run was started.
