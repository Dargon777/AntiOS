# AntiOS Guard: resident file monitoring

Guard is a separate, current-user process that checks selected directories as
files appear or change. It continues after the dashboard closes. It uses ClamAV,
not Defender. Set up the [local ClamAV daemon and FreshClam](CLAMAV.md) first.

**This is post-write detection, not prevention of file execution.** Guard does not
register as the primary antivirus in Windows Security. A file can execute before
its check completes, or appear and disappear between observations. Keep resident
Windows protection enabled. The gaps to a full replacement are tracked in
[DEFENDER_REPLACEMENT.md](DEFENDER_REPLACEMENT.md).

## Start, inspect and stop

In the portable dashboard select a **folder**, then **Watch folder**. The explicit
confirmation explains that the process continues after closing the window. The
GUI starts notification-only mode. Use **Stop Guard** to stop it and **Guard
history** to inspect detections, engine errors and quarantine events.

The CLI works independently of the dashboard:

```powershell
.\AntiOS-Guard.exe run "C:\Users\Me\Downloads"
.\AntiOS-Guard.exe status
.\AntiOS-Guard.exe history
.\AntiOS-Guard.exe stop
```

For a Python installation, use `antios guard ...` or `antios-guard ...`. The
companion EXE requests `asInvoker`, not administrator rights. Its `_guard`
directory must remain beside it. The main dashboard and advanced CLI retain
existing UAC behavior. The Store package currently contains only the dashboard;
its Guard start button is disabled when the companion is absent. Store support
requires a separate package and installed-Windows acceptance test.

Automatic encrypted quarantine requires a separate, explicit choice:

```powershell
.\AntiOS-Guard.exe run "C:\Users\Me\Downloads" --auto-quarantine
```

Only confirmed threat findings qualify. Heuristics, potentially unwanted apps,
encrypted content and archive-limit warnings remain review items. Quarantine
rechecks the file hash and identity and verifies its encrypted recovery copy
before removal. Files changed during detection or isolation are not silently
removed. Restore using the existing Quarantine page under the same Windows user.

## Opt-in startup on Windows

After obtaining a validly signed portable build, preview:

```powershell
.\guard-startup.ps1 -Roots "C:\Users\Me\Downloads" -Mode notify
```

Review the executable, certificate signer, scope and mode. Then repeat with
`-Apply`. The script registers a current-user logon task at **Limited** privilege,
starts it, and configures up to three restarts after failures. It does not create
a SYSTEM service, collect a password or change Defender settings. The task runs
only in that user's interactive session. ClamD and FreshClam still need their own
supported startup configuration; Guard reports their absence as degraded.

Use `-Mode quarantine -Apply` only if you want unattended isolation in the chosen
folders. Automatic startup refuses unsigned binaries. Manual development runs
remain available. This task is not protected against the same user or an
administrator stopping or modifying it.

Remove startup with `guard-startup.ps1 -Uninstall -Apply`. The normal uninstall
script first requests Guard shutdown, removes its task and then removes program
files. Quarantine and history stay in the user's data directory.

## What the monitor guarantees and reports

- Initial reconciliation includes existing files. Windows `ReadDirectoryChangesW`
  notifications identify changed paths; those files and their descendants lose
  cached results even if size and timestamps match. Each root has one outstanding
  asynchronous read and a 64 KiB buffer. Overflow, malformed records, ambiguous
  short names and a recovered notification handle force a root rescan. Overflow
  and ambiguous-record resynchronizations are counted and journaled. A failed watcher reports degraded
  coverage. Bounded periodic reconciliation remains; Linux uses that alone.
- Stable size, identity and the timestamps available from the filesystem are
  required for one second before checking. A new write notification restarts this
  settling period. Events received during a scan invalidate its cached result.
  Windows creation time is not treated as a reliable content-change counter.
- Successful results are reused for at most 15 minutes. A different ClamAV
  database/version invalidates the cache. Fingerprint caching is an optimization,
  not a boundary against an attacker preserving metadata.
- The queue holds at most 256 pending files by default. Each reconciliation
  allows 50,000 files and 100,000 entries; a larger scope reports degraded
  coverage. Admission rotates through the inventory so repeated invalidation of
  early entries does not starve later files. This is intended for folders such
  as Downloads, not an entire system drive.
- A scan runs in an isolated process with a total 45-second deadline. Stop
  requests terminate that worker. A blocked daemon request has its own timeout.
  Directory enumeration itself can still stall on a problematic filesystem;
  mapped network drives are not a supported deployment scope. Native watcher
  shutdown cancels pending I/O and waits for completion before freeing its
  buffers; a malfunctioning filesystem driver can also delay that completion.
- Engine errors stop further submissions until a subsequent health probe; a
  missing daemon is retried every 30 seconds. Database updates are performed by
  the official FreshClam process, not by downloading arbitrary rules in Guard.
- No overall `clean` or `fully protected` verdict is produced. States describe
  activity: `starting`, `scanning`, `monitoring`, `attention`, `degraded`,
  `stopped`, `failed`. Unknown/stale database age, unresolved scans and traversal
  limits prevent a normal monitoring status.
- Heartbeats identify an unresponsive process after 90 seconds. A forced task
  termination can leave its previous state visible until that threshold. This
  is a liveness indication, not tamper protection.
- A per-directory OS lock prevents duplicate Guard owners. Stop requests carry
  a run ID, so an old request cannot stop a restarted instance.
- The SQLite journal retains the last 1,000 events (the history command shows
  the newest 100). It contains local paths and detection labels, not submitted
  file content. It is local to `%LOCALAPPDATA%\AntiOS\Guard`. No telemetry is
  added. The state folder and quarantine are excluded from monitoring.

## Behavior correlation

Guard now includes a bounded **detection-only** correlation engine. On Windows it
uses a read-only Tool Help process snapshot collector alongside the existing
file-change watcher. The collector observes new process image/parent relationships
and correlates them with explicit file changes inside configured Guard roots.

Examples include Office/PDF or browser processes starting script interpreters,
a recently changed executable being launched, and mass changes to watched files.
A single executable launched from Downloads or user Temp is intentionally only a
low-score signal because legitimate installers commonly do that.

Behavior findings are written to the local Guard journal as `behavior-alert`
events and are summarized in Guard/protection status and the Antivirus UI. They
do **not** become ClamAV threat verdicts, do not trigger automatic quarantine,
do not terminate processes and do not claim pre-execution blocking. If process
sampling fails, Guard falls back to file-only behavior correlation and continues
normal antivirus scanning.

The complete rule IDs, scores, memory/time bounds and known visibility limits are
documented in [BEHAVIOR.md](BEHAVIOR.md).

After a completed scan, Guard fuses the scanner verdict, fresh path-specific
behavior evidence, file origin and cached native pre-execution state into an
explainable [RiskContext](RISK.md). Only confirmed scanner threats are eligible
for unattended quarantine.

## Verification scope

Tests cover new/existing/changed files, repeated writes, database-generation
changes, bounded queues, restart/stop isolation, journal limits, quarantine
opt-in, review-only outcomes, worker termination and behavior-correlation rules. Real ClamD integration uses
an inert custom rule and detects a newly created ZIP containing that marker.
This establishes functional behavior, not malware detection effectiveness.

Regression tests also cover changes preserving metadata, writes during scans,
notification overflow/failure, subtree invalidation, queue fairness during
repeated root rescans, malformed native buffers and async cancellation ownership.
Mocked native calls exercise those failure paths without claiming Windows API
acceptance. An active threat clears only after a subsequent complete benign
check (or removal from a fully enumerated scope); its historical event remains.

Windows-only tests exercise native directory notifications and handle cleanup.
The portable workflow builds all three EXEs, verifies manifests (Guard must be
`asInvoker`), checks Authenticode when signing is enabled, and tests each frozen
scan worker. These Windows checks must run before publishing this branch.

Recorded local validation (2026-10-03): Ubuntu 24.04, Python 3.12, Tk 9/Xvfb and
ClamAV 1.5.3: **234 tests passed**. Four native Windows tests are skipped here:
two notification tests, AMSI and DPAPI. Task Scheduler installation, Authenticode,
Windows packaging and installed-MSIX behavior remain unverified in this environment.
No new branch or release has been published to GitHub; the earlier remote-write
request was rejected. Stop Guard before replacing an existing installation.

Native API references: [directory change reads](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw),
[notification records](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-file_notify_information),
[I/O cancellation lifetime](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations).


## Defense-in-depth defaults

A normal same-user Setup selects Downloads, Desktop, Documents, the current user's
Temp directory and the current user's Startup folder when those directories exist.
Guard still scans every regular file admitted by those roots, but executable and
script-like extensions use a 200 ms settle cap so common execution boundaries reach
ClamAV earlier. Ordinary files keep the configured settle delay.

This fast path does **not** turn Guard into pre-execution prevention. Every scan is
revalidated against the file identity and a changing file is queued again. The
separately signed native minifilter remains AntiOS's only pre-execution blocking
path, and it must stay out of normal deployment until the documented Windows VM,
signing, altitude, Driver Verifier and HVCI gates pass.
