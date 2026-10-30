# File baselines and recovery (experimental)

This addition is independently implemented. No Kaspersky code, signatures,
models, artwork or proprietary formats are included.

## Desktop interface

Open Antivirus → File recovery (Антивирус → Резервные копии). Add files/folders,
optionally include the small Windows core baseline, and create a new archive.
Open an existing archive to check it or extend it into a different archive.
The comparison table distinguishes changed, missing and unreadable files.

Opening an archive verifies the saved bytes and lists its contents without
accessing original file paths. Contents repeats that operation; Check changes
compares against current originals. Select rows with Ctrl/Shift and choose
Recover selected, or use Recover all. After recovery the table stays available.

Recovery creates a uniquely named new folder inside a chosen directory.
The UI keeps safe original basenames inside separate numbered subfolders, such
as `00003/report.txt`. Duplicate names cannot overwrite each other. Reserved
Windows device names, path separators, alternate-stream syntax, direction
controls and excessively long names are sanitized or replaced by `recovered.bin`.
`recovery-report.json` maps exported files to their source paths and checksums;
selected exports omit paths of unselected files. Executables may be recovered,
but are never launched. Scan copies before opening them.

The UI binds selection and baseline extension to the manifest it displayed. If
the archive manifest changes before recovery or extension, the operation fails
before creating a usable output. This detects a stale selection, not archive
authenticity: a malicious party
with write access can still replace an archive before it is first opened.
Original files remain untouched. The Russian and English interface uses a
background worker, bounded progress queues and a Cancel button. Closing a busy
window requests cancellation and waits for cleanup; it never invokes Tk from
the worker. Other app languages currently use the English recovery window.
Cancellation is cooperative between files; a blocked OS file operation may
delay it. No hard timeout or instant-cancellation guarantee is made.

## Commands

Run with Python 3.11 or later from the source checkout:

```powershell
python -m antios recovery create D:\Backups\baseline.zip C:\Users\Alice\Documents --system
python -m antios recovery extend D:\Backups\extended.zip C:\Users\Alice\Pictures --previous D:\Backups\baseline.zip
# Optional stale-baseline guard for scripted workflows:
python -m antios recovery extend D:\Backups\extended.zip C:\Users\Alice\Pictures --previous D:\Backups\baseline.zip --expected-previous-id <archive_id-from-list>
python -m antios recovery check D:\Backups\extended.zip
python -m antios recovery list D:\Backups\extended.zip
python -m antios recovery export D:\Backups\extended.zip D:\RecoveredFiles
python -m antios recovery export D:\Backups\extended.zip D:\SelectedFiles --entry 0 --entry 3 --named
```

Parent directories must already exist. The archive and export directory must
not exist. Outputs are JSON; exit 0 means completion, 1 means failure, and 2 means
incomplete capture or differences/unreadable files during checking.

Each snapshot contains bytes, SHA-256, original absolute path, size and original
modification time. `extend` copies the old baseline without accepting changes to
existing tracked paths; it adds newly selected files to a new archive. Previous
incomplete coverage stays visible. It does not modify the previous archive.

`check` verifies every saved blob before accessing any original path. It rejects
network/device namespaces and other non-local manifest paths before the first
original read, then reports unchanged, changed, missing and unreadable. It does
not find newly created files
in originally selected directories. An ordinary Windows update also changes
hashes. Changed does not mean infected, and unchanged does not mean safe.

`export` verifies all stored blobs before creating a fresh directory. The
legacy CLI default exports `0.bin`, `1.bin`, etc.; `--named` uses safe basenames
in numbered subfolders. Repeat `--entry` with zero-based indices from `list` to
recover a subset. Invalid, duplicate or empty explicit selections are rejected.
`recovery-report.json` lists only recovered files. Full legacy numbered exports
also include `manifest.json` for compatibility. No original directory path from
the archive is used as an export destination. Scan recovered
content and choose what to put back. The implementation deliberately provides
no automatic replacement of Windows files or running applications.

## Coverage and resource limits

`--system` selects seven Windows core files: explorer.exe, ntoskrnl.exe, ntdll.dll,
kernel32.dll, services.exe, lsass.exe and hosts. This is a small file-integrity
baseline, **not a complete system fingerprint, registry backup, boot recovery,
VSS snapshot or Windows image**. Missing/locked/oversized files are reported.

Limits: 32 MiB per file, 512 MiB total saved content, 10,000 visited entries and
10,000 stored files, 128 traversal levels, 8 MiB manifest, 1,000 reported errors.
ZIP input size and central-directory metadata are bounded before ZIP parsing;
ZIP64/multi-disk archives are unsupported. Failed output writes invalidate the
new archive. Cancellation removes the unfinished archive or files created by
that export call; cleanup failures remain visible as errors.
Files are processed serially, without compression or GPU requirements. A limit
on traversal or total size aborts capture and removes the new incomplete archive.
Per-file read failures produce explicitly partial archives. Performance on weak
PCs has not been benchmarked. These limits are unsuitable for full-disk backups.

Symlinks, junctions and other reparse points are rejected through the existing
scanner path validation. This is not a privileged service, and does not promise
protection against a concurrent hostile process replacing paths during use.

Backups are **unencrypted and unauthenticated**. A hash detects accidental
corruption, not an attacker replacing both bytes and manifest. They include
private file contents and absolute paths. Keep them on a separate, preferably
offline, medium with suitable access controls. Local writable backups can be
deleted or encrypted by ransomware. A baseline chosen on an infected system
can preserve malware. There is no claim that baseline creation proves cleanliness.
ACLs, alternate streams, sparse layout and original file times are not restored.

## Further protection work (not implemented here)

AntiOS already combines ClamAV, behavior correlation and RiskContext. An ML
score must remain advisory until separately validated; it must not expand
automatic quarantine eligibility or turn unavailable analysis into a clean verdict.

A next implementation needs a licensed, versioned model and feature extractor,
signed model delivery, strict input/output schema, time/memory limits and a
worker-process timeout. For broad CPU support, use a small CPU inference model
and disable optional analysis on unsupported machines while reporting that
coverage reduction. No GPU or continuous local training should be required.

Release gates: independent time-separated malware and benign evaluation sets,
measured false positives, detection recall by threat class, adversarial malformed
inputs, timeout/crash isolation, and measured CPU/RAM/disk latency on actual low-end
hardware. No trained model or universal threat-detection claim is supplied here.

Full recovery additionally needs coordinated Windows backup, version retention,
protected/offline storage, and tested recovery from outside a compromised OS.
VSS is a snapshot coordination mechanism, not by itself a ransomware-proof backup:
https://learn.microsoft.com/en-us/windows/win32/vss/about-the-volume-shadow-copy-service

## Legal boundary

General functionality may inform independent development. Copyright protects
expression rather than ideas; this is not blanket permission to reuse code,
models, databases, branding or patented inventions. Dependency/data licenses and
applicable patents require review for the intended distribution jurisdictions.
No guarantee of legal clearance is made.
https://www.wipo.int/en/web/copyright/activities/software
