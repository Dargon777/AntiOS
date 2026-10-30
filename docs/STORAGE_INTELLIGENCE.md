# Lightweight Storage Intelligence (experimental)

AntiOS keeps the Storage Cleanup screen useful on old machines. The features
below are opt-in, on-demand, local and deliberately bounded. They do not
replace antivirus, backups or a human decision to keep files.

## Components

- **LastCopy**: reports whether another *independent* file with the same SHA-256
  was found within a completed scan. Other folders, offline disks, cloud
  backups and items excluded by scan limits are unknown. Hard links never count
  as independent copies. Unknown does **not** mean the last copy in existence.
- **MemoryMap**: stores one aggregate measurement per scanned root per UTC day,
  at most 180 days and 32 roots. The DB stores a SHA-256 root identifier, not
  the cleartext root path. This is pseudonymization, **not encryption**.
- **TimeDebt**: after at least three daily samples spanning seven days, presents
  an experimental median growth trend for the *selected folder*. Not a
  whole-drive forecast, not a promise that growth will continue.
- **CleanupDNA**: explicit prefer/hide/normal preferences per cleanup category.
  Confirmed removals increment counters; ignored candidates are never treated
  as negative feedback. Preferences affect presentation **only**, never
  authorize deletion. User can reset preferences in the GUI.
- **RecoveryProof**: on request, validates every backup entry within a bounded
  Storage Cleanup backup directory, SHA-256 checks the saved bytes, and
  actually restores one small file inside a temporary sandbox. No original
  filesystem path is ever overwritten; does not verify OS reinstallability,
  application settings or malware safety. Very large backup collections can
  exceed verification limits and return an incomplete status.
- **Survival**: read-only estimate of how many scanned cleanup candidates lack
  another verified independent file *within the scan*. Does not claim to
  inventory all user documents or test physical disaster recovery.
- **SmartSleep**: an AC-power/idle gate for explicitly requested optional
  background maintenance. Does not throttle or disable real-time protective
  scanning. No background indexing daemon or scheduler is installed.

All potentially destructive actions still require explicit user confirmation.
Old-file candidates rely on modification timestamps, **not proven disuse**.
The clean-up scanner has a bounded entry/file limit; incomplete scans cannot
proceed to deletion.

## Commands

Use a regular (non-administrator) Windows user token:

    antios storage-scan "C:\Users\You\Downloads" --json
    antios storage-scan "C:\Users\You\Downloads" --background --json
    antios storage-preference archive hide
    antios storage-preference duplicate prefer
    antios storage-preference archive normal
    antios storage-proof "C:\Users\You\Documents\AntiOS Backups\Storage Cleanup\antios-cleanup-..." --json

The background switch checks whether the machine is idle and connected to
AC power before doing a scan. It does not itself schedule future scans.

## Performance and privacy

No continuously running file-usage tracker, local LLM, or deep model is needed.
A manually requested scan performs hashing where duplicates may exist, then
stores only the resulting aggregate measurement and user preferences in
%LOCALAPPDATA%\AntiOS\storage-intelligence.sqlite3. This SQLite file is
**not encrypted**. No file-content or full path history is recorded by this
module; initial scans have no meaningful usage history. Existing Guard and AV
journals have their own data and privacy boundaries.

Performance goals are not benchmark results. Manual RecoveryProof can consume
disk IO when reading backups. The GUI caps rendered candidate rows to avoid
creating an enormous Tk table. No estimate is treated as permission to delete.


## User control

MemoryMap history is enabled initially but can be switched off or erased.
The GUI provides toggle/erase controls in Storage Cleanup. CLI equivalents:

    antios storage-history status --json
    antios storage-history off
    antios storage-history clear
    antios storage-history on

Disabling history stops *new* aggregate measurements. Clearing history removes
old measurements; a subsequent manual scan may create a fresh sample when
history is enabled. Neither operation affects antivirus detection or quarantine.
