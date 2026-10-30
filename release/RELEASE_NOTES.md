# AntiOS v2.0.0 alpha 29

Alpha 29 introduces lightweight Storage Intelligence and cleanup safety improvements on top of alpha 28.

## Storage Intelligence

- **LastCopy** checks whether a matching independent file was verified *inside the selected scan*. No match does not prove that a file is the only remaining copy; external drives, cloud storage and other folders are not checked.
- **MemoryMap** stores one aggregate folder-size/file-count sample per day for up to 180 days and 32 scan roots. It can be disabled or erased in the GUI or CLI. Root identifiers are pseudonymized, not encrypted.
- **TimeDebt** estimates folder-size trends only after enough separate-day samples. It is an experimental trend, not a prediction of future disk use.
- **CleanupDNA** lets users prefer, hide or reset cleanup categories. Repeated confirmed cleanups can affect display priority, never authorize deletion.
- **RecoveryProof** checks Storage Cleanup backup checksums and test-restores one small file in a private temporary directory. It does not test full Windows restoration, prove that backups are malware-free or overwrite originals.
- **Survival** provides read-only evidence about candidates lacking a verified independent copy within the selected scan.
- **SmartSleep** gates optional explicitly requested background maintenance on AC power and user idle time. It does not pause real-time antivirus protection.

## Safety and reliability

- Restored the missing Storage Cleanup results renderer in the desktop UI.
- Incomplete or bounded scans cannot proceed to destructive cleanup.
- Hard links are not misreported as independent copies or reclaimable disk space.
- Cleanup backup writes on the same volume do not overstate net freed bytes.
- Improved Guard SQLite concurrency with write-ahead logging.
- Added focused automated tests and documented privacy and limitations.

## Installation

This is a prerelease. Windows builds are unsigned unless artifact signing is configured; Windows SmartScreen may warn. Use the installer or portable ZIP from this release's Assets. Back up important files before running cleanup.

**Security scope:** Storage Intelligence is a local, on-demand aid, not a replacement for verified offline backups, antivirus or professional recovery. See docs/STORAGE_INTELLIGENCE.md.
