# AntiOS v2.0.0 alpha 28

Alpha 28 rolls the recent security, diagnostics and recovery work into one public
Windows alpha release.

## File recovery

AntiOS now includes opt-in bounded file baselines from the Antivirus page and CLI.

- save selected files with SHA-256 integrity metadata;
- inspect and compare saved files with current originals;
- recover all or selected verified copies into a fresh directory;
- reject malformed ZIP data, invalid Unicode and unsafe network/device manifest paths;
- verify every stored blob before reading original paths;
- bind baseline extension/recovery selections to the manifest that was previously shown.

This is file backup and integrity checking, not a full Windows rollback and not a
malware-clean verdict. Archives are currently unencrypted and should be kept on
appropriately protected or offline storage.

## Diagnostics Center

The desktop app now includes a local Diagnostics Center for protection and runtime
events.

- bounded JSONL event history with rollover;
- severity/component/search filters;
- human-readable diagnosis alongside technical details;
- privacy redaction at ingestion and stronger redaction in support exports;
- reviewed ZIP support export without quarantine contents, malware samples or user
  configuration files.

## Managed ClamAV trust and repair

Managed ClamAV bootstrap and maintenance were hardened substantially.

- the official ClamAV 1.5.4 Windows x64 ZIP is pinned by exact URL, size and SHA-256;
- extracted `clamd.exe` and `freshclam.exe` are attested against the trusted archive;
- installed engine trust metadata is rechecked before maintenance;
- repair snapshots owned service/task/ACL state and attempts best-effort rollback on
  later failure;
- postconditions re-check service identity, startup state and updater task identity;
- ambiguous or foreign ClamAV services/tasks fail closed instead of being replaced.

## Installer and system-change hardening

- startup task changes verify AntiOS ownership before replacing/removing tasks;
- ClamAV fresh install refuses colliding services, tasks and machine-wide bindings;
- partial install failures preserve or safely roll back owned resources when possible;
- Storage Cleanup backup files use exclusive creation and fsync before destructive
  follow-up actions;
- full-source audit tooling now checks tracked files, parsable formats, PowerShell
  grammar and high-risk source contracts in CI.

## Public site

The GitHub Pages site was redesigned for public alpha distribution with EN/RU
content, transparent capability/limitation messaging and release-aware download
buttons that follow the newest published GitHub release.

## Validation

The merged feature/audit heads passed their GitHub Actions suites before alpha 28
integration, including Windows portable builds, hardened Windows builds, Store MSIX,
CodeQL where applicable, native-boundary tests and the full-source audit.

The alpha 28 integration branch is expected to pass the same release metadata,
Python and Windows packaging gates before publication.

## Important alpha limitations

AntiOS remains pre-release software. It does not claim certified Windows primary
antivirus registration, ELAM/PPL status or complete pre-execution blocking. Resident
Guard remains primarily post-write protection; the native filter path is still
experimental. Real-machine Windows 10/11 acceptance and hostile failure-injection
coverage remain separate release-hardening work.

Windows 10 22H2 x64 (build 19045) and newer Windows 11 builds remain the supported
desktop target.
