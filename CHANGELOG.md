# Changelog

This file summarizes user-visible changes. Detailed commit history remains available in Git.

## Unreleased

## 3.0.5a1 — 2026-11-14

- Detach the packaged Windows Guard from its console and preserve current-user access to regenerated SQLite state files.
- Compare recorded whole-file hashes with a signed catalog offline, including clean files when explicitly captured in a scan report.
- Keep confirmed findings visible and defer automatic quarantine when the local trusted baseline conflicts, cannot be read, or the scan worker was interrupted.
- Show scan coverage and affected files in the Windows interface.
- Match incident evidence to the observed process instance before using a file path, and distinguish a Guard startup exit from a heartbeat timeout.

## 3.0.4a1 — 2026-11-14

- Keep earlier Windows quarantine records readable across consecutive isolations.
- Check signed catalog updates against a local baseline of trusted file hashes and block conflicting updates.
- Keep Guard notifications active during scans, report capacity limits and recheck files that change during inspection.
- Add bounded Windows thread-start inspection and report coverage gaps.
- Inspect TAR and TGZ members using extended PAX or GNU path headers.
- Add five exact file indicators from CISA AR25-261A.

## 3.0.3a1 — 2026-11-12

- Expanded read-only Windows process inspection with bounded token integrity, loaded-module inventory and on-disk image signing metadata.
- Improved process identity handling and persistence evidence correlation without treating partial telemetry as a clean result.
- Added bounded process-memory, persistence, loaded-driver trust/BYOVD and platform security-posture evidence, with explicit coverage limits.
- Connected the new evidence to risk/incident review; weak heuristic evidence does not independently authorize quarantine.
- Simplified the CI workflow layout and refreshed public documentation.
- Hardened unsigned prerelease provenance checks to require exact commit SHA, master ref, workflow identity and consistent archive metadata.

## 3.0.2a1 — 2026-11-12

- Redesigned the Windows dashboard around protection status, scanning, quarantine and tools.
- Added light, balanced and heavy scan profiles with a separate worker setting.
- Expanded the local SHA-256 signature set and improved scanning of folders with many small files.
- Added clearer coverage reporting and offline decision replay from saved scan reports.
- Added an inert benchmark with known expected outcomes.
- Published Windows Setup/portable, Linux x86_64 and Python prerelease packages.

## 3.0.1a1 — 2026-11-10

- Moved the app, CLI and Resident Guard to the independent AntiOS Engine.
- Removed the third-party antivirus-engine runtime requirement from new packages.
- Kept coexistence reporting for existing security products.
- Added safer handling for legacy installations that still contain retired engine components.

## 2.0 alpha line — 2026-09 to 2026-11

The 2.0 alpha series established the current dashboard, Guard, quarantine, recovery, diagnostics, coexistence, Linux companion, installer and packaging foundations. It also included the older managed third-party scan-engine path that was retired in the 3.0 line.

Per-release historical notes remain available on the GitHub Releases page.

Security vulnerabilities should be reported through [SECURITY.md](SECURITY.md).
