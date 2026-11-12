# Changelog

This file summarizes user-visible changes. Detailed commit history remains available in Git.

## Unreleased

No changes recorded yet.

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
