# AntiOS public changelog

This public changelog intentionally contains only user-facing capability summaries.

Detailed security architecture, trust-boundary sequencing, service/task identities, IPC/state layouts, detection thresholds, cache/queue settings, update handoff mechanics, repair/rollback sequencing and native protocol details are not published here.

## 2.0.0a33 - 2026-11-04

- opens the Windows dashboard on a redesigned protection center with the current access level and a system-drive selector;
- adds an interactive administrator scan window for installed copies;
- scans the full file selection by default and streams large files through ClamAV;
- reports inaccessible files and incomplete engine analysis in scan results.
- fixes false-positive permission checks that could prevent the ClamAV engine from installing on otherwise standard Windows folders;

## 2.0.0a32 - 2026-11-03

- improves Windows Guard startup and recovery after running AntiOS as administrator;
- keeps independent protection status available when a component cannot be read;
- reduces repeated diagnostic messages when navigating the interface;
- fixes interface cleanup when changing themes during a scan;
- clarifies incompatible Guard settings and Windows access errors;
- adds isolated regression checks for startup, status reporting and Windows compatibility.

Existing inaccessible user data may require a one-time administrator-assisted Guard reconfiguration. AntiOS remains prerelease companion software.

## 2.0.0a31 - 2026-11-03

Alpha 31 improves protection diagnostics and reliability:

- keeps protection status reporting available when a companion component cannot be read;
- improves Windows permission-error messages and gives clearer guidance for incompatible Guard settings;
- reduces repeated diagnostic notices without concealing the underlying failure;
- distinguishes incomplete scan coverage from successful process completion;
- improves privacy-conscious support reports and adds regression coverage.

This prerelease does not replace Windows Defender or other antivirus products. An inaccessible Windows resource may still require a local repair.

## 2.0.0a30 - 2026-10-31

Alpha 30 expands AntiOS companion support across Windows and Linux:

- adds a Linux x86_64 release archive alongside the Windows installer and portable package;
- adds supplemental Kaspersky and Dr.Web coexistence support on Windows and Linux;
- keeps third-party antivirus products in control of their own real-time protection and policy;
- exposes companion status in AntiOS diagnostics and protection views;
- carries forward Storage Intelligence, cleanup safety and recovery verification improvements from the previous alpha.

## Current alpha line

Recent AntiOS v2 alpha work includes:

- Windows and Linux companion support;
- on-demand antivirus scanning and optional resident protection;
- encrypted quarantine and restore workflows;
- coexistence with Microsoft Defender and selected third-party antivirus products;
- diagnostics, incident views and privacy-conscious support export;
- Storage Cleanup and Storage Intelligence;
- bounded file recovery and integrity checking;
- installer, updater, repair and upgrade reliability work;
- hardened build and signing work;
- Windows 10 22H2 x64 compatibility target and Windows 11 support;
- UI, localization and Microsoft Store packaging improvements.

For security reasons, historical engineering-level changelog entries have been removed from the current public tree. Older commits and previously published GitHub metadata may still exist in repository history.

Security issues should be reported through [SECURITY.md](SECURITY.md).
