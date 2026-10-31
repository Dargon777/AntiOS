# AntiOS

**Languages:** English · [Русский](README.ru.md) · [Español](README.es.md) · [简体中文](README.zh-CN.md) · [Suomi](README.fi.md) · [Polski](README.pl.md) · [Монгол](README.mn.md)

AntiOS is an endpoint-security and system-maintenance project for Windows, with supplemental Linux companion support.

> **Pre-release:** AntiOS v2 alpha

## What AntiOS provides

- on-demand file and folder scanning;
- optional resident protection;
- quarantine and restore workflows;
- coexistence with supported third-party antivirus products;
- Windows security and system diagnostics;
- Storage Cleanup and Storage Intelligence;
- bounded file-recovery and integrity features;
- local diagnostic and incident views;
- update, installer and repair workflows designed to fail safely.

## Download

Use the latest published installer or portable package from GitHub Releases:

https://github.com/Dargon777/AntiOS/releases

Windows 10 22H2 x64 and newer Windows 11 builds are the supported desktop target. Linux companion support is supplemental.

## Security and privacy

AntiOS processes security and diagnostic data locally by default and does not enable automatic telemetry.

Security-sensitive implementation details are intentionally not documented in public-facing materials. Public documentation describes capabilities, limitations and user-visible behavior, but does not publish internal control flow, trust-boundary sequencing, persistence details, state/IPC layouts, service/task identities, recovery formats, detection thresholds, cache/queue parameters, native protocol internals, or update/repair handoff mechanics.

This documentation policy is intended to reduce unnecessary reconnaissance value. It is **not** a substitute for secure design, code review, signed updates, least privilege or fail-safe behavior.

See:
- [SECURITY.md](SECURITY.md)
- [PRIVACY.md](PRIVACY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)

## Antivirus

The Antivirus area provides scanning, findings, quarantine, protection status and advanced diagnostics. AntiOS can coexist with Microsoft Defender and selected third-party products without disabling their protection.

On Windows, Kaspersky and Dr.Web companion detection is documented in [docs/WINDOWS_COMPANION.md](docs/WINDOWS_COMPANION.md). AntiOS remains a supplemental layer and does not change vendor exclusions, services, quarantine or policy.

Resident protection and experimental native components are documented only at a high level. AntiOS does not claim certified Windows primary-antivirus status, ELAM/PPL protection or complete pre-execution coverage.

See [docs/ANTIVIRUS.md](docs/ANTIVIRUS.md).

## Storage and recovery

Storage Cleanup can identify cleanup candidates and perform explicitly confirmed actions. File-recovery features are bounded backup/integrity tools, not full-system rollback and not proof that restored content is malware-free.

## Installation

For normal Windows use, install the latest `AntiOS-Setup.exe` from Releases. The portable ZIP is intended for portable/developer use.

Implementation-specific installer, service, task and repair sequencing is intentionally omitted from public documentation.

## Development

The current v2 tree is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Public source remains available in this repository. Contributors should avoid adding operational security-sensitive architecture narratives to README files, release notes, pull-request descriptions, issues or other public text. When detailed internal design discussion is necessary, use a private engineering channel or private repository.
