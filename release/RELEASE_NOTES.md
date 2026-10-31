# AntiOS v2.0.0 alpha 30

Alpha 30 expands AntiOS into a cross-platform companion release while keeping Windows as the primary desktop target.

## Highlights

- Linux x86_64 companion build is now published alongside the Windows installer and portable package.
- Kaspersky and Dr.Web coexistence support is available on Windows and Linux.
- AntiOS remains a supplemental layer: it does not disable third-party protection, change vendor exclusions or policies, or automatically launch vendor scans.
- Windows continues to support Microsoft Defender coexistence.
- Linux includes the AntiOS CLI and a lightweight desktop companion surface for status and on-demand second-opinion scanning.
- Storage Intelligence, cleanup safeguards and recovery verification from Alpha 29 remain included.
- Packaging, compatibility checks and automated test coverage were expanded for the combined Windows/Linux release.

## Platform notes

Windows 10 22H2 x64 and newer Windows 11 builds remain the supported Windows target.

Linux support is supplemental. Distribution packaging and service setup can vary; the release provides a portable x86_64 archive rather than claiming native distro-package integration.

This is a prerelease. Direct-download Windows builds may still trigger SmartScreen when code signing is unavailable.

See SECURITY.md and PRIVACY.md for the current security and privacy contracts.
