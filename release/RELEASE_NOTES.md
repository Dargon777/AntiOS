# AntiOS public prerelease — v2.0.0-alpha.36

This release improves recovery of existing Windows protection installations.

- Older engine configurations are completed during recovery so that signature updates and scanning can work after an upgrade.
- A running engine reloads repaired configuration; conflicting settings are preserved and reported.
- Windows acceptance now checks actual scanning and resident protection after installation and recovery, including a large benign file and a standard harmless antivirus test.

Administrator approval is required for system maintenance. Existing Guard history is preserved. Protection readiness is checked separately after recovery; inaccessible files and incomplete scans remain visible in reports.

AntiOS v2 remains prerelease companion software. See README.md, PRIVACY.md and SECURITY.md for supported usage and limitations.
