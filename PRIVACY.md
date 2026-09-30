# AntiOS Privacy

AntiOS is designed to work locally on your Windows PC.

## What AntiOS reads

Depending on the feature you use, AntiOS may read local information such as:

- Windows version and build;
- processor and architecture;
- TPM and Secure Boot state;
- Microsoft Defender status;
- BitLocker/device-encryption status;
- free space on the system drive;
- common startup application entries;
- common pending-restart markers;
- documented Windows identity metadata used by the advanced CLI.

## What AntiOS sends

**AntiOS does not include automatic telemetry or analytics.**

The application does not automatically upload health checks, startup entries, Windows identifiers, exported reports, or other diagnostic data to the AntiOS project.

The GUI contains buttons that open GitHub or built-in Windows Settings pages. Network activity caused by those destinations is governed by those services, not by AntiOS.

## Exported reports

When you choose **Export report**, AntiOS writes a JSON file to a location you select. The file stays on your computer unless you decide to share it.

Review exported reports before posting them publicly. They may contain local system information such as your computer name, Windows build and startup entries.

## Logs

File logging is disabled by default.

If you enable logging, AntiOS records operational information such as command name, dry-run state, change count and backup path. It intentionally avoids logging scanned fingerprint values, generated identity values, or backup contents.

## System changes

The consumer dashboard is read-only.

Advanced CLI write operations remain dry-run by default, require explicit confirmation, and use the safeguards documented in the project README.

## Questions

For privacy questions or bug reports:

https://github.com/Dargon777/AntiOS/issues
