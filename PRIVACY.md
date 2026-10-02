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
- file contents, SHA-256 hashes and paths in folders you select for antivirus scanning;
- encrypted quarantine records when you list or restore quarantined files.

## What AntiOS sends

**AntiOS does not include automatic telemetry or analytics.**

The application does not automatically upload health checks, startup entries, Windows identifiers, exported reports, or other diagnostic data to the AntiOS project.

The GUI contains buttons that open GitHub or built-in Windows Settings pages. Network activity caused by those destinations is governed by those services, not by AntiOS.

Antivirus scans submit selected content to the **installed Windows AMSI provider**. The provider may use cloud services or sample submission under its own settings and privacy policy. Defender operations likewise use Defender's configured cloud and remediation policy. AntiOS does not change those settings. Updating Defender signatures uses its configured update sources.

## Exported reports

When you choose **Export report**, AntiOS writes a JSON file to a location you select. The file stays on your computer unless you decide to share it.

Review exported reports before posting them publicly. They may contain local system information such as your computer name, Windows build and startup entries.

Antivirus reports also contain file paths, file hashes and detection details. They do not contain scanned file contents. Quarantined file contents and metadata are encrypted together with current-user Windows DPAPI and stored under `%LOCALAPPDATA%\AntiOS\Quarantine`. No plaintext quarantine key is stored by AntiOS. Restoration usually requires the same Windows account and computer; retain the account profile if you need these backups.

## Logs

File logging is disabled by default.

If you enable logging, AntiOS records operational information such as command name, dry-run state, change count and backup path. It intentionally avoids logging scanned fingerprint values, generated identity values, or backup contents.

## System changes

Health and Storage Cleanup checks and on-demand file scans are read-only. Quarantine and restoration require a GUI confirmation or CLI `--yes`. Restoration never overwrites an existing file. Defender scans require confirmation and may remediate detections under Defender's own policy.

Advanced CLI write operations remain dry-run by default, require explicit confirmation, and use the safeguards documented in the project README.

## Questions

For privacy questions or bug reports:

https://github.com/Dargon777/AntiOS/issues

The GUI scan worker temporarily records scan requests, file paths and findings in a private temporary job directory and removes it after completion or cancellation. Forced termination retains completed results in app memory. Startup UAC elevation uses the selected Windows account; choosing a different administrator changes the account used for settings and encrypted quarantine.
