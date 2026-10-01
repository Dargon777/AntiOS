# AntiOS v2.0.0 alpha 11

AntiOS now includes an **Antivirus** page with on-demand file and folder scanning, encrypted quarantine and Microsoft Defender controls.

## Antivirus

- Windows AMSI content scanning and optional local SHA-256 signatures.
- Explicit progress, cancellation, findings, skipped files and errors.
- Manual current-user DPAPI quarantine and restore without overwriting existing files.
- Defender quick/full scans and signature updates after confirmation.
- JSON export and `virus-scan`, `quarantine` and `defender` CLI commands.
- Seven-language UI; Settings and existing diagnostic/cleanup features are retained.

## Scope

This is the first on-demand antivirus alpha. Persistent protection remains with an installed antivirus. AntiOS does not install a kernel driver, register as a primary antivirus or disable Defender. AMSI scans submitted buffers and does not reproduce Defender's full file/archive engine. The built-in local signature is only the EICAR test hash; no independent malware feed is included. Default scan limits are 32 MiB per file and 100,000 files. Incomplete coverage is never reported as clean.

Scans do not change files. Quarantine, restoration and Defender actions require confirmation. Defender system scans follow its own remediation/cloud policy; results are viewed in Windows Security.

See `ANTIVIRUS.md` in the portable package or [the documentation](https://github.com/Dargon777/AntiOS/blob/master/docs/ANTIVIRUS.md) for CLI exit codes, limits and recovery instructions.
