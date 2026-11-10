# Antivirus

AntiOS provides on-demand scanning, findings, quarantine/restore and optional resident protection.

## Public behavior

- Users choose files or folders to scan.
- Results distinguish detections, skipped items, errors and incomplete coverage.
- Quarantine and restore are explicit operations.
- AntiOS can coexist with supported primary antivirus products without disabling them.
- **AntiOS Engine is the default file detection engine.** It checks local SHA-256 signatures, advisory executable and script indicators, and supported ZIP, GZIP and TAR contents. The engine runs offline.
- The built-in signature is an antivirus self-test. For additional exact matches, CLI and dashboard scans can load a local SHA-256 signature file. Findings based on structural indicators are for manual review.
- Large files can still match a full-file hash. Limits, damaged entries and recognized unsupported archives are surfaced as incomplete coverage.
- Protection status surfaces degraded or incomplete states instead of silently reporting success.
- Experimental native protection is not treated as production-certified primary antivirus protection.

## Important limitations

AntiOS v2 alpha is pre-release software. It does not claim ELAM/PPL, Windows primary-antivirus certification, complete boot-time protection or perfect pre-execution interception.

A clean result is limited to the content and providers that were actually checked.

## Internal design

Security-sensitive implementation detail is intentionally omitted from public documentation. This includes internal provider sequencing, process/service identities, state and IPC formats, retry/timeout values, verdict caches, native protocol details, repair/update handoffs and enforcement thresholds.

For vulnerabilities, use [../SECURITY.md](../SECURITY.md).
