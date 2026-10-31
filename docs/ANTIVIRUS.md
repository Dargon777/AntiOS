# Antivirus

AntiOS provides on-demand scanning, findings, quarantine/restore and optional resident protection.

## Public behavior

- Users choose files or folders to scan.
- Results distinguish detections, skipped items, errors and incomplete coverage.
- Quarantine and restore are explicit operations.
- AntiOS can coexist with supported primary antivirus products without disabling them.
- Protection status surfaces degraded or incomplete states instead of silently reporting success.
- Experimental native protection is not treated as production-certified primary antivirus protection.

## Important limitations

AntiOS v2 alpha is pre-release software. It does not claim ELAM/PPL, Windows primary-antivirus certification, complete boot-time protection or perfect pre-execution interception.

A clean result is limited to the content and providers that were actually checked.

## Internal design

Security-sensitive implementation detail is intentionally omitted from public documentation. This includes internal provider sequencing, process/service identities, state and IPC formats, retry/timeout values, verdict caches, native protocol details, repair/update handoffs and enforcement thresholds.

For vulnerabilities, use [../SECURITY.md](../SECURITY.md).
