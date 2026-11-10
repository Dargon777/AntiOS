# Antivirus

AntiOS provides on-demand scanning, findings, quarantine/restore and optional resident protection.

## Public behavior

- Users choose files or folders to scan.
- Results distinguish detections, skipped items, errors and incomplete coverage.
- Quarantine and restore are explicit operations.
- AntiOS can coexist with supported primary antivirus products without disabling them.
- **AntiOS Engine is the default file detection engine.** It checks local SHA-256 signatures, advisory PE, ELF and script indicators, and supported ZIP, GZIP, TAR, BZIP2 and XZ contents. Supported OpenXML VBA projects are reported for review. The engine runs offline.
- CLI, dashboard and Guard use a shared signed SHA-256 catalog for the current user. The bundled starter set is curated from public malware reports and includes a separate EICAR self-test rule. The existing local SHA-256 file option overrides the shared catalog for an individual on-demand scan. Findings based on structural indicators are for manual review.
- Large files can still match a full-file hash. Limits, damaged entries and recognized unsupported archives are surfaced as incomplete coverage.
- An explicit on-demand file limit can be set up to 2 GiB. Full content inspection has a smaller memory budget, and larger files use streaming SHA-256 with bounded structural inspection.
- Protection status surfaces degraded or incomplete states instead of silently reporting success.
- Experimental native protection is not treated as production-certified primary antivirus protection.

## Important limitations

AntiOS v2 alpha is pre-release software. It does not claim ELAM/PPL, Windows primary-antivirus certification, complete boot-time protection or perfect pre-execution interception.

A clean result is limited to the content and providers that were actually checked.

## Catalog updates

Run `antios signatures status --json` to see the active catalog version and any fallback warning.
Run `antios signatures install PACKAGE` to install a newer publisher-signed catalog for your account.
A rejected update leaves the existing catalog available. An unreadable installed catalog is surfaced as degraded while scanning continues with a verified fallback.

The starter catalog contains public sector information from the UK National Cyber Security Centre
licensed under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).
See the [NCSC malware analysis reports](https://www.ncsc.gov.uk/section/keep-up-to-date/malware-analysis-reports)
for the original indicators and publication dates. The catalog is a limited exact-match set.

## Internal design

Security-sensitive implementation detail is intentionally omitted from public documentation. This includes internal provider sequencing, process/service identities, state and IPC formats, retry/timeout values, verdict caches, native protocol details, repair/update handoffs and enforcement thresholds.

For vulnerabilities, use [../SECURITY.md](../SECURITY.md).
