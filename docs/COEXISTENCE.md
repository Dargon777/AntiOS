# Security-product coexistence

AntiOS supports a layered companion model with supported security products.

## Public contract

- AntiOS does not disable, stop or reconfigure Microsoft Defender.
- AntiOS does not add Defender exclusions.
- AntiOS does not write fake Windows Security Center antivirus registration.
- AntiOS does not disable, stop or reconfigure Kaspersky or Dr.Web, and does not add vendor exclusions.
- AntiOS does not rely on process hiding or rootkit techniques.
- A failure in another provider does not automatically become a clean AntiOS verdict.
- Temporary conflicts and unavailable resources are surfaced as degraded or incomplete coverage.

AntiOS can also provide supplemental scanning alongside selected Kaspersky and Dr.Web products where supported.

## AntiOS Engine protection boundary

AntiOS Engine is an independent local file-inspection engine with SHA-256 rules,
bounded archive inspection and advisory executable/script indicators.
Resident Guard monitors files after writes and is **not** a Windows pre-execution
minifilter. No ClamAV daemon, third-party detection API or AMSI provider is
required for AntiOS scans. It may miss unknown threats.

AntiOS does not claim primary antivirus certification or replace the installed
real-time protection product. Upgrading from an older managed ClamAV/AMSI build
does not authorize deleting any old service or provider without verifying its
ownership and installer history. The coexistence goal is to add an independent
layer without weakening existing protection.
