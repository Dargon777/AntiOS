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

## Experimental native protection

Native components remain experimental until their signing, compatibility and real-machine validation gates are satisfied. Public documentation does not describe their internal queueing, protocol, caching, fail-open/fail-closed thresholds, telemetry fields or broker/driver handoff.

The coexistence goal is simple: add an independent layer without weakening the existing protection product.
