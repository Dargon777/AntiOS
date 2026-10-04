# AntiOS v2.0.0 alpha 13

Alpha 13 makes the independent ClamAV stack the normal AntiOS antivirus path instead of an optional alternative to AMSI.

## Standalone-by-default antivirus

- Managed ClamAV is now the default engine for GUI file/folder scans and CLI `virus-scan`.
- Quarantine confirmation rescans use ClamAV by default.
- On Windows, normal ClamAV scans require the configured trusted SCM service peer before file bytes are sent to ClamD.
- AMSI remains available only when explicitly selected as a compatibility mode; AntiOS does not silently fall back between engines.
- The alpha 12 managed-engine lifecycle remains in place: protected runtime/data ACLs, automatic ClamD service startup, FreshClam bootstrap and recurring SYSTEM signature updates.
- Resident Guard continues to require verified engine identity and reports degraded coverage when the engine is missing, stale or untrusted.
- `protection-status` continues to report detection-engine readiness, database freshness, Guard state and native enforcement separately.

## Reliability

- Updated Windows regression fixtures for the verified-peer constructor contract introduced by the standalone default.
- Release metadata is synchronized across Python package, Windows executable resources, GitHub tag metadata and Microsoft Store development package version `2.0.13.0`.

## Safety and scope

Alpha 13 does not disable Microsoft Defender and does not claim Windows Security Center registration, ELAM/PPL protection or certified primary-antivirus status. The experimental native x64 execute-open minifilter and LocalSystem broker remain outside the normal release package until signed-driver/altitude and installed-VM acceptance gates are satisfied.

Use `AntiOS.exe protection-status --json` to inspect the truthful state of every protection layer.
