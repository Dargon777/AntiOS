# AntiOS v2.0.0 alpha 12

Alpha 12 moves AntiOS from an on-demand antivirus experiment toward an independently operated protection stack.

## Independent protection core

- Managed ClamAV engine lifecycle for Windows: protected Program Files runtime, protected ProgramData databases/configuration, automatic SCM startup and SYSTEM FreshClam updates.
- Windows ClamD requests can be bound to a specific own-process LocalSystem SCM service. AntiOS verifies the server side of the exact established loopback TCP connection before sending data and rechecks service identity before accepting a result.
- Resident Guard requires verified engine identity on Windows. A bare process listening on 127.0.0.1:3310 cannot produce a fully clean resident verdict.
- New `protection-status` command reports independent engine readiness, database freshness, Resident Guard state and native minifilter/service enforcement separately.
- FreshClam notifies ClamD after signature updates so the running engine can reload databases.

## Existing protection layers

- On-demand ClamAV and AMSI scanning with bounded workers and explicit incomplete coverage.
- Encrypted DPAPI quarantine and safe restore.
- Resident selected-folder post-write Guard.
- Experimental native x64 execute-open minifilter and LocalSystem broker remain available for signed VM acceptance testing.

## Safety and scope

AntiOS still does **not** disable Microsoft Defender, fake Windows Security Center registration or claim ELAM/PPL protection. The native minifilter remains experimental and is not included in the normal release package. Production primary-antivirus status still requires signed-driver deployment, Microsoft minifilter altitude, Windows VM/Driver Verifier acceptance, Windows Security integration and the applicable external Microsoft/certification gates.

Use `AntiOS.exe protection-status --json` for the truthful state of each layer.
