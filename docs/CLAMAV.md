# ClamAV integration

AntiOS can use a managed ClamAV installation as an independent scanning provider.

## Public behavior

- provider health is checked before AntiOS treats scanning as complete;
- stale or unavailable protection data is surfaced as incomplete coverage;
- signature maintenance can be requested through supported AntiOS workflows;
- AntiOS does not treat provider failure as a clean verdict;
- coexistence with Microsoft Defender and selected third-party products is supported.

## Trust and safety

AntiOS validates the managed provider and its update material before trusting it. Exact validation order, service identity checks, network-peer verification, file paths, hashes, rollback steps, repair postconditions and maintenance scheduling are intentionally not documented publicly.

This page documents the capability boundary, not the operational trust protocol.
