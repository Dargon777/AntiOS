# AntiOS release notes

AntiOS release notes are intentionally written at the product-capability level.

## Current alpha

This release line includes improvements to:

- antivirus scanning and resident protection;
- quarantine and recovery;
- coexistence with supported security products;
- diagnostics and incident handling;
- Storage Cleanup and Storage Intelligence;
- installation, updating, repair and upgrade reliability;
- Windows compatibility and packaging;
- privacy, safety checks and test coverage.

### Security documentation policy

Public release notes must not disclose operational architecture that would materially simplify reconnaissance. Avoid publishing exact component handoff order, internal state paths, persistence/service/task identities, watchdog or lock behavior, trust-boundary verification sequences, cache/queue/timeout parameters, detection thresholds, native protocol fields, rollback internals or update activation details.

Describe **what changed for the user**, not the internal sequence used to implement it.

See [../SECURITY.md](../SECURITY.md) for vulnerability reporting.
