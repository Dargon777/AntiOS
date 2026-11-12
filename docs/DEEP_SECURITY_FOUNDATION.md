# Deep-security sensor foundation

AntiOS treats deep inspection as a set of independent sensors feeding one
correlation pipeline. The foundation is intentionally separate from OS-specific
collectors so unsupported or privileged checks cannot silently turn into a
"clean" result.

## Planned surfaces

| Surface | Examples | Default acquisition | Minimum privilege |
| --- | --- | --- | --- |
| Process | module/image integrity, process ancestry | snapshot | user |
| RAM | executable private memory, image mismatch | snapshot | admin |
| Persistence | services, scheduled tasks, WMI, COM, autoruns | query | user |
| Driver | loaded drivers, signatures, vulnerable-driver intelligence | query | admin |
| Kernel | kernel integrity evidence | snapshot | system |
| Boot | boot configuration and measured-boot evidence | attestation | admin |
| UEFI | Secure Boot and available UEFI integrity evidence | attestation | admin |
| Platform firmware | firmware/security-processor posture exposed by platform APIs | attestation | admin |
| Device firmware | storage/NIC/GPU/USB firmware inventory and change evidence | query | admin |
| GPU | process/device telemetry and exposed integrity evidence | query | user |
| Network | connection/process correlation | event stream | user |
| Browser | extensions, enterprise policies and risky persistence | query | user |
| DMA | platform DMA protection posture | attestation | admin |
| Virtualization | hypervisor/VBS/security posture | query | admin |
| Attestation | TPM/measured boot and platform claims | attestation | admin |

This table describes planned coverage, not implemented detection claims.

## Contracts

Every collector has a versioned `SensorDescriptor` and returns a
`SensorReport`. Reports distinguish complete, partial, unavailable,
unsupported, permission-denied, error and not-implemented states. Any state
other than complete requires an explicit reason.

`ScanBudget` provides hard item, byte, time and depth limits. Privileged
collection is disabled unless the caller explicitly enables it. A collector
that fails is isolated; the registry reports a sanitized failure instead of
propagating implementation details.

Observations carry a surface, evidence kind, severity and confidence. Heuristic,
behavioral, configuration and telemetry observations cannot mark themselves as
eligible for automatic remediation. Exact authenticated matches and explicit
integrity failures are the only evidence classes that may request that flag;
the final policy engine must still decide whether action is allowed.

## Integration target

The sensor layer should publish observations into the existing evidence and
incident-correlation pipeline rather than create independent verdict engines.
A future adapter can map `Observation` into the project's EvidenceBus without
making the sensor package depend on internal bus implementation details.

## Implementation order

1. Process + persistence inventory.
2. Process-memory inspection with explicit access/coverage reporting.
3. Driver trust and vulnerable-driver intelligence.
4. Boot, Secure Boot, TPM/measured-boot and DMA posture.
5. Browser and network correlation.
6. GPU/device-firmware inventory and telemetry.
7. Platform-firmware and virtualization attestation where supported.

Deep firmware, SMM, management-engine/security-processor and arbitrary VRAM
inspection must not be advertised as supported unless AntiOS has a documented,
testable acquisition path for the specific platform.
