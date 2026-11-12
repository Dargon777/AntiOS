# Deep-security sensor foundation

AntiOS treats deep inspection as a set of independent collectors feeding the
same shared `Evidence` / `EvidenceBus` pipeline used by detection, risk and
incident correlation. The sensor layer does not create a second verdict engine.

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

This table describes the target surface map. On Windows, process inventory,
high-value persistence inventory and bounded process-memory inspection are now
connected to this architecture. The remaining rows are still planned coverage.

## Contracts

Every collector has a versioned `SensorDescriptor` and returns a
`SensorReport`. Reports distinguish complete, partial, unavailable,
unsupported, permission-denied, error and not-implemented states. Any state
other than complete requires an explicit reason.

`ScanBudget` provides hard item, byte, time and depth limits. Privileged
collection is disabled unless the caller explicitly enables it. Collector
failures are isolated and surfaced as sanitized coverage errors.

Collectors emit the project's shared `Evidence` objects. The helper
`sensor_evidence()` stamps surface, sensor version, rule ID and scan run ID so
later signature/risk/incident stages can correlate observations without losing
provenance. A `SensorRegistry` can publish successful reports directly into
the existing bounded `EvidenceBus`.

Generic sensor evidence never becomes an independent enforcement path. Current
AntiOS policy continues to reserve automatic enforcement for confirmed scanner
threats; behavioral, firmware, GPU, memory and other sensor signals remain
review/correlation input unless a future policy is explicitly designed and
validated.

## Implementation status and order

1. **Implemented baseline:** Process inventory + persistence inventory.
   - running process PID/PPID, stable creation identity and image path;
   - Run/RunOnce, auto/boot/system services and drivers, Startup folders;
   - scheduled-task command inventory;
   - WMI command/script consumers through a bounded read-only CIM query;
   - per-user COM server overrides;
   - user-writable/interpreter-based entries are review evidence, never an
     automatic remediation decision.
2. **Implemented baseline:** Process-memory inspection.
   - bounded VirtualQueryEx enumeration;
   - private executable region detection;
   - writable+executable metadata;
   - small read-only header probes only for private executable regions;
   - embedded PE-header classification;
   - inaccessible/protected processes remain explicit partial coverage;
   - raw memory bytes are never persisted in evidence or logs.
3. Driver trust and vulnerable-driver intelligence.
4. Boot, Secure Boot, TPM/measured-boot and DMA posture.
5. Browser and network correlation.
6. GPU/device-firmware inventory and telemetry.
7. Platform-firmware and virtualization attestation where supported.

Deep firmware, SMM, management-engine/security-processor and arbitrary VRAM
inspection must not be advertised as supported unless AntiOS has a documented,
testable acquisition path for the specific platform.


## Resident Guard integration

On Windows the Guard schedules process+RAM inspection and persistence inventory
in a single background deep-security worker. The worker is bounded and does not
block the Guard heartbeat, directory notifications or ordinary file scanning.
Raw sensor evidence is published to the shared EvidenceBus, evaluated by the
multi-sensor signature engine and then attached to IncidentGraph on the Guard
thread.

The initial implementation remains detect/review-only. Memory metadata,
persistence heuristics and multi-sensor signatures cannot authorize quarantine
or process termination.
