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

This table describes planned coverage, not implemented detection claims.

## Current implementation status

Stage 1 now has read-only Windows collectors:

- **Process:** Toolhelp32 process enumeration plus executable path and process
  creation FILETIME where accessible. Each process is emitted with a stable
  PID+creation-time identity into the shared EvidenceBus. Command line, signer,
  integrity level and loaded-module integrity are deliberately still reported
  as missing coverage.
- **Persistence:** Run/RunOnce/policy autoruns, Startup folders, automatic
  Win32 services, scheduled-task definitions, Winlogon/AppInit/BootExecute and
  targeted IFEO/SilentProcessExit hooks. WMI permanent event subscriptions and
  broad COM-hijack inspection are not yet implemented, so the sensor reports
  PARTIAL coverage instead of a false clean result.

Both collectors are inventory/correlation sensors only. They never modify
processes, services, registry values, Startup entries or scheduled tasks.


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

## Implementation order

1. Process + persistence inventory. **Baseline implemented on Windows.**
2. Process-memory inspection with explicit access/coverage reporting.
3. Driver trust and vulnerable-driver intelligence.
4. Boot, Secure Boot, TPM/measured-boot and DMA posture.
5. Browser and network correlation.
6. GPU/device-firmware inventory and telemetry.
7. Platform-firmware and virtualization attestation where supported.

Deep firmware, SMM, management-engine/security-processor and arbitrary VRAM
inspection must not be advertised as supported unless AntiOS has a documented,
testable acquisition path for the specific platform.
