# AntiOS + Microsoft Defender coexistence mode

AntiOS coexistence mode is a **parallel secondary protection** design. Microsoft
Defender remains installed and active. AntiOS keeps its own ClamAV engine,
Resident Guard, optional native minifilter and optional AMSI provider without
claiming the Windows Security Center primary-antivirus slot.

## Invariants

The implementation must preserve all of these conditions:

- AntiOS does not disable, stop or reconfigure Microsoft Defender.
- AntiOS does not add Defender exclusions.
- AntiOS does not write fake Windows Security Center antivirus registration.
- AntiOS does not modify AMSI `FeatureBits` to weaken provider-signature checks.
- AntiOS does not use test-signing, Secure Boot bypasses or driver-signature bypasses.
- An unknown/timeout result from AntiOS is not converted into a clean verdict.
- Native/AMSI components accept ClamD verdicts only from the configured
  own-process LocalSystem service whose established loopback connection is bound
  to the current SCM process identity.

These rules are product behavior, not merely documentation. The Python status
model and native diagnostics expose them explicitly.

## Layer model

```text
                    Windows application / script
                              |
                    +---------+---------+
                    |                   |
                Microsoft            Windows AMSI
                 Defender                |
                    |              +-----+------+
                    |              |            |
                    |          Defender      AntiOS
                    |           provider      provider
                    |                          |
                    |                       ClamD
                    |
                filesystem I/O
                    |
          +---------+------------------+
          |                            |
     Defender filter            AntiOS-Filter.sys
                                      |
                              AntiOS-Service.exe
                                      |
                                   ClamD

                       + Resident Guard
                         post-write reconciliation
```

The layers are intentionally independent. A Defender clean result is not treated
as an AntiOS clean result and vice versa.

## Coexistence status

```powershell
AntiOS.exe coexistence-status
AntiOS.exe coexistence-status --json
AntiOS.exe protection-status
```

The coexistence probe is read-only. It reads:

- `Get-MpComputerStatus` for Defender service and real-time state;
- `WscGetSecurityProviderHealth(WSC_SECURITY_PROVIDER_ANTIVIRUS)` for aggregate
  Windows Security antivirus health;
- the AntiOS AMSI provider's own COM/AMSI registry keys.

`layered-with-defender` is reported only when Defender service, antivirus and
real-time protection are all observed as active. AntiOS still reports
`production_primary_antivirus=false`.

## Resident Guard coordination

Guard watches AntiOS-selected roots and performs independent ClamAV scans. It
does not recursively monitor Defender-owned protected stores under
`%ProgramData%\Microsoft\Windows Defender` or
`%ProgramData%\Microsoft\Windows Defender Advanced Threat Protection`.
This is an AntiOS-side exclusion only; Defender policy is untouched.

Executable/script-like writes still use the short Guard settle path. Guard is
post-write detection and does not claim pre-execution prevention.

## Native minifilter

The experimental minifilter can coexist in the Windows Filter Manager stack with
other minifilters. It remains source/lab tooling until AntiOS has a Microsoft
assigned altitude, approved production driver signing, HVCI/Driver Verifier
acceptance and the full Windows VM matrix documented in `native/README.md`.

Unknown engine results are fail-open and counted as incomplete. A confirmed
signature can be blocked in explicit enforcement mode. The driver never changes
Defender state or Windows Security registration.

Microsoft documents the `FSFilter Anti-Virus` altitude group as 320000-329999;
AntiOS must receive its own altitude rather than borrowing one.

## AMSI provider

`native/windows/amsi/provider.cpp` implements an
`IAntimalwareProvider` COM server. It reads AMSI streams up to the same 32 MiB
native scan limit and submits them to the verified AntiOS-managed ClamD service.

Only a confirmed ClamAV threat returns `AMSI_RESULT_DETECTED`. Timeouts,
unavailable engines, oversized streams and review/heuristic results remain
`AMSI_RESULT_NOT_DETECTED` from the AntiOS provider so the host and other
providers can continue their own policy. This is deliberate coexistence behavior,
not a claim that unknown content is safe.

Build:

```powershell
.\native\windows\build.ps1 -Target Amsi
```

Production registration requires a valid Authenticode signature:

```powershell
.\native\windows\amsi\Install-AmsiProvider.ps1 `
  -ProviderDll .\build\native\windows\AntiOS-AmsiProvider.dll `
  -Apply
```

Removal:

```powershell
.\native\windows\amsi\Install-AmsiProvider.ps1 -Uninstall -Apply
```

The registration script only creates/removes AntiOS's CLSID and
`HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}` entry. It refuses an
unsigned DLL and never changes AMSI signing policy.

## Why AntiOS does not register as primary AV in this mode

On ordinary Windows 10/11 clients without the applicable Defender for Endpoint
configuration, Microsoft documents that when a non-Microsoft solution becomes
the primary antivirus, Microsoft Defender Antivirus is disabled automatically.
That defeats the goal of two active independent engines.

Coexistence mode therefore leaves Defender as the primary registered solution
and makes AntiOS a secondary layered engine. A future certified primary-AntiOS
mode is a separate product state with separate Microsoft program, signing,
Windows Security and independent-test gates.

References:

- https://learn.microsoft.com/en-us/defender-endpoint/defender-antivirus-compatibility-without-mde
- https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers
