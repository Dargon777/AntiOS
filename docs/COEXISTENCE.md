# AntiOS + Microsoft Defender coexistence

AntiOS supports a **layered companion** model on Windows.

The goal is simple: Microsoft Defender may remain active while AntiOS runs its
own independent engine, Resident Guard and (when separately validated and
deployed) native pre-execution filter. AntiOS does not need to impersonate,
disable, hide from or replace Defender to provide this second layer.

## Contract

AntiOS coexistence mode follows these rules:

- Microsoft Defender preferences are not changed.
- AntiOS does not write fake Windows Security Center registration.
- AntiOS does not register itself as the primary antivirus in this mode.
- AntiOS does not add Defender exclusions for itself or its watched folders.
- AntiOS does not use process hiding, rootkit techniques or anti-analysis tricks.
- ClamAV signatures and verdicts remain independent from Defender.
- Defender status is queried read-only with `Get-MpComputerStatus`.
- A failure to query Defender never disables AntiOS scanning.

`AntiOS.exe protection-status --json` exposes both the observed Defender state
and the AntiOS coexistence profile.

Typical healthy state:

```json
{
  "coexistence": {
    "mode": "layered",
    "layered_with_defender": true,
    "antios_role": "independent-companion",
    "primary_antivirus_registration": false,
    "defender_configuration_changed": false,
    "security_center_spoofing": false,
    "stealth_or_hiding": false
  }
}
```

## File ownership conflicts

Two real-time products can touch the same file close together. A temporary
sharing or lock violation is therefore not immediately treated as a broken
protection stack.

Resident Guard:

1. keeps the original file identity;
2. defers the scan after a transient sharing/lock conflict;
3. retries at most three times with a bounded delay;
4. reuses the normal inventory/revalidation path, so changed bytes cannot inherit
   an old verdict;
5. reports a real scan error if the conflict persists beyond the retry budget.

If the file disappears between discovery and scan, Guard records a
`scan-vanished` event instead of claiming the bytes were clean. This covers
ordinary deletion as well as remediation performed by another protection layer.

This is deliberately different from blindly ignoring `ACCESS_DENIED`: permanent
permission problems remain visible because they can represent a real coverage
gap.

## Detection layers

The intended production shape is:

```text
Windows application / download / script
              |
      +-------+--------+
      |                |
Microsoft Defender   AntiOS
      |                |
Defender engine     Resident Guard
                   /        |
             ClamAV      quarantine
                   |
          optional native filter
       (only after signing/VM gates)
```

The released Guard is still post-write protection. The experimental native
minifilter is the only AntiOS component designed for pre-execution file blocking,
and it stays outside normal deployment until its signing, altitude, HVCI, Driver
Verifier and Windows VM acceptance gates pass.

## AMSI

AntiOS can use Windows AMSI as an explicit compatibility scan engine. This is
separate from the independent ClamAV path and does not make AntiOS a Defender
plugin. A future AntiOS AMSI provider would require its own Windows integration
and signing work; it should not be confused with the current AMSI client scanner.

## What coexistence does not promise

Layered mode is not equivalent to two certified primary antivirus products.
It does not grant Windows Security Center primary registration, ELAM, protected
service/PPL status, boot-time protection or external effectiveness
certification.

The point of coexistence is narrower and useful: **keep Defender active and add
an independent AntiOS protection path without weakening either product.**


## Native coexistence telemetry

The experimental minifilter now uses native protocol v2 for coexistence diagnostics.
Its default INF remains audit/manual-start and sets:

- `CoexistenceMode=1`;
- `MaxPendingScans=4`;
- `Enforcement=0`;
- a bounded local scan timeout.

The loaded driver exposes current/peak pending scans, overload bypasses, message
delivery timeouts, scan completion timeouts, cancelled execute opens and total,
average and maximum wait latency. These values are measurements, not a security
score. A high or growing timeout/bypass count means the machine needs review even
if both products are technically running.

On overload the prototype remains fail-open and increments an incomplete/bypass
counter. This is intentional for coexistence: blocking the system because another
security filter briefly owns I/O would turn a detection gap into an availability
failure. Production readiness requires the VM stress harness to demonstrate that
this bounded fail-open path is rare and observable.

`Test-NativeCoexistence.ps1` refuses to run unless Defender real-time protection
is active and `WdFilter` is loaded. It then exercises many simultaneous harmless
`FILE_EXECUTE` opens while AntiOS is attached, checks that clean files are not
blocked, verifies the queue drains and records latency/timeout deltas.


## Native admission bound

The experimental native broker owns four scan workers. The minifilter therefore
admits at most four concurrent user-mode scans in coexistence mode. Extra execute
opens fail open into an explicit incomplete/busy-bypass counter rather than
building an unbounded kernel wait queue. The installer rejects a
`MaxPendingScans` value above the four native broker workers.

The disposable-VM coexistence harness verifies Microsoft Defender real-time
protection both before and after the stress run. A run cannot pass merely because
Defender was active at startup and became inactive during testing.


## Runtime health semantics

AntiOS no longer equates a correct native configuration with a proven healthy
runtime. The aggregate protection status distinguishes:

- `inactive/not-validated` — required native coexistence pieces are absent or unsafe;
- `configured-unmeasured` — configuration is valid but telemetry is unavailable;
- `configured-unexercised` — the loaded stack has not observed a scan attempt yet;
- `operational` — scans have been observed without recorded gaps;
- `operational-with-gaps` — bounded fail-open events or section conflicts occurred,
  but no delivery/completion timeout or latency-ceiling violation was recorded;
- `attention` — a delivery/completion timeout or excessive recorded wait requires
  review.

These counters are lifetime telemetry for the loaded driver, not a malware
verdict and not a certification result.
