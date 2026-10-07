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

AntiOS keeps the existing AMSI client scan path and now also contains an **x64
IAntimalwareProvider companion DLL** under `native/windows/amsi/`. The provider
is backed by the same independently verified AntiOS ClamD service and is designed
to coexist with Defender's provider rather than replace it.

Production registration requires a valid Authenticode signature. The installer
script refuses an unsigned DLL and only creates/removes AntiOS's own provider
CLSID and AMSI provider entry; it never changes AMSI `FeatureBits`, Defender
preferences or Windows Security Center registration.

```powershell
.\native\windows\build.ps1 -Target Amsi

.\native\windows\amsi\Install-AmsiProvider.ps1 `
  -ProviderDll .\build\native\windows\AntiOS-AmsiProvider.dll `
  -Apply
```

Because AMSI providers load in-process, the current DLL covers x64 AMSI hosts.
32-bit hosts continue to rely on Defender/other providers plus AntiOS file-system
layers until a separate x86 provider is built.

`antios coexistence-status` reports Defender/WSC state and whether the AntiOS
AMSI provider is registered. `antios protection-status` includes that AMSI state
alongside Guard, behavior/risk correlation and native-filter health.

## What coexistence does not promise

Layered mode is not equivalent to two certified primary antivirus products.
It does not grant Windows Security Center primary registration, ELAM, protected
service/PPL status, boot-time protection or external effectiveness
certification.

The point of coexistence is narrower and useful: **keep Defender active and add
an independent AntiOS protection path without weakening either product.**


## Native coexistence telemetry

The experimental minifilter now uses native protocol v4 for coexistence diagnostics.
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


## VM proof against fake coexistence

The native coexistence VM harness also verifies that the tested machine is not
quietly weakening Defender to make the result look successful. It reads Defender
preferences and fails if an AntiOS-related path/process exclusion is present. It
also reads the Windows Security Center antivirus inventory and fails if AntiOS is
registered there as a primary antivirus product.

These checks are read-only. The harness never adds/removes exclusions and never
changes Security Center registration.


## Clean-verdict cache

Protocol v4 adds a bounded clean-only cache to reduce duplicate work when
Defender and AntiOS both observe the same executable activity.

- The kernel stream context keeps `AvFileNotInfected` only until the monotonic
  `CleanCacheTtlMs` deadline. The default is 30000 ms and the driver refuses
  configuration above 300000 ms.
- Modifying I/O clears the stream deadline before the next execute-open.
- If the stream context is recreated, the broker can reuse a clean verdict only
  when SHA-256 of the exact Filter Manager snapshot matches one of its fixed 128
  entries and that entry has not expired.
- Only `AO_CLEAR` produced with a current ClamAV database enters the broker
  cache. Unknown, review, timeout, cancellation, stale-database and threat
  results never become clean cache entries.
- The legacy per-volume file-ID table is not trusted for cross-handle clean
  reuse because it does not carry a bounded lifetime/database generation.
- A ClamAV signature update can therefore leave a previously clean verdict
  reusable only for the remaining cache TTL, at most five minutes by policy and
  30 seconds by default.

The disposable-VM harness reopens unchanged clean executables and requires
cache-hit telemetry, then modifies the bytes and requires the next execute-open
to miss the clean cache and re-enter the native scan path.


### Generation changes

The clean cache is also keyed to the trusted ClamAV database generation. The
native service polls the verified ClamD `VERSION` response every 2 seconds.
A changed generation clears the broker SHA-256 cache and updates the minifilter's
global generation. Kernel stream clean states carry the generation that produced
their verdict and are rejected on the next open as soon as it differs.

A failed or stale VERSION probe publishes generation 0, deliberately disabling
clean-cache reuse until a current trusted generation is restored. In-flight clean
verdicts from the previous generation cannot overwrite a newer generation.
