# Experimental native Windows scanner boundary

This is **source for a laboratory prototype**, separate from AntiOS's Python GUI,
Guard, installer and Microsoft Store package. It is not a supported primary
antivirus, a certified driver, or a ready-to-install Defender replacement.

The native tree also contains an **x64 AMSI coexistence provider**. Unlike the
kernel filter, that provider can be shipped as a normal signed DLL: it is an
in-process `IAntimalwareProvider` backed by the same verified ClamD service
identity checks. It is secondary-only, never registers AntiOS as the Windows
Security primary antivirus and never changes Defender or AMSI FeatureBits.
See [Defender coexistence mode](../docs/COEXISTENCE.md).

## Implemented

- `AntiOS-Filter.sys`: a minifilter derived from Microsoft's AvScan sample,
  pinned to `windows/UPSTREAM_COMMIT`. It attaches only to local non-CSV NTFS
  volumes and inspects opens requesting `FILE_EXECUTE`. In explicit enforcement
  mode, a confirmed infected stream causes the open to be cancelled with
  `STATUS_VIRUS_INFECTED`. The **default is audit**, with manual driver/service
  startup. Loader coverage still requires signed Windows VM acceptance before production use.
- File contents travel through Filter Manager data-scan sections, not a path
  supplied by an untrusted application. The broker copies the exact EOF length,
  catches inaccessible pages through `ReadProcessMemory`, and submits the
  snapshot to a separate local ClamD. No executable content is run by the scanner.
- `AntiOS-Service.exe`: native x64 SCM host, LocalSystem, four scanning workers,
  independent abort listener, per-request overlapped receive ownership, graceful
  stop and Application event logging. A worker/port failure stops the service
  instead of leaving SCM reporting a healthy running scanner.
- Protocol version/size checks, complete capture of kernel command inputs, server
  port/type binding, LocalSystem checks on scan connections and write-side
  messages. The separate administrator-readable query port cannot submit verdicts.
- One broker deadline covers section copying plus ClamD VERSION/INSTREAM work.
  Network I/O uses a monotonic deadline and 50 ms cancellation checks. Files over
  32 MiB, overload, heuristics, PUA, scanner errors and stale/unknown database
  freshness are incomplete results, never cached as clean. A positive signature
  still reports a threat with an old database.
- Kernel serialization and message waits are bounded, with at most four pending
  user scan contexts. Clean verdicts and the upstream cross-handle cache are not
  reused. Positive stream state remains until a write/context teardown; reload
  the filter after rule removal to clear a previous positive in this prototype.
- `--status` reports SCM state and configured/actual Windows process protection
  separately. `--driver-status` reads loaded policy and counters; it does not infer
  protection from a registry setting. `--scan-file PATH` is a bounded diagnostic.
  Diagnostic exits: 0 clean, 1 confirmed signature, 2 incomplete/review/error.

## Explicit limitations

This is an **execute-open filter**, not a complete process/memory/script/network
prevention system. It does not cover all image-section creation paths, already
open/mapped images, scripts/JIT/fileless attacks, non-NTFS/network/removable
coverage, boot threats or kernel attackers. Its effectiveness against actual
`CreateProcess`, image reuse and concurrent modifications requires Windows tests.
Writes invalidate inherited stream state; a race or unknown result is allowed.
The filter does not provide a fail-closed security guarantee.

Fail-open behavior is intentional in this lab version: when the broker/engine is
absent, a timeout occurs, all slots are busy or a verdict is uncertain, the open is
allowed. Counters/logs identify incomplete coverage. The `Incomplete` counter
counts incomplete events, not unique files; not every skipped filesystem path
creates a scan event. A running service alone does not mean the engine is ready.

ClamD is a **separate, unprotected process** on 127.0.0.1:3310. The broker requires
an explicitly configured own-process LocalSystem ClamD service. Before sending
VERSION or file bytes, it checks the server-side established TCP connection's full
address/port tuple and owner PID against that running SCM service. A held process
handle and a final SCM/liveness check reject engine restarts during a scan. Missing
configuration, a different socket owner or failed verification yields UNKNOWN;
there is no fallback to an unchecked connection. The installer stores the service
name in HKLM and adds it as an SCM dependency. Service wrappers spawning ClamD as
a child process are unsupported.

This is OS process-identity binding, not TLS or binary attestation. It addresses
ordinary-user port impersonation, assuming protected SCM/registry configuration.
It does not protect against an administrator, injected engine code or modified
databases. `--scan-file-verified PATH` exercises this same path; `--scan-file PATH`
is an explicitly unchecked transport diagnostic and is never used by the broker.
Windows runtime validation of owner-PID matching and engine restart races remains
required in the lab VM. Include these negative cases: stop ClamD and bind 3310
from an ordinary-user process (no commands/file bytes may arrive); restart the
configured engine between VERSION and INSTREAM (UNKNOWN); restore the trusted
service and verify both harmless clean and custom-signature verdicts. Check the
service's SCM permissions and executable/database directory ACLs before doing so. Protecting the broker alone would not protect this engine
or its database. The default SCM service is not PPL and is not tamper-proof
against administrators. There is no ELAM driver or Windows Security Center
registration, and neither is faked.

The inherited section/transaction/cancellation lifecycle still needs Driver
Verifier and adversarial stress testing. Kernel section creation and memory
paging can wait inside Windows: a 3-second engine deadline is **not** a hard bound
on every kernel operation or service shutdown. The independent default waits are
5 seconds for per-stream serialization, 5 for delivery/reply, 5 for completion,
then abort handling. Windows storage stalls can exceed these bounds.

## Build and current validation

From an x64 Windows C++ development environment, with `nuget.exe` available:

```powershell
./native/windows/build.ps1 -Restore
```

The build pins WDK/SDK NuGet 10.0.26100.2454 and produces **unsigned experimental**
artifacts under `build/native/windows`. MSVC uses a static runtime for the service.
The separate `windows-native.yml` workflow builds and tests them; it never loads
a driver, installs a service or publishes a release. Its Windows results remain
pending until this branch is submitted and that job actually runs.

Local checks performed in Linux: native service cross-compilation with MinGW,
all six driver C units compiled with Clang against official WDK headers and linked
against WDK libraries into a `.sys`, protocol tests against real ClamD with inert
plain/ZIP signatures, timeout/cancellation/malformed-reply tests, and an
AddressSanitizer/UBSan parser corpus. These do **not** validate Windows runtime,
MSVC release builds, driver signing, HVCI, installation or certification.

## Signed lab package and VM acceptance

Use a disposable **Windows 11 24H2+ x64 NTFS VM**, with a snapshot and working
recovery access. Keep Defender, Secure Boot and signature enforcement enabled.
There is deliberately no test-signing or signature-bypass installer.

1. Obtain an altitude assigned to this filter by Microsoft. Generate the INF
   with `New-DriverInf.ps1 -AssignedAltitude <your-allocation> -OutputDirectory
   <package>`. The script validates syntax, not ownership. It has no borrowed or
   default altitude. Run the WDK INF/catalog validation and approved driver-signing
   submission process on the exact SYS/INF package. Do not install the raw CI SYS.
2. First register ClamD directly as an own-process LocalSystem service (not a
   child of a service wrapper). Install the reviewed signed primitive-driver package through the Windows
   driver deployment process. Sign the service executable with the expected
   publisher certificate. `Install-NativeService.ps1 -SignedExecutable <exe>
   -SignerThumbprint <thumbprint> -EngineServiceName <ClamD-service-name>` checks prerequisites; `-Apply` creates the
   manual-start service and a protected Program Files directory. It neither starts
   it nor changes the kernel policy. No PPL setting is applied.
3. Configure a lab ClamD on 127.0.0.1:3310 with official fresh databases and limits
   suitable for 32 MiB INSTREAM content. Use `New-LabFixture.ps1` with the supplied
   `Native-Inert.exe` (source: `tests/inert_program.c`) to generate **harmless**
   executables plus a custom rule. Load that rule only into the isolated lab
   engine. The fixture simply exits; the appended marker is not malware.
4. Start `AntiOSNative` through SCM (its driver dependency loads first). Verify
   `AntiOS-Service.exe --status` and elevated `--driver-status`. In audit mode,
   run `Test-NativeVm.ps1 -ServiceExecutable <installed-exe> -FixtureDirectory
   <fixtures> -ExpectedMode Audit -ReportPath <audit.json>`. This checks exact
   execute-access opening, actual process creation, SEC_IMAGE image-section mapping, clean execution and counters.
5. Only after audit passes, stop the broker and unload the filter in the VM.
   Set `HKLM\SYSTEM\CurrentControlSet\Services\AntiOS-Filter\Parameters\Enforcement`
   to DWORD 1, then reload/restart. Verify the **loaded** policy with driver status.
   Run the same test with `-ExpectedMode Enforce`. It must observe Windows error
   225 for the marked execute/process/image-section paths and no marked-fixture process execution; clean execution must still work.
6. Before considering deployment, also test the matrix below. Revert to audit or
   restore the VM snapshot if any criterion fails. Never label a failed/skipped
   VM test as protection readiness.

| Scenario | Required evidence before release |
| --- | --- |
| Engine missing, stale database, malformed reply | Open is allowed within measured bounds; incomplete status is visible; no false clean |
| Broker stop, crash, filter disconnect/unload | Outstanding I/O drains, SCM state reflects failure, no freed OVERLAPPED/context use |
| More than four concurrent opens | Bounded memory/queue, no deadlock, explicit incomplete counts |
| Concurrent write/truncate/rename/delete, hard links, transactions | No stale clean/positive decision, no kernel crash or indefinite wait |
| Reused image sections and DLL loads | SEC_IMAGE acceptance plus measured reuse/DLL coverage and documented bypasses |
| Ordinary-user malformed/duplicate IPC and handle passing | Cannot connect to scan/abort ports or forge a verdict |
| Sleep/resume, low memory, disk fault, reboot | Driver Verifier clean, recovery path works, no boot failure |
| HVCI/Memory Integrity + other antivirus filters | Signed package loads and coexists under normal security settings |
| False positives, latency, corpus effectiveness | Published representative measurements, not just EICAR/inert tests |
| Service upgrades/removal | Stop succeeds, handles drain, signed files cannot be replaced by a standard user |

For this manual-start lab service, rollback is: stop `AntiOSNative`, wait for
`STOPPED`, delete that SCM service, unload the filter and remove its **specific**
Windows driver package using the recorded published INF name. Remove the
`Program Files\AntiOSNative` folder only after the service has been removed.
Do not delete unrelated driver packages or force-delete binaries while running.
Production update/uninstall and PPL self-update lifecycle are still pending.

## Protected service and primary antivirus gates

The status command implements truthful inspection; it does not grant PPL.
A legitimate protected anti-malware service requires ELAM eligibility, a signed
ELAM resource registering the service certificate, page-hash signing and compliant
DLLs. The isolated ClamD engine, updater, database ACLs and authenticated broker-to-
engine identity must also be designed and validated before a tamper-protection
claim. This repository does not contain those credentials or program approvals.
Windows Security Center registration is a separate external integration gate.

## Provenance and license

The native module is **MS-PL**, with the full license in
`windows/LICENSE.microsoft`; the Python AntiOS application remains Apache-2.0.
The filter/inc foundation comes from
[Microsoft Windows-driver-samples / AvScan](https://github.com/microsoft/Windows-driver-samples/tree/2dc3fd3a0cc84a2933f2194e7ec0871584979071/filesys/miniFilter/avscan).
Microsoft copyright notices are retained. AntiOS modifications include the native
ClamD boundary, rebuilt user transport/SCM host, default-audit execute-only policy,
bounded waits/admission, IPC validation/status, disabled demo matcher/cache, build
and acceptance tooling. No ClamAV binary/database is redistributed here.

Technical references:

- [Data-scan sections](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltcreatesectionfordatascan)
- [Process callback restrictions](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager)
- [Minifilter INF requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver)
- [Altitude request](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request)
- [Protected anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
