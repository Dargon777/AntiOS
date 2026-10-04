# Full Windows antivirus replacement: readiness gates

AntiOS is not yet a complete or certified replacement for Microsoft Defender.
A Store listing, a code-signing certificate and a background process do not by
themselves supply prevention, tamper protection or Windows antivirus registration.

| Component | Current state | Remaining acceptance condition |
| --- | --- | --- |
| Independent content detection | Managed ClamAV is the default engine; Setup bootstraps a pinned official x64 package, verifies SHA-256/AuthentiCode and binds scans to the verified ClamD service peer | Representative malware/benign corpus testing, measured false positives and performance |
| Resident scanning | Selected-folder post-write Guard with bounded queue/recovery; normal same-user Setup enables it for Downloads/Desktop/Documents after engine bootstrap | Windows load, sleep/resume, removable media, disk-error and long-running tests |
| Remediation | DPAPI quarantine with stable-file revalidation, SHA-256 restore checks, hardened Windows ACL and whole-vault integrity verification | Windows failure/recovery matrix and service-owned quarantine design for broader machine-wide remediation |
| Updates | Setup bootstrap + pinned engine manifest + FreshClam SYSTEM task; protection-repair can restore service/ACL/task state; AntiOS updater verifies release hash and requires Authenticode before automatic install | Enable release Trusted Signing, long-running failure/recovery telemetry and signed engine/version policy |
| Pre-execution prevention | Experimental execute-open minifilter + native ClamD broker; VM acceptance now requires FILE_EXECUTE, CreateProcess and SEC_IMAGE mapping coverage | Signed deployment, concurrency/Driver Verifier/HVCI acceptance and Microsoft-assigned altitude |
| Windows service | Native SCM service diagnostics plus Python/Guard binding to a verified own-process LocalSystem ClamD peer | Signed Windows installation, stop/recovery, native service PPL path and full upgrade lifecycle |
| Boot protection / protected service | ELAM/PPL not implemented; SCM service is not protected | ELAM eligibility, page-hash signing, protected dependencies/engine and Windows integration |
| Primary antivirus registration | Not implemented | Applicable Microsoft partner onboarding and documented integration |
| Publisher/driver identity | Unresolved | Required account verification, trusted signing and driver signing approvals |
| Independent effectiveness certification | Not performed | External laboratory certification and ongoing maintenance |
| Store delivery | Existing dashboard package only | Packaging, background lifecycle, restricted-capability review and installed-package tests |

Do not switch off Defender, write fake Security Center registration data, enable
Windows test-signing, disable Secure Boot, or report `protected` merely to make
this table look complete. None of these actions adds missing detection or
prevention capability. No such changes are made by this implementation.

Microsoft's [MVI criteria](https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria)
currently require a commercially available real-time solution, ongoing updates,
industry standing, agreements, Trusted Signing and independent certification.
[ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites)
require MVI membership for the early-launch submission route.
[Protected antimalware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
require an ELAM driver and appropriate signing of the service and dependencies.
These are external program and validation gates; code changes cannot grant them.

The repository now also exposes `antios protection-status`, which reports engine
freshness/identity, Resident Guard state and native service/driver enforcement
separately. It deliberately keeps `production_primary_antivirus=false` while the
external registration/certification gates remain unresolved.

Next engineering work should happen in disposable Windows VMs with rollback:
exercise the full Setup/bootstrap/repair/update lifecycle, validate Guard under
sleep/resume and failure injection, run the
[native boundary acceptance matrix](../native/README.md) including SEC_IMAGE,
obtain a Microsoft minifilter altitude and production driver signing, and
measure real-world detection/false positives. Do not deploy an untested
filesystem filter to users.
