# Full Windows antivirus replacement: readiness gates

AntiOS is not yet a complete or certified replacement for Microsoft Defender.
A Store listing, a code-signing certificate and a background process do not by
themselves supply prevention, tamper protection or Windows antivirus registration.

| Component | Current state | Remaining acceptance condition |
| --- | --- | --- |
| Independent content detection | ClamAV integration; functional tests | Official-database and representative malware/benign corpus testing, measured false positives and performance |
| Resident scanning | Selected-folder, post-write Guard with bounded queue and recovery | Windows load, sleep/resume, removable media, disk-error and long-running tests |
| Remediation | Explicit opt-in DPAPI quarantine with revalidation | Windows failure/recovery matrix and safe update/uninstall testing |
| Updates | Separate official FreshClam | Supported deployment, update failure handling and operational monitoring on Windows |
| Pre-execution prevention | Experimental execute-open minifilter + native ClamD broker; default audit; compiled locally | Actual CreateProcess/section-reuse coverage, signed deployment, concurrency/Verifier and Windows acceptance |
| Windows service | Native SCM service and actual protection-level diagnostics implemented | Signed Windows installation, stop/recovery, authenticated engine identity and update lifecycle |
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

Next engineering work should happen in disposable Windows VMs with rollback:
validate Guard and its installer, run the [native boundary acceptance matrix](../native/README.md),
complete signed-driver Windows CI and failure-injection testing, and measure
real-world detection. The native source is deliberately excluded from the normal
release and Store package. Do not deploy an untested filesystem filter to users.
