# AntiOS Linux Companion

Linux support is a **supplemental companion mode**, not an attempt to replace a
vendor's real-time endpoint product.

## Supported scope

Initial Linux support covers:

- read-only Linux system/health status;
- on-demand AntiOS ClamAV second-opinion scanning;
- Storage Cleanup and Storage Intelligence features;
- detection of Kaspersky Endpoint Security for Linux;
- detection of Dr.Web for Linux / Dr.Web Security Space command-line control;
- a small optional Tk desktop dashboard;
- explicit, opt-in AntiOS Guard only when the user chooses to run it.

AntiOS does **not** install, disable, stop, reconfigure or add exclusions to
Kaspersky or Dr.Web. It also does not automatically launch vendor scan tasks.
That avoids accidentally inheriting a vendor remediation policy and avoids
stacking heavyweight on-demand scans on low-end systems.

## Kaspersky coexistence

AntiOS recognizes the vendor control tool kesl-control only from trusted
system/vendor locations. It uses documented read-only application status and
task-state commands to determine whether Kaspersky is present and whether File
Threat Protection can be confirmed active.

When Kaspersky real-time protection is confirmed, AntiOS recommends leaving
Resident Guard opt-in and using AntiOS primarily for second-opinion manual
ClamAV scans, storage analysis and diagnostics.

Official documentation:
https://support.kaspersky.com/help/KES4Linux/12.3.0/en-US/

## Dr.Web coexistence

AntiOS recognizes drweb-ctl only from trusted system/vendor locations. It uses
--version and the documented appinfo status command. No configuration commands
are issued.

Official documentation:
https://cdn-download.drweb.com/pub/drweb/unix/workstation/11.1/business/documentation/html/en/ctl.htm

## ClamAV requirement

AntiOS Linux scanning uses a local ClamD endpoint on 127.0.0.1:3310.
Distribution packaging and service configuration differ, so AntiOS does not
silently install or reconfigure ClamAV.

For Debian/Ubuntu, distro packages commonly start with:

    sudo apt install clamav-daemon
    sudo systemctl enable --now clamav-daemon

Verify your distribution's package/service names before applying commands.

Then:

    antios coexistence-status
    antios protection-status
    antios quick-check
    antios virus-scan ~/Downloads --engine clamav

The Linux dashboard is optional and requires Tk, often packaged as python3-tk:

    antios dashboard

## Security boundaries

- No shell is used for vendor status commands.
- Vendor executables must resolve below trusted system/vendor directories.
- No sudo is invoked by AntiOS.
- No vendor service start/stop commands are issued.
- No vendor exclusions are created.
- Vendor-specific quarantine is not controlled by AntiOS.
- AntiOS encrypted quarantine currently remains Windows-only because its
  existing design relies on Windows DPAPI.
- AntiOS does not claim primary-antivirus registration on Linux.

Linux support is intentionally additive: the existing vendor product owns its
real-time policy; AntiOS supplies independent analysis around it.
