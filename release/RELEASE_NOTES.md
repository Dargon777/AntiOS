# AntiOS v2.0.0 alpha 17

Alpha 17 removes the console-window noise around normal desktop use and tightens
the Windows helper boundary.

## Quiet desktop runtime

Background health checks, Secure Boot/TPM reads, Defender actions, quarantine
ACL work, scan workers, Guard, protection repair and update verification now
launch Windows console helpers without creating visible terminal windows.

Setup and uninstall use NSIS `nsExec` for protection PowerShell scripts, so the
installer no longer flashes PowerShell consoles while ClamAV/Guard are prepared
or removed. The normal Windows UAC consent dialog remains visible by design.

Security-sensitive Windows tools are resolved from `System32` instead of
relying on `PATH` lookup.

## Reliability

Scan reports now use the actual AntiOS package version rather than a stale alpha
1 constant. The Resident Guard quarantine regression test also waits for the
Guard engine to reach its monitoring state before creating the test file,
removing a startup timing race seen on loaded Windows runners.
