# AntiOS public prerelease вЂ” v2.0.0-alpha.35

This release improves Windows protection-engine installation and resident protection reliability.

- The Windows installer and repair action can restore missing engine settings on 64-bit systems.
- Guard can restore access to existing user state files during explicitly approved reconfiguration while retaining scan history.
- The recovery path preserves unrelated user files and does not alter Microsoft Defender or other antivirus settings.

If an older Guard state directory was created with administrator-only permissions, a one-time elevated AntiOS session may be necessary to reconfigure Guard. Actual protection is not assumed active until the engine and Guard independently report healthy status.

Public notes intentionally omit implementation-level security details. For usage, limitations, privacy information and responsible vulnerability reporting, see `README.md`, `PRIVACY.md` and `SECURITY.md`.

AntiOS v2 remains prerelease companion software.
