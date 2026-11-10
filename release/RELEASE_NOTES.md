# AntiOS 3.0.01 Alpha — preview

AntiOS 3 introduces an independent, locally running antivirus scan engine and updated application packaging.

- On-demand scans, the desktop application and optional resident monitoring now use the AntiOS engine.
- Previous external antivirus-engine runtime requirements have been retired.
- Existing Windows Defender coexistence remains read-only; AntiOS does not disable third-party protection.
- Archive and file inspection is bounded. Unverified or partially inspected files are not claimed to be safe.

**Important upgrade notice:** Some existing 2.x installations cannot be upgraded in place. The installer will refuse an unsafe mixed installation rather than silently remove older services or settings. Follow verified migration instructions before upgrading.

**Limitations:** This is an early alpha with a small local signature database. Detection coverage is not comparable to mature commercial antivirus products. Do not rely on it as your only endpoint protection.

The pre-release remains unverified for broad production rollout. Public Windows distributions require valid code signing and release acceptance.
