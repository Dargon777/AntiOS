# AntiOS public prerelease — v2.0.0-alpha.37

This release adds a local protection assistant to the Windows antivirus center.

- Self-check uses harmless test data to verify the scanning engine and a temporary backup recovery round trip, with clear next steps when a check needs attention.
- Snapshot comparison shows added, changed and removed files. Earlier changed copies can be recovered into a new folder.
- Activity explanations describe recorded evidence in plain language and distinguish confirmed detections, incomplete scans and behavior that needs review.
- Standard Windows sessions keep engine status visible even when protected installation settings cannot be inspected.

Open Antivirus → Assistant to use the new workspace. The command line also supports antios self-check --json.

All explanations are generated locally. Self-check results describe the moment of testing; they do not guarantee detection of every threat. Snapshot features remain file-level backup tools.

AntiOS v2 remains prerelease companion software.
