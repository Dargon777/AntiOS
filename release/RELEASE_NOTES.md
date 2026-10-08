# AntiOS v2.0.0 alpha 26

Alpha 26 is a full desktop interface redesign. The protection backend, Guard,
quarantine and update safety rules remain the same; the desktop experience is
rebuilt around a consistent endpoint-security design system.

## New design system

- new graphite / emerald / cyan palette with restrained semantic use of amber
  and red;
- 8 px base rhythm with larger spacing following a phi-like progression
  (8 / 13 / 21 / 34 / 55);
- unified card, button, navigation, table and status hierarchy;
- Windows 10-safe Segoe UI typography;
- quieter borders, stronger contrast hierarchy and clearer primary actions.

The large protection visuals use a restrained logarithmic / golden-ratio-style
orbit motif as a visual identity element. It is decorative only and never
replaces real status text.

## New Overview

The Overview is rebuilt as a protection dashboard instead of the legacy
read-only diagnostics landing page. It now prioritizes:

- current protection state;
- a transparent protection-health score derived from AntiOS health checks;
- Resident Guard state;
- Defender coexistence state;
- engine / signature summary;
- the most relevant recent system checks;
- direct paths into Antivirus, Windows Security and Updates.

## New Antivirus screen

The Antivirus page now has:

- a large Resident Guard protection hero;
- live protection score and Guard status;
- dedicated cards for Guard, behavior analysis, file monitoring and engine
  state;
- a clearer scan target / scan action workflow;
- component health summary;
- findings and quarantine kept in the same operational page;
- advanced engine, signature and Defender tools retained as secondary controls.

All existing backend operations remain connected to the redesigned widgets.

## New Settings

Settings is reorganized into a two-column control surface with clear sections
for appearance, language, Resident Guard startup, cleanup defaults, updates and
product information.

The update area now exposes an explicit **Open folder** action for downloaded
updates while keeping the existing SHA-256 / GitHub digest / Authenticode safety
policy. Unsigned installers are still never launched automatically.

## Product language

Top-level copy has been updated to reflect AntiOS as an endpoint-security
product rather than the older health-dashboard wording.

## Compatibility

The redesign keeps the Alpha 25 support target: Windows 10 22H2 x64 (build
19045) and newer Windows 11 builds. No Windows 11-only UI font is required.
