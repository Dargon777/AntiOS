# AntiOS v2.0.0 alpha 21

Alpha 21 turns the antivirus work into one layered protection stack.

Microsoft Defender can stay active while AntiOS runs its own managed ClamAV
engine, Resident Guard and optional native protection. The new x64 AntiOS AMSI
provider adds an independent AMSI scanning layer without taking the Windows
Security primary-antivirus slot or changing Defender settings.

Resident Guard now combines fast handling for executable/script writes with
detect-only behavior correlation, RiskContext fusion and a bounded Incident
Graph. Incident Viewer and Response Center make those chains inspectable and let
the user rescan linked files, open their location, export a report and isolate
only freshly confirmed scanner threats after explicit confirmation.

The experimental native minifilter gained bounded coexistence telemetry,
clean-verdict caching tied to the current ClamAV database generation and a
Defender-active stress harness. It remains lab-only until Microsoft-assigned
altitude, production driver signing, HVCI/Driver Verifier and disposable-VM
acceptance are complete.

The Setup/release path can stage and register the AMSI provider only when the DLL
has a valid Authenticode signature. No Defender exclusions, Security Center
spoofing, AMSI policy weakening or test-signing bypasses are introduced.
