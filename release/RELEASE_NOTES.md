# AntiOS v2.0.0 alpha 25

Alpha 25 defines the supported desktop Windows baseline down to Windows 10 22H2 x64.

## Windows 10 support target

AntiOS now treats **Windows 10 22H2 x64, build 19045** as the minimum supported desktop Windows version. Windows 11 remains supported. Older Windows 10 builds and 32-bit Windows are outside the supported target.

System inventory now records an explicit compatibility result, and `doctor` reports unsupported Windows builds instead of merely identifying the Windows generation.

## Packaging alignment

The Microsoft Store package minimum version is aligned to Windows 10 build 19045.

The experimental native filter INF is also aligned to build 19045+ instead of being restricted to build 26100. The native filter is compiled against the base Windows 10 API contract so accidental dependencies on newer Windows-only declarations are caught by the native build.

The native filter remains experimental and still requires its existing production signing, altitude and validation gates.

## Compatibility validation

CI adds a legacy Windows API proxy job on the older Windows Server 2019 runner. This is intentionally **not** presented as Windows 10 certification; it is an extra regression check against accidentally introducing newer Win32 dependencies.

A real Windows 10 22H2 build 19045 VM or physical-machine acceptance run is still required before calling Windows 10 field-validated.

Microsoft Defender configuration remains unchanged.
