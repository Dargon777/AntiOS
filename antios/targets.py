from __future__ import annotations

from .models import RegistryTarget

# Values useful for understanding the local Windows identity. They are scanned
# only; v2 deliberately does not modify licensing, hardware, telemetry, update,
# storage or network-adapter identifiers.
READ_ONLY_TARGETS: tuple[RegistryTarget, ...] = (
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Cryptography",
        "MachineGuid",
        description="Windows MachineGuid (read-only in AntiOS v2)",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductId",
        description="Windows ProductId (read-only in AntiOS v2)",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "ProductName",
        description="Windows product name",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "EditionID",
        description="Windows edition identifier",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "DisplayVersion",
        description="Windows display version",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuild",
        description="Current Windows build",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
        description="Current Windows build number",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "UBR",
        kind="dword",
        description="Windows update build revision",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "InstallationType",
        description="Windows installation type",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "RegisteredOwner",
        description="Registered owner display metadata",
    ),
)

# v2 writes only ordinary user-facing system metadata, through a small explicit
# allowlist. This is intentionally much narrower than the 2019 implementation.
MUTABLE_TARGETS: tuple[RegistryTarget, ...] = (
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "RegisteredOwner",
        mutable=True,
        description="Registered owner display metadata",
    ),
    RegistryTarget(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
        "ComputerName",
        mutable=True,
        description="Configured computer name",
    ),
    RegistryTarget(
        "HKLM",
        r"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
        "ComputerName",
        mutable=True,
        description="Active computer name",
    ),
)

# Deduplicate RegisteredOwner while retaining the mutable target for writes.
ALL_TARGETS = READ_ONLY_TARGETS + tuple(
    target for target in MUTABLE_TARGETS
    if target.key not in {item.key for item in READ_ONLY_TARGETS}
)
MUTABLE_BY_KEY = {target.key: target for target in MUTABLE_TARGETS}
