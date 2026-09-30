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
        "CurrentBuild",
        description="Current Windows build",
    ),
    RegistryTarget(
        "HKLM",
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "DisplayVersion",
        description="Windows display version",
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

ALL_TARGETS = READ_ONLY_TARGETS + MUTABLE_TARGETS
MUTABLE_BY_KEY = {target.key: target for target in MUTABLE_TARGETS}
