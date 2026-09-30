from antios.core import (
    apply_plan,
    generate_plan,
    random_computer_name,
    restore,
    snapshot,
)
from antios.registry import MemoryRegistryBackend
from antios.targets import MUTABLE_TARGETS


def _initial():
    return {
        target.key: (
            "OLD-PC" if target.name == "ComputerName" else "Old Owner",
            1,
        )
        for target in MUTABLE_TARGETS
    }


def test_random_computer_name_is_windows_friendly():
    name = random_computer_name("lab!")
    assert name.startswith("LAB-")
    assert len(name) <= 15
    assert name.replace("-", "").isalnum()


def test_apply_defaults_to_dry_run():
    backend = MemoryRegistryBackend(_initial())
    plan = generate_plan("NEW-PC", "New Owner")

    operations = apply_plan(backend, plan, dry_run=True)

    assert operations
    assert all(item["dry_run"] for item in operations)
    assert backend.read(MUTABLE_TARGETS[0]).value == "Old Owner"


def test_backup_apply_restore_round_trip():
    backend = MemoryRegistryBackend(_initial())
    backup = snapshot(backend)

    apply_plan(
        backend,
        generate_plan("NEW-PC", "New Owner"),
        dry_run=False,
    )

    assert any(
        backend.read(target).value == "NEW-PC"
        for target in MUTABLE_TARGETS
        if target.name == "ComputerName"
    )

    restore(backend, backup, dry_run=False)

    for target in MUTABLE_TARGETS:
        expected = "OLD-PC" if target.name == "ComputerName" else "Old Owner"
        assert backend.read(target).value == expected


def test_restore_ignores_unapproved_registry_paths():
    backend = MemoryRegistryBackend(_initial())
    backup = snapshot(backend)
    backup["entries"].append({
        "target": {
            "hive": "HKLM",
            "path": r"SOFTWARE\Danger",
            "name": "MachineGuid",
            "kind": "string",
            "mutable": True,
            "description": "",
        },
        "exists": True,
        "value": "crafted",
        "reg_type": 1,
        "error": None,
    })

    operations = restore(backend, backup, dry_run=False)

    assert all("Danger" not in item["target"] for item in operations)
