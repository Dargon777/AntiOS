from __future__ import annotations

import json
import platform
import re
import secrets
import string
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import IdentityPlan, RegistryTarget
from .registry import RegistryBackend
from .targets import ALL_TARGETS, MUTABLE_BY_KEY, MUTABLE_TARGETS

BACKUP_SCHEMA = "antios-v2-backup-1"


def scan(backend: RegistryBackend) -> dict[str, Any]:
    values = [backend.read(target).to_dict() for target in ALL_TARGETS]
    return {
        "antios_version": "2.0.0a1",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "registry": values,
    }


def random_computer_name(prefix: str = "LAB") -> str:
    clean = re.sub(r"[^A-Za-z0-9-]", "", prefix.upper())[:6] or "LAB"
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(8))
    # Windows computer names should remain short and uncomplicated.
    return f"{clean}-{suffix}"[:15]


def random_registered_owner() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "User-" + "".join(secrets.choice(alphabet) for _ in range(8))


def generate_plan(
    computer_name: str | None = None,
    registered_owner: str | None = None,
) -> IdentityPlan:
    return IdentityPlan(
        computer_name=computer_name or random_computer_name(),
        registered_owner=registered_owner or random_registered_owner(),
    )


def plan_changes(plan: IdentityPlan) -> list[tuple[RegistryTarget, str]]:
    changes: list[tuple[RegistryTarget, str]] = []
    for target in MUTABLE_TARGETS:
        if target.name == "RegisteredOwner" and plan.registered_owner is not None:
            changes.append((target, plan.registered_owner))
        elif target.name == "ComputerName" and plan.computer_name is not None:
            changes.append((target, plan.computer_name))
    return changes


def snapshot(backend: RegistryBackend) -> dict[str, Any]:
    entries = [backend.read(target).to_dict() for target in MUTABLE_TARGETS]
    return {
        "schema": BACKUP_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }


def save_backup(path: str | Path, data: dict[str, Any]) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def load_backup(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("schema") != BACKUP_SCHEMA:
        raise ValueError("Unsupported or invalid AntiOS backup schema")
    return data


def apply_plan(backend: RegistryBackend, plan: IdentityPlan, dry_run: bool = True) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for target, new_value in plan_changes(plan):
        before = backend.read(target)
        item = {
            "target": target.key,
            "description": target.description,
            "before": before.value if before.exists else None,
            "after": new_value,
            "changed": before.value != new_value,
            "dry_run": dry_run,
        }
        operations.append(item)
        if not dry_run and item["changed"]:
            backend.write(target, new_value, before.reg_type)
    return operations


def restore(backend: RegistryBackend, backup: dict[str, Any], dry_run: bool = True) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for entry in backup.get("entries", []):
        target_data = entry.get("target", {})
        key = f"{target_data.get('hive')}\\{target_data.get('path')}::{target_data.get('name')}"
        target = MUTABLE_BY_KEY.get(key)
        if target is None:
            # Never trust arbitrary paths from a backup file.
            continue
        if not entry.get("exists"):
            continue
        current = backend.read(target)
        new_value = entry.get("value")
        item = {
            "target": target.key,
            "before": current.value if current.exists else None,
            "after": new_value,
            "changed": current.value != new_value,
            "dry_run": dry_run,
        }
        operations.append(item)
        if not dry_run and item["changed"]:
            backend.write(target, new_value, entry.get("reg_type"))
    return operations
