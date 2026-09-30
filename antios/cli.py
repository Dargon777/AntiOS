from __future__ import annotations

import argparse
import ctypes
import json
import sys
from pathlib import Path

from .core import (
    apply_plan,
    generate_plan,
    load_backup,
    restore,
    save_backup,
    scan,
    snapshot,
)
from .doctor import diagnose
from .registry import WindowsRegistryBackend, is_windows
from .report import render_doctor_human, render_operations_human, render_scan_human
from .system_name import WindowsComputerNameBackend
from .terminal import color_enabled


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _require_windows() -> None:
    if not is_windows():
        raise RuntimeError("AntiOS v2 registry commands currently require Windows.")


def _backend() -> WindowsRegistryBackend:
    _require_windows()
    return WindowsRegistryBackend()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antios",
        description="AntiOS v2: auditable Windows privacy/system identity laboratory",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser(
        "scan",
        help="Read Windows identity, version and platform-security metadata.",
    )
    scan_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )

    doctor_cmd = sub.add_parser(
        "doctor",
        help="Check the AntiOS runtime and report useful Windows security/inventory warnings.",
    )
    doctor_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the human report.",
    )

    plan = sub.add_parser("plan", help="Generate a reversible metadata-change plan.")
    plan.add_argument("--computer-name")
    plan.add_argument("--registered-owner")

    backup = sub.add_parser("backup", help="Back up v2-mutable metadata before a change.")
    backup.add_argument("path", nargs="?", default="antios-backup.json")

    apply_cmd = sub.add_parser("apply", help="Preview or apply a v2 plan.")
    apply_cmd.add_argument("--computer-name")
    apply_cmd.add_argument("--registered-owner")
    apply_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually write changes. Without --yes, apply is a dry run.",
    )
    apply_cmd.add_argument(
        "--backup",
        default="antios-backup.json",
        help="Backup path created immediately before a real write.",
    )
    apply_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the change table.",
    )

    restore_cmd = sub.add_parser("restore", help="Preview or restore from a v2 backup.")
    restore_cmd.add_argument("path")
    restore_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually restore. Without --yes, restore is a dry run.",
    )
    restore_cmd.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of the change table.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    use_color = color_enabled()

    try:
        backend = _backend()
        computer_backend = WindowsComputerNameBackend()

        if args.command == "scan":
            data = scan(backend)
            if args.json:
                _print_json(data)
            else:
                print(render_scan_human(data, color=use_color))
            return 0

        if args.command == "doctor":
            data = diagnose(scan(backend))
            if args.json:
                _print_json(data)
            else:
                print(render_doctor_human(data, color=use_color))
            return int(data.get("exit_code", 0))

        if args.command == "plan":
            _print_json(generate_plan(args.computer_name, args.registered_owner).to_dict())
            return 0

        if args.command == "backup":
            out = save_backup(args.path, snapshot(backend, computer_backend))
            _print_json({"backup": str(out.resolve())})
            return 0

        if args.command == "apply":
            plan = generate_plan(args.computer_name, args.registered_owner)
            dry_run = not args.yes
            backup_path: Path | None = None
            if not dry_run:
                if not _is_admin():
                    raise PermissionError("Administrator privileges are required for system writes.")
                backup_path = save_backup(
                    args.backup,
                    snapshot(backend, computer_backend),
                ).resolve()

            operations = apply_plan(
                backend,
                plan,
                computer_backend=computer_backend,
                dry_run=dry_run,
            )
            payload = {
                "plan": plan.to_dict(),
                "operations": operations,
                "backup": str(backup_path) if backup_path else None,
                "note": (
                    "Dry run only. Re-run with --yes to write."
                    if dry_run
                    else "Changes written."
                ),
            }

            if args.json:
                _print_json(payload)
            else:
                print(render_operations_human(
                    operations,
                    title="AntiOS v2 apply plan",
                    dry_run=dry_run,
                    color=use_color,
                ))
                if backup_path:
                    print(f"Backup: {backup_path}")
            return 0

        if args.command == "restore":
            dry_run = not args.yes
            if not dry_run and not _is_admin():
                raise PermissionError("Administrator privileges are required for system writes.")

            data = load_backup(args.path)
            operations = restore(
                backend,
                data,
                computer_backend=computer_backend,
                dry_run=dry_run,
            )
            payload = {
                "operations": operations,
                "note": "Dry run only." if dry_run else "Restore completed.",
            }

            if args.json:
                _print_json(payload)
            else:
                print(render_operations_human(
                    operations,
                    title="AntiOS v2 restore plan",
                    dry_run=dry_run,
                    color=use_color,
                ))
            return 0

    except (OSError, RuntimeError, PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1
