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
from .registry import WindowsRegistryBackend, is_windows


def _print(data: object) -> None:
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

    sub.add_parser("scan", help="Read a small, documented set of Windows identity metadata.")

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

    restore_cmd = sub.add_parser("restore", help="Preview or restore from a v2 backup.")
    restore_cmd.add_argument("path")
    restore_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually restore. Without --yes, restore is a dry run.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        backend = _backend()

        if args.command == "scan":
            _print(scan(backend))
            return 0

        if args.command == "plan":
            _print(generate_plan(args.computer_name, args.registered_owner).to_dict())
            return 0

        if args.command == "backup":
            out = save_backup(args.path, snapshot(backend))
            _print({"backup": str(out.resolve())})
            return 0

        if args.command == "apply":
            plan = generate_plan(args.computer_name, args.registered_owner)
            dry_run = not args.yes
            if not dry_run:
                if not _is_admin():
                    raise PermissionError("Administrator privileges are required for registry writes.")
                save_backup(args.backup, snapshot(backend))
            _print({
                "plan": plan.to_dict(),
                "operations": apply_plan(backend, plan, dry_run=dry_run),
                "note": (
                    "Dry run only. Re-run with --yes to write."
                    if dry_run
                    else f"Changes written. Backup: {Path(args.backup).resolve()}"
                ),
            })
            return 0

        if args.command == "restore":
            dry_run = not args.yes
            if not dry_run and not _is_admin():
                raise PermissionError("Administrator privileges are required for registry writes.")
            data = load_backup(args.path)
            _print({
                "operations": restore(backend, data, dry_run=dry_run),
                "note": "Dry run only." if dry_run else "Restore completed.",
            })
            return 0

    except (OSError, RuntimeError, PermissionError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1
