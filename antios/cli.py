from __future__ import annotations

import argparse
import ctypes
import json
import sys
from pathlib import Path

from .build_info import render_version, version_info
from .config import default_config_path, load_config, write_default_config
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
from .logging_utils import configure_logging
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
    parser.add_argument(
        "--version",
        action="version",
        version=render_version(),
        help="Show AntiOS version and exit.",
    )
    parser.add_argument(
        "--config",
        help="Path to antios.toml. Defaults to the per-user configuration path.",
    )
    parser.add_argument(
        "--log-file",
        help="Override the configured log file for this invocation.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors for this invocation.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    version_cmd = sub.add_parser("version", help="Show AntiOS and Python versions.")
    version_cmd.add_argument("--json", action="store_true")

    config_cmd = sub.add_parser("config", help="Inspect or initialize AntiOS configuration.")
    config_sub = config_cmd.add_subparsers(dest="config_command", required=True)
    config_show = config_sub.add_parser("show", help="Show effective configuration.")
    config_show.add_argument("--json", action="store_true")
    config_init = config_sub.add_parser("init", help="Create a default configuration file.")
    config_init.add_argument("--force", action="store_true", help="Overwrite an existing config.")

    scan_cmd = sub.add_parser(
        "scan",
        help="Read Windows identity, version and platform-security metadata.",
    )
    scan_cmd.add_argument("--json", action="store_true")

    doctor_cmd = sub.add_parser(
        "doctor",
        help="Check the runtime and report Windows security/inventory warnings.",
    )
    doctor_cmd.add_argument("--json", action="store_true")

    plan = sub.add_parser("plan", help="Generate a reversible metadata-change plan.")
    plan.add_argument("--computer-name")
    plan.add_argument("--registered-owner")

    backup = sub.add_parser("backup", help="Back up v2-mutable metadata before a change.")
    backup.add_argument("path", nargs="?")

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
        help="Backup path created immediately before a real write.",
    )
    apply_cmd.add_argument("--json", action="store_true")

    restore_cmd = sub.add_parser("restore", help="Preview or restore from a v2 backup.")
    restore_cmd.add_argument("path")
    restore_cmd.add_argument(
        "--yes",
        action="store_true",
        help="Actually restore. Without --yes, restore is a dry run.",
    )
    restore_cmd.add_argument("--json", action="store_true")

    return parser


def _render_config(config_path: Path, config: object) -> str:
    cfg = config.to_dict()
    general = cfg["general"]
    logging_cfg = cfg["logging"]
    return "\n".join([
        "AntiOS v2 configuration",
        "=======================",
        f"Path                 : {config_path}",
        f"Computer name prefix : {general['computer_name_prefix']}",
        f"Default backup path  : {general['backup_path']}",
        f"Color                : {general['color']}",
        f"Log level            : {logging_cfg['level']}",
        f"Log file             : {logging_cfg['file'] or '(disabled)'}",
    ])


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config_path = Path(args.config) if args.config else default_config_path()

    try:
        if args.command == "config" and args.config_command == "init":
            created = write_default_config(config_path, overwrite=args.force)
            print(f"Created configuration: {created}")
            return 0

        config = load_config(config_path)
        log_file = args.log_file if args.log_file is not None else config.logging.file
        logger = configure_logging(config.logging.level, log_file)
        logger.info("command=%s", args.command)

        color_mode = "never" if args.no_color else config.general.color
        use_color = color_enabled(mode=color_mode)

        if args.command == "version":
            if args.json:
                _print_json(version_info())
            else:
                print(render_version())
            return 0

        if args.command == "config":
            if args.config_command == "show":
                if args.json:
                    _print_json({
                        "path": str(config_path),
                        "config": config.to_dict(),
                    })
                else:
                    print(_render_config(config_path, config))
                return 0

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
            _print_json(generate_plan(
                args.computer_name,
                args.registered_owner,
                computer_name_prefix=config.general.computer_name_prefix,
            ).to_dict())
            return 0

        if args.command == "backup":
            target = args.path or config.general.backup_path
            out = save_backup(target, snapshot(backend, computer_backend))
            logger.info("backup-created path=%s", out)
            _print_json({"backup": str(out.resolve())})
            return 0

        if args.command == "apply":
            plan_data = generate_plan(
                args.computer_name,
                args.registered_owner,
                computer_name_prefix=config.general.computer_name_prefix,
            )
            dry_run = not args.yes
            backup_path: Path | None = None
            backup_target = args.backup or config.general.backup_path

            if not dry_run:
                if not _is_admin():
                    raise PermissionError("Administrator privileges are required for system writes.")
                backup_path = save_backup(
                    backup_target,
                    snapshot(backend, computer_backend),
                ).resolve()
                logger.info("apply backup-created path=%s", backup_path)

            operations = apply_plan(
                backend,
                plan_data,
                computer_backend=computer_backend,
                dry_run=dry_run,
            )
            logger.info(
                "apply dry_run=%s changed=%d reboot=%s",
                dry_run,
                sum(1 for item in operations if item.get("changed")),
                any(item.get("changed") and item.get("requires_reboot") for item in operations),
            )
            payload = {
                "plan": plan_data.to_dict(),
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
            logger.info(
                "restore dry_run=%s changed=%d reboot=%s",
                dry_run,
                sum(1 for item in operations if item.get("changed")),
                any(item.get("changed") and item.get("requires_reboot") for item in operations),
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
        try:
            logger.error("command failed: %s", exc)
        except UnboundLocalError:
            pass
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1
