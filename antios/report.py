from __future__ import annotations

from typing import Any


def _yn(value: Any) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _value(value: Any) -> str:
    return "unknown" if value in (None, "") else str(value)


def render_scan_human(data: dict[str, Any]) -> str:
    info = data.get("system", {})
    host = info.get("host", {})
    win = info.get("windows", {})
    sec = info.get("security", {})
    runtime = info.get("runtime", {})

    secure_boot = sec.get("secure_boot", {})
    tpm = sec.get("tpm", {})

    lines = [
        "AntiOS v2 system scan",
        "======================",
        "",
        "Host",
        f"  Computer name : {_value(host.get('computer_name'))}",
        f"  User          : {_value(host.get('user'))}",
        f"  Architecture  : {_value(host.get('architecture'))}",
        f"  Processor     : {_value(host.get('processor'))}",
        "",
        "Windows",
        f"  Product       : {_value(win.get('product_name'))}",
        f"  Edition       : {_value(win.get('edition_id'))}",
        f"  Version       : {_value(win.get('display_version'))}",
        f"  Build         : {_value(win.get('full_build'))}",
        f"  Install type  : {_value(win.get('installation_type'))}",
        f"  Owner         : {_value(win.get('registered_owner'))}",
        "",
        "Platform security",
        f"  Secure Boot   : {_yn(secure_boot.get('enabled'))}",
        f"  TPM present   : {_yn(tpm.get('present'))}",
        f"  TPM ready     : {_yn(tpm.get('ready'))}",
        f"  TPM vendor    : {_value(tpm.get('manufacturer'))}",
        f"  TPM version   : {_value(tpm.get('version'))}",
        "",
        "Runtime",
        f"  Python        : {_value(runtime.get('python'))}",
        f"  Implementation: {_value(runtime.get('python_implementation'))}",
        "",
        "Read-only identifiers",
    ]

    for entry in data.get("registry", []):
        target = entry.get("target", {})
        name = target.get("name", "unknown")
        description = target.get("description") or ""
        value = entry.get("value") if entry.get("exists") else None
        suffix = f" — {description}" if description else ""
        lines.append(f"  {name}: {_value(value)}{suffix}")

    return "\n".join(lines)
