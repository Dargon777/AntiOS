from __future__ import annotations

from typing import Any


def _check(
    id: str,
    level: str,
    title: str,
    detail: str,
    action: str | None = None,
    settings_uri: str | None = None,
) -> dict[str, Any]:
    return {
        "id": id,
        "level": level,
        "title": title,
        "detail": detail,
        "action": action,
        "settings_uri": settings_uri,
    }


def _bitlocker_on(value: Any) -> bool | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"on", "1", "true"}:
        return True
    if normalized in {"off", "0", "false"}:
        return False
    return None


def evaluate_health(
    scan_data: dict[str, Any],
    health_data: dict[str, Any],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    storage = health_data.get("storage", {})
    if storage.get("available"):
        pct = storage.get("percent_free")
        free_gb = (storage.get("free_bytes") or 0) / (1024 ** 3)
        if pct is not None and (pct < 10 or free_gb < 10):
            checks.append(_check(
                "storage", "warn", "Storage space",
                f"Only {pct:.1f}% ({free_gb:.1f} GB) is free on the system drive.",
                "Free up storage space.",
                "ms-settings:storagesense",
            ))
        elif pct is not None and pct < 20:
            checks.append(_check(
                "storage", "advisory", "Storage space",
                f"{pct:.1f}% ({free_gb:.1f} GB) is free on the system drive.",
                "Review storage usage when convenient.",
                "ms-settings:storagesense",
            ))
        else:
            checks.append(_check(
                "storage", "ok", "Storage space",
                f"{pct:.1f}% free on the system drive." if pct is not None else "Storage is available.",
            ))
    else:
        checks.append(_check(
            "storage", "info", "Storage space",
            "Storage status could not be read.",
        ))

    defender = health_data.get("defender", {})
    if defender.get("available"):
        antivirus = defender.get("antivirus_enabled")
        realtime = defender.get("real_time_protection")
        if antivirus is False or realtime is False:
            checks.append(_check(
                "defender", "warn", "Microsoft Defender",
                "Microsoft Defender antivirus or real-time protection is not active.",
                "Review Windows Security.",
                "windowsdefender:",
            ))
        elif antivirus is True and realtime is True:
            age = defender.get("signature_age_days")
            detail = "Antivirus and real-time protection are active."
            if isinstance(age, int):
                detail += f" Signatures are {age} day(s) old."
            checks.append(_check("defender", "ok", "Microsoft Defender", detail))
        else:
            checks.append(_check(
                "defender", "info", "Microsoft Defender",
                "Defender status is partially available; another security product may be active.",
                "Review Windows Security.",
                "windowsdefender:",
            ))
    else:
        checks.append(_check(
            "defender", "info", "Microsoft Defender",
            "Defender status could not be queried. A third-party antivirus or Windows edition may affect this check.",
            "Review Windows Security.",
            "windowsdefender:",
        ))

    bitlocker = health_data.get("bitlocker", {})
    if bitlocker.get("available"):
        protected = _bitlocker_on(bitlocker.get("protection_status"))
        if protected is True:
            checks.append(_check(
                "bitlocker", "ok", "Device encryption",
                "BitLocker protection is on for the system drive.",
            ))
        elif protected is False:
            checks.append(_check(
                "bitlocker", "advisory", "Device encryption",
                "BitLocker protection is off for the system drive.",
                "Review device encryption if you want protection for data at rest.",
                "ms-settings:deviceencryption",
            ))
        else:
            checks.append(_check(
                "bitlocker", "info", "Device encryption",
                f"BitLocker status: {bitlocker.get('protection_status') or 'unknown'}.",
            ))
    else:
        checks.append(_check(
            "bitlocker", "info", "Device encryption",
            "BitLocker status is unavailable on this system.",
        ))

    pending = health_data.get("pending_reboot", {})
    if pending.get("available") and pending.get("pending"):
        checks.append(_check(
            "pending-reboot", "advisory", "Restart pending",
            "Windows has changes waiting for a restart.",
            "Restart when convenient to finish pending system work.",
            "ms-settings:windowsupdate",
        ))
    elif pending.get("available"):
        checks.append(_check(
            "pending-reboot", "ok", "Restart pending",
            "No common pending-restart markers were found.",
        ))
    else:
        checks.append(_check(
            "pending-reboot", "info", "Restart pending",
            "Pending-restart state could not be determined.",
        ))

    startup = health_data.get("startup", {})
    if startup.get("available"):
        count = int(startup.get("count") or 0)
        if count >= 20:
            checks.append(_check(
                "startup", "advisory", "Startup apps",
                f"{count} startup entries were found. A large startup set can make sign-in feel slower.",
                "Review startup apps and disable only software you recognize and do not need.",
                "ms-settings:startupapps",
            ))
        else:
            checks.append(_check(
                "startup", "ok", "Startup apps",
                f"{count} startup entr{'y' if count == 1 else 'ies'} found.",
                "Review startup apps if Windows sign-in feels slow." if count else None,
                "ms-settings:startupapps" if count else None,
            ))
    else:
        checks.append(_check(
            "startup", "info", "Startup apps",
            "Startup applications could not be enumerated.",
            "Review startup apps in Windows Settings.",
            "ms-settings:startupapps",
        ))

    security = scan_data.get("system", {}).get("security", {})
    secure_boot = security.get("secure_boot", {})
    if secure_boot.get("enabled") is True:
        checks.append(_check("secure-boot", "ok", "Secure Boot", "Secure Boot is enabled."))
    elif secure_boot.get("enabled") is False:
        checks.append(_check(
            "secure-boot", "advisory", "Secure Boot",
            "Secure Boot is disabled.",
            "Review firmware/security settings if your hardware supports Secure Boot.",
            "windowsdefender:",
        ))
    else:
        checks.append(_check(
            "secure-boot", "info", "Secure Boot",
            "Secure Boot status is unavailable.",
        ))

    tpm = security.get("tpm", {})
    if tpm.get("present") is True and tpm.get("ready") is True:
        checks.append(_check("tpm", "ok", "TPM", "TPM is present and ready."))
    elif tpm.get("present") is True:
        checks.append(_check(
            "tpm", "advisory", "TPM",
            "TPM is present but Windows does not report it as ready.",
            "Review Windows Security or firmware TPM settings.",
            "windowsdefender:",
        ))
    elif tpm.get("present") is False:
        checks.append(_check(
            "tpm", "info", "TPM",
            "TPM is not reported as present.",
        ))
    else:
        checks.append(_check("tpm", "info", "TPM", "TPM status is unavailable."))

    counts = {"ok": 0, "info": 0, "advisory": 0, "warn": 0}
    for item in checks:
        counts[item["level"]] = counts.get(item["level"], 0) + 1

    if counts["warn"]:
        overall = "needs-attention"
        headline = "Some items need attention"
    elif counts["advisory"]:
        overall = "review"
        headline = "Your PC looks okay, with a few things to review"
    else:
        overall = "good"
        headline = "Your PC looks good"

    return {
        "overall": overall,
        "headline": headline,
        "summary": counts,
        "checks": checks,
    }


def render_quick_check(data: dict[str, Any]) -> str:
    summary = data.get("summary", {})
    lines = [
        "AntiOS quick check",
        "==================",
        data.get("headline", "Windows check completed"),
        (
            f"OK {summary.get('ok', 0)}  |  "
            f"Review {summary.get('advisory', 0)}  |  "
            f"Warnings {summary.get('warn', 0)}  |  "
            f"Info {summary.get('info', 0)}"
        ),
        "",
    ]

    labels = {
        "ok": "OK",
        "info": "INFO",
        "advisory": "REVIEW",
        "warn": "WARN",
    }
    for item in data.get("checks", []):
        label = labels.get(str(item.get("level")), "INFO")
        lines.append(f"[{label}] {item.get('title')}")
        lines.append(f"  {item.get('detail')}")
        if item.get("action"):
            lines.append(f"  Suggestion: {item.get('action')}")
        lines.append("")

    return "\n".join(lines).rstrip()
