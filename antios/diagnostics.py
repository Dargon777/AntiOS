"""Bounded, user-local diagnostics for AntiOS.

This is a journal, never a command interpreter. It stores sanitized structured
events per process, tolerates write failures without affecting antivirus work,
and exports only deliberately whitelisted information (no configs or samples).
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import threading
import uuid
from zipfile import ZIP_DEFLATED, ZipFile

_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_COMPONENTS = {
    "Guard", "ClamAV", "Scanner", "Quarantine", "Updater",
    "Installer", "Protection", "UI", "Defender", "System",
}
_MAX_BYTES = 1024 * 1024
_MAX_DETAIL = 7000
_MAX_FILES = 24
_IO_LOCK = threading.RLock()

# Never persist bearer tokens, email addresses or credentials in a support log.
_PRIVATE = (
    (re.compile(r"(?i)\bAuthorization\s*[:=]\s*(?:Bearer\s+)?[A-Za-z0-9._~+/\-]+=*"), "Authorization: [REDACTED]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-]{8,}=*"), "Bearer [REDACTED]"),
    (re.compile(r"(?i)\b(authorization|bearer|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*[^\s,;]+"), r"\1=[REDACTED]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"(?i)\b([?&](?:token|code|key|secret|password|auth|sig|signature)=)[^&\s]+"), r"\1[REDACTED]"),
)
_WINDOWS_HOME = re.compile(r"(?i)(?:[A-Z]:\\Users\\|/Users/)[^\\/\s]+")
_POSIX_HOME = re.compile(r"/home/[^/\s]+")
_SUPPORTED = {"ru", "en"}

_HELP = {
    "ENGINE_SIGNATURE_INVALID": {
        "ru": ("Не удалось подтвердить подпись ClamAV",
               "AntiOS не может доверять clamd.exe или freshclam.exe. Проверка не запускается, пока источник исполняемых файлов не подтверждён.",
               "Запустите «Восстановить защиту» через AntiOS. Если ошибка повторится, отправьте обезличенный отчёт разработчику. Не отключайте проверку подписей."),
        "en": ("ClamAV signature could not be verified",
               "AntiOS cannot trust clamd.exe or freshclam.exe and will not run unverified engine binaries.",
               "Use Repair protection in AntiOS. If it continues, export the redacted report. Do not disable signature checks."),
    },
    "ENGINE_NOT_READY": {
        "ru": ("Движок защиты недоступен",
               "ClamAV или его базы не готовы. AntiOS не считает такое состояние активной защитой.",
               "Проверьте состояние ClamAV, затем выполните восстановление защиты с подтверждением UAC."),
        "en": ("Protection engine not ready",
               "ClamAV or its databases are not ready. AntiOS does not claim protection in this state.",
               "Check ClamAV status, then run Repair protection with explicit UAC consent."),
    },
    "ELEVATION_REQUIRED": {
        "ru": ("Требуются права администратора",
               "Для изменения системного движка нужны отдельные повышенные права. Обычный интерфейс остаётся без них.",
               "Нажмите «Восстановить защиту» и подтвердите запрос UAC, если доверяете операции."),
        "en": ("Administrator approval required",
               "Machine-wide protection maintenance needs a separate elevated operation.",
               "Choose Repair protection and approve UAC only if you trust the operation."),
    },
    "OPERATION_FAILED": {
        "ru": ("Операция завершилась ошибкой",
               "Один из компонентов не выполнил запрос. Подробности доступны в техническом журнале.",
               "Проверьте источник и время события. При повторении экспортируйте обезличенный отчёт."),
        "en": ("Operation failed",
               "A component could not complete its operation. The technical details are in the journal.",
               "Check the component and timestamp. Export a redacted report if the error recurs."),
    },
    "OPERATION_STARTED": {
        "ru": ("Операция запущена", "AntiOS выполняет запрошенное действие.",
               "Дождитесь завершения или остановите проверку штатной кнопкой."),
        "en": ("Operation started", "AntiOS is performing the requested action.",
               "Wait for completion or use the normal Cancel action."),
    },
    "OPERATION_COMPLETED": {
        "ru": ("Операция завершена", "Запрошенное действие завершилось без исключения.",
               "Проверьте фактическое состояние компонента перед оценкой защищённости."),
        "en": ("Operation completed", "The requested operation returned without an exception.",
               "Check the component's actual state before assuming protection is active."),
    },
    "ACCESS_DENIED": {
        "ru": ("Доступ запрещён", "Windows отказала в доступе к ресурсу или операции.",
               "Проверьте права доступа. Для обслуживания движка используйте отдельное подтверждение UAC."),
        "en": ("Access denied", "Windows denied access to a resource or operation.",
               "Check file permissions. Use the separate UAC flow for engine maintenance."),
    },
    "OPERATION_TIMEOUT": {
        "ru": ("Истекло время ожидания", "Ответ компонента не поступил вовремя; результат операции неизвестен.",
               "Обновите состояние компонента перед повторной попыткой, не считайте действие завершённым."),
        "en": ("Operation timed out", "The component did not respond in time; the outcome is unknown.",
               "Refresh component status before retrying; do not assume it completed."),
    },
    "GUARD_UNRESPONSIVE": {
        "ru": ("Guard не отвечает",
               "Нет подтверждения, что фоновый мониторинг работает. Нельзя считать защиту активной.",
               "Проверьте ClamAV и перезапустите Guard после устранения ошибок движка."),
        "en": ("Guard is unresponsive",
               "Resident monitoring is not confirmed; protection must not be shown as active.",
               "Check ClamAV and restart Guard after resolving engine errors."),
    },
    "GUARD_STATE_CHANGED": {
        "ru": ("Изменилось состояние Guard",
               "Состояние резидентной защиты изменилось. Это не всегда ошибка.",
               "Если состояние «не отвечает» или «сбой», откройте последние ошибки движка."),
        "en": ("Guard state changed",
               "Resident protection changed its state. This is not always a failure.",
               "If Guard is unresponsive or failed, inspect recent engine errors."),
    },
    "SCAN_COMPLETED": {
        "ru": ("Проверка завершена",
               "Результаты проверки файлов обновлены.", "Посмотрите находки и покрытие проверки."),
        "en": ("Scan completed", "The file scan results have been updated.", "Review findings and scan coverage."),
    },
}


def diagnostics_directory() -> Path:
    if os.name == "nt":
        home = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        return home / "AntiOS" / "Diagnostics"
    xdg = os.environ.get("XDG_STATE_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "state") / "antios" / "diagnostics"


def redact(text: object, *, exported: bool = False) -> str:
    result = str(text or "")[:_MAX_DETAIL]
    for pattern, replacement in _PRIVATE:
        result = pattern.sub(replacement, result)
    if exported:
        result = _WINDOWS_HOME.sub(lambda _: r"C:\Users\[USER]", result)
        result = _POSIX_HOME.sub("/home/[USER]", result)
        try:
            home = str(Path.home())
            if home and len(home) > 3:
                result = re.sub(re.escape(home), "[USER_HOME]", result, flags=re.I)
        except Exception:
            pass
    return result


def explanation(code: str, language: str = "en") -> tuple[str, str, str]:
    entry = _HELP.get(code, _HELP["OPERATION_FAILED"])
    return entry["ru" if language == "ru" else "en"]


def classify_error(message: str, *, component: str = "") -> str:
    lower = str(message).lower()
    if ("authenticode" in lower or "digital signature" in lower or "цифров" in lower) and (
        "clam" in lower or "freshclam" in lower or "engine" in lower
    ):
        return "ENGINE_SIGNATURE_INVALID"
    if ("administrator" in lower or "uac" in lower or "elevation" in lower) and (
        "require" in lower or "deny" in lower or "cancel" in lower
    ):
        return "ELEVATION_REQUIRED"
    if "access denied" in lower or "permission denied" in lower or "доступ запрещ" in lower:
        return "ACCESS_DENIED"
    if "timed out" in lower or "timeout" in lower or "время ожидания" in lower:
        return "OPERATION_TIMEOUT"
    if ("unresponsive" in lower or "не отвечает" in lower) and component == "Guard":
        return "GUARD_UNRESPONSIVE"
    if ("clamav" in lower or "clamd" in lower or "engine" in lower) and (
        "not ready" in lower or "unavailable" in lower or "не готов" in lower
    ):
        return "ENGINE_NOT_READY"
    return "OPERATION_FAILED"


def _safe_component(value: str) -> str:
    name = str(value).strip()
    return name if name in _COMPONENTS else "System"


def _safe_code(value: str) -> str:
    name = str(value).upper()
    return name if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", name) else "OPERATION_FAILED"


def _prepare(directory: Path) -> bool:
    try:
        if directory.is_symlink():
            return False
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory.is_dir() and not directory.is_symlink()
    except OSError:
        return False


def _rotate(path: Path) -> None:
    if path.is_symlink():
        raise OSError("Refusing diagnostic symlink")
    if path.exists() and path.stat().st_size >= _MAX_BYTES:
        older = path.with_suffix(".old.jsonl")
        if older.is_symlink():
            raise OSError("Refusing diagnostic archive symlink")
        path.replace(older)


def record_event(
    component: str, level: str, message: str, *,
    code: str = "OPERATION_FAILED",
    details: str = "",
    context: dict | None = None,
    directory: Path | None = None,
) -> dict:
    """Best-effort journal write; must never interrupt protection operations."""
    name = _safe_component(component)
    severity = str(level).upper()
    if severity not in _LEVELS:
        severity = "ERROR"
    event = {
        "schema": 1,
        "id": uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "level": severity,
        "component": name,
        "code": _safe_code(code),
        "message": redact(message)[:700],
        "details": redact(details),
        "context": {
            str(key)[:50]: redact(value)[:250]
            for key, value in (context or {}).items()
            if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,49}", str(key))
            and str(key).lower() not in {"password", "token", "secret", "path", "command"}
        },
    }
    try:
        root = Path(directory) if directory is not None else diagnostics_directory()
        with _IO_LOCK:
            if _prepare(root):
                path = root / ("events-" + str(os.getpid()) + ".jsonl")
                _rotate(path)
                # Opening with O_NOFOLLOW where available avoids a symlink
                # replacement redirecting diagnostic data outside the log dir.
                flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(path, flags, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    except (OSError, ValueError, TypeError):
        pass
    return event


def recent_events(*, limit: int = 300, directory: Path | None = None) -> list[dict]:
    """Read a bounded tail of each process journal; skip corrupt/oversize rows."""
    root = Path(directory) if directory is not None else diagnostics_directory()
    limit = max(1, min(1000, int(limit)))
    found: list[dict] = []
    try:
        with _IO_LOCK:
            paths = sorted(root.glob("events-*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)[:_MAX_FILES]
            for path in paths:
                if path.is_symlink() or not path.is_file():
                    continue
                with path.open("rb") as stream:
                    stream.seek(0, os.SEEK_END)
                    end = stream.tell()
                    # Allow one extra maximum row when reading the bounded tail.
                    # A single valid event can be longer than the rollover
                    # threshold in tiny test stores or after a rotation.
                    stream.seek(max(0, end - min(end, _MAX_BYTES + 16384)), os.SEEK_SET)
                    if stream.tell() > 0:
                        stream.readline()  # skip truncated leading line
                    for line in stream:
                        if len(line) > 16000:
                            continue
                        try:
                            entry = json.loads(line)
                        except (ValueError, UnicodeDecodeError):
                            continue
                        if (
                            isinstance(entry, dict)
                            and entry.get("schema") == 1
                            and entry.get("level") in _LEVELS
                            and isinstance(entry.get("message"), str)
                            and isinstance(entry.get("timestamp"), str)
                        ):
                            found.append(entry)
    except (OSError, ValueError):
        pass
    found.sort(key=lambda item: (item["timestamp"], str(item.get("id", ""))), reverse=True)
    return found[:limit]


def export_report(destination: Path, *, directory: Path | None = None, metadata: dict | None = None) -> int:
    """One redacted ZIP, no raw logs, credentials, configs, user files or system commands."""
    events = recent_events(limit=500, directory=directory)
    clean = []
    for event in events:
        clean.append({
            "timestamp": str(event.get("timestamp", ""))[:60],
            "level": str(event.get("level", ""))[:20],
            "component": _safe_component(event.get("component", "")),
            "code": _safe_code(event.get("code", "")),
            "message": redact(event.get("message", ""), exported=True),
            "details": redact(event.get("details", ""), exported=True),
            "context": {
                str(k)[:50]: redact(v, exported=True)[:250]
                for k, v in (event.get("context") or {}).items()
                if str(k) in {"operation", "state", "action", "exit_code", "source"}
            },
        })
    approved = {"app_version", "os_name", "os_release", "python_version", "language"}
    header = {k: redact(v, exported=True)[:100] for k, v in (metadata or {}).items() if k in approved}
    with ZipFile(destination, "w", ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("README.txt", "AntiOS diagnostics — redacted support bundle.\nNo settings, binaries, samples or quarantine files are included.\nReview before sharing.\n")
        archive.writestr("summary.json", json.dumps({"schema": 1, "metadata": header, "events": len(clean)}, ensure_ascii=False, indent=2))
        archive.writestr("events.json", json.dumps(clean, ensure_ascii=False, indent=2))
    return len(clean)
