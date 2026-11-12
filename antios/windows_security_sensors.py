"""Read-only Windows Process and Persistence sensors for AntiOS.

The collectors in this module inventory operating-system state only. They do
not terminate processes, alter autoruns, disable services, delete scheduled
tasks, or make enforcement decisions. Observations are emitted as neutral
shared Evidence for later correlation.

Coverage is intentionally conservative:
- process inventory currently lacks command-line, signer, integrity-level and
  loaded-module integrity metadata;
- persistence inventory covers common registry autoruns, Startup folders,
  automatic services, scheduled tasks and several targeted registry hooks, but
  not WMI permanent event subscriptions or broad COM-hijack analysis yet.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Mapping, Protocol
import xml.etree.ElementTree as ET

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows hosts
    winreg = None

from .process_identity import process_identity
from .security_sensors import (
    Acquisition,
    BudgetGuard,
    CapabilityState,
    Coverage,
    Privilege,
    ScanBudget,
    ScanContext,
    SensorDescriptor,
    SensorReport,
    Surface,
    sensor_evidence,
)
from .windows_behavior import WindowsProcessSampler


PROCESS_DESCRIPTOR = SensorDescriptor(
    name="antios.process.windows",
    surface=Surface.PROCESS,
    acquisition=Acquisition.SNAPSHOT,
    minimum_privilege=Privilege.USER,
    capability=CapabilityState.AVAILABLE,
    version=1,
    experimental=True,
)

PERSISTENCE_DESCRIPTOR = SensorDescriptor(
    name="antios.persistence.windows",
    surface=Surface.PERSISTENCE,
    acquisition=Acquisition.QUERY,
    minimum_privilege=Privilege.USER,
    capability=CapabilityState.AVAILABLE,
    version=1,
    experimental=True,
)

_INTERPRETER_NAMES = (
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
)
_USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "\\downloads\\",
    "\\temp\\",
    "\\users\\public\\",
    "%appdata%",
    "%localappdata%",
    "%temp%",
    "%tmp%",
)
_MAX_REGISTRY_TEXT = 16_384
_MAX_TASK_BYTES = 1 * 1024 * 1024


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    image: str
    path: str = ""
    creation_time: int = 0

    def __post_init__(self) -> None:
        if type(self.pid) is not int or self.pid <= 0:
            raise ValueError("pid must be a positive integer")
        if type(self.ppid) is not int or self.ppid < 0:
            raise ValueError("ppid must be a non-negative integer")
        if type(self.creation_time) is not int or self.creation_time < 0:
            raise ValueError("creation_time must be non-negative")
        if not isinstance(self.image, str) or not isinstance(self.path, str):
            raise ValueError("process image/path must be strings")


@dataclass(frozen=True)
class ProcessInventory:
    records: tuple[ProcessRecord, ...]
    inspected_bytes: int = 0
    skipped_items: int = 0
    error_items: int = 0
    complete: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.inspected_bytes, self.skipped_items, self.error_items)
        ):
            raise ValueError("inventory counters must be non-negative integers")
        if not self.complete and not self.reason.strip():
            raise ValueError("incomplete process inventory requires a reason")


@dataclass(frozen=True)
class PersistenceRecord:
    source: str
    location: str
    name: str
    command: str
    enabled: bool | None = None
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.location.strip() or not self.name.strip():
            raise ValueError("persistence source/location/name must be non-empty")
        if not isinstance(self.command, str):
            raise ValueError("persistence command must be a string")
        if self.enabled not in (True, False, None):
            raise ValueError("enabled must be bool or None")
        if not isinstance(self.attributes, Mapping):
            raise ValueError("attributes must be a mapping")


@dataclass(frozen=True)
class PersistenceInventory:
    records: tuple[PersistenceRecord, ...]
    inspected_bytes: int = 0
    skipped_items: int = 0
    error_items: int = 0
    complete: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.inspected_bytes, self.skipped_items, self.error_items)
        ):
            raise ValueError("inventory counters must be non-negative integers")
        if not self.complete and not self.reason.strip():
            raise ValueError("incomplete persistence inventory requires a reason")


class ProcessInventorySource(Protocol):
    def collect(self, budget: ScanBudget) -> ProcessInventory: ...


class PersistenceInventorySource(Protocol):
    def collect(self, budget: ScanBudget) -> PersistenceInventory: ...


def _bounded_text(value: object, limit: int = _MAX_REGISTRY_TEXT) -> str:
    text = str(value or "")
    return text[:limit]


def _user_writable_hint(value: str) -> bool:
    lowered = os.path.expandvars(value or "").replace("/", "\\").lower()
    return any(marker in lowered for marker in _USER_WRITABLE_MARKERS)


def _interpreter_hint(value: str) -> bool:
    lowered = (value or "").lower()
    return any(re.search(rf"(^|[\\/\s\"]){re.escape(name)}(?:[\s\"]|$)", lowered)
               for name in _INTERPRETER_NAMES)


def _record_size(*values: object) -> int:
    return sum(len(str(value or "").encode("utf-8", errors="replace")) for value in values)


class WindowsProcessInventorySource:
    """Use Toolhelp32 + limited process queries to build a bounded snapshot."""

    def __init__(self, sampler: WindowsProcessSampler | None = None) -> None:
        if os.name != "nt" and sampler is None:
            raise OSError("Windows process inventory is only available on Windows")
        self.sampler = sampler or WindowsProcessSampler()

    def collect(self, budget: ScanBudget) -> ProcessInventory:
        snapshot = self.sampler.snapshot()
        guard = BudgetGuard(budget)
        records: list[ProcessRecord] = []
        skipped = 0
        metadata_gaps = 0
        ordered = sorted(snapshot.values(), key=lambda item: item.pid)

        for index, process in enumerate(ordered):
            if not guard.can_take(items=1):
                skipped += len(ordered) - index
                break

            # Resolve the minimum stable metadata needed by the shared process
            # identity/correlation layer. Limited-information queries may fail
            # for protected or exiting processes; the record remains useful.
            path = self.sampler._path(process.pid)
            creation_time = self.sampler._creation_time(process.pid)
            size = _record_size(process.image, path)
            if not guard.take(items=1, byte_count=size):
                skipped += len(ordered) - index
                break
            if not path or not creation_time:
                metadata_gaps += 1
            records.append(ProcessRecord(
                pid=process.pid,
                ppid=process.ppid,
                image=process.image,
                path=path,
                creation_time=creation_time,
            ))

        reasons = [
            "basic process inventory only: command line, signer, integrity level "
            "and loaded-module integrity are not collected yet"
        ]
        if metadata_gaps:
            reasons.append(f"{metadata_gaps} process records have incomplete path/creation metadata")
        if skipped:
            reasons.append(f"{skipped} process records were skipped by the scan budget")

        return ProcessInventory(
            records=tuple(records),
            inspected_bytes=guard.bytes,
            skipped_items=skipped,
            error_items=metadata_gaps,
            complete=False,
            reason="; ".join(reasons),
        )


class WindowsProcessSensor:
    descriptor = PROCESS_DESCRIPTOR

    def __init__(self, source: ProcessInventorySource | None = None) -> None:
        self.source = source or WindowsProcessInventorySource()

    def collect(self, context: ScanContext) -> SensorReport:
        inventory = self.source.collect(context.budget)
        evidence = []
        for record in inventory.records:
            identity = process_identity(record.pid, record.creation_time)
            image_path = record.path or record.image
            evidence.append(sensor_evidence(
                self.descriptor,
                context,
                subject=identity.node_id,
                kind="process",
                rule_id="process.inventory",
                detail=f"Running process: {image_path}"[:1000],
                complete=bool(record.path and record.creation_time),
                correlation_group=identity.node_id,
                attributes={
                    "pid": record.pid,
                    "ppid": record.ppid,
                    "image": record.image,
                    "path": record.path,
                    "creation_time": record.creation_time,
                    "stable_identity": identity.stable,
                    "user_writable_path": _user_writable_hint(record.path),
                },
            ))
        return SensorReport(
            descriptor=self.descriptor,
            coverage=Coverage.COMPLETE if inventory.complete else Coverage.PARTIAL,
            evidence=tuple(evidence),
            reason="" if inventory.complete else inventory.reason,
            inspected_items=len(inventory.records),
            inspected_bytes=inventory.inspected_bytes,
            skipped_items=inventory.skipped_items,
            error_items=inventory.error_items,
        )


class WindowsPersistenceInventorySource:
    """Read common persistence locations without changing system state."""

    _RUN_KEYS = (
        (r"Software\Microsoft\Windows\CurrentVersion\Run", "run"),
        (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "run-once"),
        (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "policy-run"),
    )

    def __init__(
        self,
        *,
        env: Mapping[str, str] | None = None,
        task_root: Path | None = None,
    ) -> None:
        if os.name != "nt" and winreg is None:
            raise OSError("Windows persistence inventory is only available on Windows")
        self.env = dict(os.environ if env is None else env)
        system_root = self.env.get("SystemRoot") or r"C:\Windows"
        self.task_root = task_root or Path(system_root) / "System32" / "Tasks"

    @staticmethod
    def _registry_views() -> tuple[int, ...]:
        if winreg is None:
            return ()
        views = []
        for value in (
            getattr(winreg, "KEY_WOW64_64KEY", 0),
            getattr(winreg, "KEY_WOW64_32KEY", 0),
        ):
            if value not in views:
                views.append(value)
        return tuple(views or (0,))

    @staticmethod
    def _root_name(root: object) -> str:
        if winreg is None:
            return "HK?"
        if root == winreg.HKEY_CURRENT_USER:
            return "HKCU"
        if root == winreg.HKEY_LOCAL_MACHINE:
            return "HKLM"
        return "HK?"

    def _enum_values(self, root: object, path: str, view: int) -> tuple[list[tuple[str, object, int]], int]:
        if winreg is None:
            return [], 1
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                values = []
                index = 0
                while True:
                    try:
                        values.append(winreg.EnumValue(key, index))
                        index += 1
                    except OSError:
                        break
                return values, 0
        except FileNotFoundError:
            return [], 0
        except (PermissionError, OSError):
            return [], 1

    def _query_value(self, root: object, path: str, name: str, view: int) -> tuple[object | None, int]:
        if winreg is None:
            return None, 1
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                value, _kind = winreg.QueryValueEx(key, name)
                return value, 0
        except FileNotFoundError:
            return None, 0
        except (PermissionError, OSError):
            return None, 1

    def _enum_subkeys(self, root: object, path: str, view: int) -> tuple[list[str], int]:
        if winreg is None:
            return [], 1
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
                values = []
                index = 0
                while True:
                    try:
                        values.append(winreg.EnumKey(key, index))
                        index += 1
                    except OSError:
                        break
                return values, 0
        except FileNotFoundError:
            return [], 0
        except (PermissionError, OSError):
            return [], 1

    @staticmethod
    def _task_text(root: ET.Element, tag: str) -> str:
        node = root.find(f".//{{*}}{tag}")
        return (node.text or "").strip() if node is not None else ""

    def collect(self, budget: ScanBudget) -> PersistenceInventory:
        guard = BudgetGuard(budget)
        records: list[PersistenceRecord] = []
        errors = 0
        skipped = 0
        budget_exhausted = False

        def add(record: PersistenceRecord, *, extra_bytes: int = 0) -> bool:
            nonlocal budget_exhausted, skipped
            size = _record_size(
                record.source, record.location, record.name, record.command,
                *record.attributes.values(),
            ) + max(0, int(extra_bytes))
            if not guard.take(items=1, byte_count=size):
                budget_exhausted = True
                skipped += 1
                return False
            records.append(record)
            return True

        if winreg is not None:
            # User/machine Run, RunOnce and policy autoruns in both registry views.
            for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for view in self._registry_views():
                    for path, kind in self._RUN_KEYS:
                        values, failed = self._enum_values(root, path, view)
                        errors += failed
                        for name, value, _value_type in values:
                            command = _bounded_text(value)
                            if not command:
                                continue
                            if not add(PersistenceRecord(
                                source="registry",
                                location=f"{self._root_name(root)}\\{path}",
                                name=_bounded_text(name or "(Default)", 512),
                                command=command,
                                attributes={
                                    "persistence_type": kind,
                                    "registry_view": int(view),
                                },
                            )):
                                break
                        if budget_exhausted:
                            break
                    if budget_exhausted:
                        break
                if budget_exhausted:
                    break

            # Targeted persistence hooks with high defensive value.
            targeted = (
                (winreg.HKEY_LOCAL_MACHINE,
                 r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                 ("Shell", "Userinit"), "winlogon"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                 ("AppInit_DLLs",), "appinit"),
                (winreg.HKEY_LOCAL_MACHINE,
                 r"SYSTEM\CurrentControlSet\Control\Session Manager",
                 ("BootExecute",), "boot-execute"),
            )
            if not budget_exhausted:
                for root, path, names, kind in targeted:
                    for view in self._registry_views():
                        for name in names:
                            value, failed = self._query_value(root, path, name, view)
                            errors += failed
                            if value in (None, "", []):
                                continue
                            if isinstance(value, (list, tuple)):
                                command = " ".join(_bounded_text(item) for item in value)
                            else:
                                command = _bounded_text(value)
                            if not add(PersistenceRecord(
                                source="registry",
                                location=f"{self._root_name(root)}\\{path}",
                                name=name,
                                command=command,
                                attributes={
                                    "persistence_type": kind,
                                    "registry_view": int(view),
                                },
                            )):
                                break
                        if budget_exhausted:
                            break
                    if budget_exhausted:
                        break

            # IFEO Debugger and SilentProcessExit MonitorProcess.
            subkey_specs = (
                (r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                 "Debugger", "ifeo-debugger"),
                (r"Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
                 "MonitorProcess", "silent-process-exit"),
            )
            if not budget_exhausted:
                for base, value_name, kind in subkey_specs:
                    for view in self._registry_views():
                        children, failed = self._enum_subkeys(
                            winreg.HKEY_LOCAL_MACHINE, base, view
                        )
                        errors += failed
                        for child in children:
                            path = f"{base}\\{child}"
                            value, failed = self._query_value(
                                winreg.HKEY_LOCAL_MACHINE, path, value_name, view
                            )
                            errors += failed
                            command = _bounded_text(value)
                            if not command:
                                continue
                            if not add(PersistenceRecord(
                                source="registry",
                                location=f"HKLM\\{path}",
                                name=value_name,
                                command=command,
                                attributes={
                                    "persistence_type": kind,
                                    "target_image": child,
                                    "registry_view": int(view),
                                },
                            )):
                                break
                        if budget_exhausted:
                            break
                    if budget_exhausted:
                        break

            # Automatic Win32 services. Driver trust is handled separately by
            # the future driver sensor; this layer records service persistence.
            if not budget_exhausted:
                services = r"SYSTEM\CurrentControlSet\Services"
                children, failed = self._enum_subkeys(
                    winreg.HKEY_LOCAL_MACHINE, services, 0
                )
                errors += failed
                for child in children:
                    path = f"{services}\\{child}"
                    start, failed1 = self._query_value(
                        winreg.HKEY_LOCAL_MACHINE, path, "Start", 0
                    )
                    image, failed2 = self._query_value(
                        winreg.HKEY_LOCAL_MACHINE, path, "ImagePath", 0
                    )
                    service_type, failed3 = self._query_value(
                        winreg.HKEY_LOCAL_MACHINE, path, "Type", 0
                    )
                    delayed, failed4 = self._query_value(
                        winreg.HKEY_LOCAL_MACHINE, path, "DelayedAutoStart", 0
                    )
                    errors += failed1 + failed2 + failed3 + failed4
                    try:
                        start_value = int(start)
                    except (TypeError, ValueError):
                        continue
                    try:
                        type_value = int(service_type or 0)
                    except (TypeError, ValueError):
                        type_value = 0
                    # SERVICE_WIN32_OWN_PROCESS / SHARE_PROCESS only.
                    if start_value != 2 or not (type_value & 0x30):
                        continue
                    command = _bounded_text(image)
                    if not command:
                        continue
                    if not add(PersistenceRecord(
                        source="service",
                        location=f"HKLM\\{path}",
                        name=child,
                        command=command,
                        enabled=True,
                        attributes={
                            "persistence_type": "auto-service",
                            "start": start_value,
                            "service_type": type_value,
                            "delayed_auto_start": bool(delayed),
                        },
                    )):
                        break

        # Per-user and all-users Startup folders.
        if not budget_exhausted:
            startup_dirs = []
            appdata = self.env.get("APPDATA")
            program_data = self.env.get("ProgramData")
            if appdata:
                startup_dirs.append(
                    ("user-startup", Path(appdata) / "Microsoft" / "Windows" /
                     "Start Menu" / "Programs" / "Startup")
                )
            if program_data:
                startup_dirs.append(
                    ("common-startup", Path(program_data) / "Microsoft" / "Windows" /
                     "Start Menu" / "Programs" / "StartUp")
                )
            for kind, folder in startup_dirs:
                try:
                    entries = sorted(
                        (item for item in folder.iterdir() if item.is_file()),
                        key=lambda item: item.name.lower(),
                    )
                except FileNotFoundError:
                    entries = []
                except (PermissionError, OSError):
                    errors += 1
                    entries = []
                for item in entries:
                    try:
                        stat = item.stat()
                        size = int(stat.st_size)
                    except OSError:
                        errors += 1
                        size = 0
                    if not add(PersistenceRecord(
                        source="startup-folder",
                        location=str(folder),
                        name=item.name,
                        command=str(item),
                        enabled=True,
                        attributes={
                            "persistence_type": kind,
                            "file_size": size,
                        },
                    )):
                        break
                if budget_exhausted:
                    break

        # Scheduled Task XML definitions. Read-only; no Task Scheduler service
        # calls are made and no task is enabled/disabled.
        if not budget_exhausted:
            try:
                task_files = sorted(
                    (item for item in self.task_root.rglob("*") if item.is_file()),
                    key=lambda item: str(item).lower(),
                )
            except (PermissionError, OSError):
                errors += 1
                task_files = []
            for task in task_files:
                try:
                    size = task.stat().st_size
                except OSError:
                    errors += 1
                    continue
                if size < 0 or size > _MAX_TASK_BYTES:
                    skipped += 1
                    continue
                if not guard.can_take(items=1, byte_count=int(size)):
                    budget_exhausted = True
                    skipped += 1
                    break
                try:
                    data = task.read_bytes()
                    root = ET.fromstring(data)
                except (OSError, ET.ParseError, ValueError):
                    errors += 1
                    continue

                enabled_text = self._task_text(root, "Enabled").lower()
                enabled = None
                if enabled_text in {"true", "1"}:
                    enabled = True
                elif enabled_text in {"false", "0"}:
                    enabled = False

                exec_nodes = root.findall(".//{*}Actions/{*}Exec")
                com_nodes = root.findall(".//{*}Actions/{*}ComHandler")
                commands = []
                action_type = "other"
                for node in exec_nodes:
                    command_node = node.find("{*}Command")
                    arguments_node = node.find("{*}Arguments")
                    command = (command_node.text or "").strip() if command_node is not None else ""
                    arguments = (arguments_node.text or "").strip() if arguments_node is not None else ""
                    if command:
                        commands.append((command + (" " + arguments if arguments else "")).strip())
                if commands:
                    action_type = "exec"
                elif com_nodes:
                    action_type = "com-handler"
                    for node in com_nodes:
                        class_node = node.find("{*}ClassId")
                        class_id = (class_node.text or "").strip() if class_node is not None else ""
                        if class_id:
                            commands.append(f"COM:{class_id}")

                command = " ; ".join(commands)[:_MAX_REGISTRY_TEXT]
                relative = str(task.relative_to(self.task_root)).replace("/", "\\")
                if not add(PersistenceRecord(
                    source="scheduled-task",
                    location=f"TaskScheduler\\{relative}",
                    name=task.name,
                    command=command,
                    enabled=enabled,
                    attributes={
                        "persistence_type": "scheduled-task",
                        "action_type": action_type,
                        "hidden": self._task_text(root, "Hidden").lower() in {"true", "1"},
                    },
                ), extra_bytes=len(data)):
                    break

        reason_parts = [
            "common Windows persistence inventory collected; WMI permanent event "
            "subscriptions and broad COM-hijack analysis are not collected yet"
        ]
        if errors:
            reason_parts.append(f"{errors} locations/items could not be read or parsed")
        if budget_exhausted:
            reason_parts.append("scan budget was exhausted")
        if skipped:
            reason_parts.append(f"{skipped} items were skipped")

        return PersistenceInventory(
            records=tuple(records),
            inspected_bytes=guard.bytes,
            skipped_items=skipped,
            error_items=errors,
            complete=False,
            reason="; ".join(reason_parts),
        )


class WindowsPersistenceSensor:
    descriptor = PERSISTENCE_DESCRIPTOR

    def __init__(self, source: PersistenceInventorySource | None = None) -> None:
        self.source = source or WindowsPersistenceInventorySource()

    def collect(self, context: ScanContext) -> SensorReport:
        inventory = self.source.collect(context.budget)
        evidence = []
        for record in inventory.records:
            subject = (
                f"persistence:{record.source}:"
                f"{record.location}::{record.name}"
            )[:32768]
            attributes = dict(record.attributes)
            attributes.update({
                "persistence_source": record.source,
                "location": record.location,
                "name": record.name,
                "command": record.command,
                "enabled": record.enabled,
                "user_writable_target": _user_writable_hint(record.command),
                "interpreter_target": _interpreter_hint(record.command),
            })
            evidence.append(sensor_evidence(
                self.descriptor,
                context,
                subject=subject,
                kind="behavior",
                rule_id="persistence.inventory",
                detail=f"{record.source}: {record.location} -> {record.command}"[:1000],
                complete=True,
                correlation_group=subject[:128],
                attributes=attributes,
            ))

        return SensorReport(
            descriptor=self.descriptor,
            coverage=Coverage.COMPLETE if inventory.complete else Coverage.PARTIAL,
            evidence=tuple(evidence),
            reason="" if inventory.complete else inventory.reason,
            inspected_items=len(inventory.records),
            inspected_bytes=inventory.inspected_bytes,
            skipped_items=inventory.skipped_items,
            error_items=inventory.error_items,
        )
