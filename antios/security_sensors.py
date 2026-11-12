"""Shared contracts for optional AntiOS hardware and memory security sensors.

This module deliberately does not read process memory, VRAM, firmware or kernel
memory. Collectors must be implemented separately and explicitly enabled.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from time import time
from typing import Callable, Protocol
from collections import deque


class Surface(str, Enum):
    PROCESS = "process"
    RAM = "ram"
    GPU = "gpu"
    FIRMWARE = "firmware"
    DRIVER = "driver"
    BOOT = "boot"


class Coverage(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    ERROR = "error"
    PARTIAL = "partial"
    COMPLETE = "complete"


@dataclass(frozen=True)
class Observation:
    sensor: str
    surface: Surface
    subject: str
    rule_id: str
    summary: str
    observed_at: float = field(default_factory=time)
    confidence: float = 0.0
    metadata: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.sensor or not self.subject or not self.rule_id:
            raise ValueError("sensor, subject and rule_id must be non-empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True)
class SensorReport:
    sensor: str
    surface: Surface
    coverage: Coverage
    observations: tuple[Observation, ...] = ()
    reason: str = ""
    collected_at: float = field(default_factory=time)

    def __post_init__(self) -> None:
        if self.coverage != Coverage.COMPLETE and not self.reason:
            raise ValueError("incomplete coverage requires a reason")
        if any(item.surface != self.surface or item.sensor != self.sensor
               for item in self.observations):
            raise ValueError("observation does not belong to reporting sensor")


class Sensor(Protocol):
    name: str
    surface: Surface

    def collect(self) -> SensorReport: ...


class PlaceholderSensor:
    """Honest capability placeholder; never claims to scan a device."""

    def __init__(self, name: str, surface: Surface) -> None:
        self.name = name
        self.surface = surface

    def collect(self) -> SensorReport:
        return SensorReport(self.name, self.surface, Coverage.NOT_IMPLEMENTED,
                            reason="Collector not implemented; no inspection performed")


class SensorRegistry:
    """Bounded, exception-isolated registry; no automatic sensor execution."""

    def __init__(self, max_sensors: int = 32) -> None:
        if max_sensors < 1:
            raise ValueError("max_sensors must be positive")
        self._lock = RLock()
        self._sensors: dict[str, Sensor] = {}
        self._max_sensors = max_sensors

    def register(self, sensor: Sensor) -> None:
        with self._lock:
            if not sensor.name or sensor.name in self._sensors:
                raise ValueError("empty or duplicate sensor name")
            if len(self._sensors) >= self._max_sensors:
                raise ValueError("sensor capacity reached")
            self._sensors[sensor.name] = sensor

    def collect_all(self) -> tuple[SensorReport, ...]:
        with self._lock:
            sensors = tuple(self._sensors.values())
        reports = []
        for sensor in sensors:
            try:
                report = sensor.collect()
                if report.sensor != sensor.name or report.surface != sensor.surface:
                    raise ValueError("collector returned mismatched identity")
                reports.append(report)
            except Exception as exc:
                reports.append(SensorReport(
                    sensor.name, sensor.surface, Coverage.ERROR,
                    reason=f"Collector failure: {type(exc).__name__}"))
        return tuple(reports)


def default_registry() -> SensorRegistry:
    registry = SensorRegistry()
    for surface in Surface:
        registry.register(PlaceholderSensor(f"antios.{surface.value}", surface))
    return registry


class ObservationBuffer:
    """Thread-safe bounded buffer for later EvidenceBus integration."""

    def __init__(self, capacity: int = 1024) -> None:
        if capacity < 1:
            raise ValueError("capacity must be positive")
        self._items: deque[Observation] = deque(maxlen=capacity)
        self._lock = RLock()

    def publish(self, report: SensorReport) -> None:
        with self._lock:
            self._items.extend(report.observations)

    def snapshot(self) -> tuple[Observation, ...]:
        with self._lock:
            return tuple(self._items)
