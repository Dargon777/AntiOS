"""Tests for real Process/Persistence sensor contracts and Windows plumbing."""
from types import SimpleNamespace
import os

import pytest

from antios.evidence import EvidenceBus
from antios.security_sensors import (
    Coverage,
    ScanBudget,
    ScanContext,
    Surface,
    runtime_registry,
)
from antios.windows_security_sensors import (
    PersistenceInventory,
    PersistenceRecord,
    ProcessInventory,
    ProcessRecord,
    WindowsPersistenceSensor,
    WindowsProcessInventorySource,
    WindowsProcessSensor,
)


class _FakeProcessSource:
    def collect(self, budget):
        return ProcessInventory(
            records=(
                ProcessRecord(
                    pid=123,
                    ppid=10,
                    image="sample.exe",
                    path=r"C:\Users\Example\AppData\Local\Temp\sample.exe",
                    creation_time=456,
                ),
            ),
            inspected_bytes=64,
            complete=False,
            reason="test fixture lacks signer metadata",
        )


class _FakePersistenceSource:
    def collect(self, budget):
        return PersistenceInventory(
            records=(
                PersistenceRecord(
                    source="registry",
                    location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    name="Example",
                    command=r"powershell.exe -File C:\Users\Example\AppData\Local\x.ps1",
                    enabled=True,
                    attributes={"persistence_type": "run"},
                ),
            ),
            inspected_bytes=96,
            complete=False,
            reason="WMI/COM not collected in fixture",
        )


def test_process_sensor_emits_stable_shared_process_evidence():
    sensor = WindowsProcessSensor(source=_FakeProcessSource())
    report = sensor.collect(
        ScanContext(requested_surfaces=frozenset({Surface.PROCESS}))
    )
    assert report.coverage is Coverage.PARTIAL
    assert report.inspected_items == 1
    item, = report.evidence
    assert item.kind == "process"
    assert item.subject == "process:123:456"
    assert item.attributes["pid"] == 123
    assert item.attributes["ppid"] == 10
    assert item.attributes["stable_identity"] is True
    assert item.attributes["user_writable_path"] is True
    assert item.risk_score == 0


def test_persistence_sensor_emits_neutral_correlatable_evidence():
    sensor = WindowsPersistenceSensor(source=_FakePersistenceSource())
    report = sensor.collect(
        ScanContext(requested_surfaces=frozenset({Surface.PERSISTENCE}))
    )
    assert report.coverage is Coverage.PARTIAL
    assert report.inspected_items == 1
    item, = report.evidence
    assert item.kind == "behavior"
    assert item.attributes["persistence_type"] == "run"
    assert item.attributes["interpreter_target"] is True
    assert item.attributes["user_writable_target"] is True
    assert item.risk_score == 0


def test_process_inventory_source_enforces_item_budget_before_enrichment():
    class Sampler:
        def snapshot(self):
            return {
                1: SimpleNamespace(pid=1, ppid=0, image="one.exe"),
                2: SimpleNamespace(pid=2, ppid=1, image="two.exe"),
            }

        def _path(self, pid):
            return fr"C:\Program Files\Example\{pid}.exe"

        def _creation_time(self, pid):
            return 1000 + pid

    source = WindowsProcessInventorySource(sampler=Sampler())
    result = source.collect(
        ScanBudget(max_items=1, max_bytes=4096, max_seconds=60)
    )
    assert len(result.records) == 1
    assert result.skipped_items == 1
    assert result.records[0].pid == 1
    assert "budget" in result.reason.lower()


def test_runtime_registry_keeps_one_sensor_per_planned_surface():
    registry = runtime_registry()
    descriptors = registry.descriptors()
    assert len(descriptors) == len(Surface)
    assert {item.surface for item in descriptors} == set(Surface)
    if os.name == "nt":
        by_surface = {item.surface: item for item in descriptors}
        assert by_surface[Surface.PROCESS].name == "antios.process.windows"
        assert by_surface[Surface.PERSISTENCE].name == "antios.persistence.windows"


@pytest.mark.skipif(os.name != "nt", reason="native Windows process/persistence inventory")
def test_windows_runtime_process_and_persistence_smoke():
    bus = EvidenceBus(max_events=4096)
    registry = runtime_registry(evidence_bus=bus)
    reports = registry.collect_all(
        ScanContext(
            budget=ScanBudget(
                max_items=5000,
                max_bytes=64 * 1024 * 1024,
                max_seconds=30,
            ),
            requested_surfaces=frozenset({
                Surface.PROCESS,
                Surface.PERSISTENCE,
            }),
        )
    )
    assert {item.descriptor.surface for item in reports} == {
        Surface.PROCESS,
        Surface.PERSISTENCE,
    }
    by_surface = {item.descriptor.surface: item for item in reports}
    assert by_surface[Surface.PROCESS].coverage in {
        Coverage.PARTIAL,
        Coverage.COMPLETE,
    }
    assert by_surface[Surface.PROCESS].inspected_items > 0
    assert by_surface[Surface.PERSISTENCE].coverage in {
        Coverage.PARTIAL,
        Coverage.COMPLETE,
    }
    assert bus.status()["published"] == sum(len(item.evidence) for item in reports)
