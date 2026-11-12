"""Safety and contract tests for the AntiOS deep-security foundation."""
import pytest

from antios.security_sensors import (
    Acquisition,
    BudgetGuard,
    CapabilityState,
    Coverage,
    CoverageSummary,
    EvidenceKind,
    Observation,
    ObservationBuffer,
    PlaceholderSensor,
    Privilege,
    ScanBudget,
    ScanContext,
    SensorDescriptor,
    SensorRegistry,
    SensorReport,
    Severity,
    Surface,
    default_descriptors,
    default_registry,
)


def _descriptor(
    name: str = "x",
    surface: Surface = Surface.PROCESS,
    privilege: Privilege = Privilege.USER,
) -> SensorDescriptor:
    return SensorDescriptor(
        name=name,
        surface=surface,
        acquisition=Acquisition.SNAPSHOT,
        minimum_privilege=privilege,
        capability=CapabilityState.AVAILABLE,
        experimental=False,
    )


def test_every_planned_surface_has_a_descriptor():
    assert {d.surface for d in default_descriptors()} == set(Surface)


def test_default_registry_never_claims_a_clean_scan():
    reports = default_registry().collect_all(
        ScanContext(budget=ScanBudget(allow_privileged=True))
    )
    assert {r.descriptor.surface for r in reports} == set(Surface)
    assert all(r.coverage is Coverage.NOT_IMPLEMENTED for r in reports)
    assert all(r.reason and not r.observations for r in reports)


def test_privileged_sensors_are_denied_by_default_before_collection():
    class MustNotRun:
        descriptor = _descriptor("admin", Surface.RAM, Privilege.ADMIN)

        def collect(self, context):
            raise AssertionError("must not execute")

    registry = SensorRegistry()
    registry.register(MustNotRun())
    report, = registry.collect_all()
    assert report.coverage is Coverage.PERMISSION_DENIED


def test_requested_surface_filtering():
    registry = default_registry()
    reports = registry.collect_all(
        ScanContext(
            requested_surfaces=frozenset({Surface.PROCESS, Surface.BROWSER})
        )
    )
    assert {r.descriptor.surface for r in reports} == {
        Surface.PROCESS,
        Surface.BROWSER,
    }


def test_invalid_confidence_rejected():
    with pytest.raises(ValueError):
        Observation(
            "x",
            Surface.RAM,
            "pid:1",
            "rule",
            "summary",
            confidence=1.2,
        )


def test_heuristic_evidence_cannot_request_auto_action():
    with pytest.raises(ValueError):
        Observation(
            "x",
            Surface.PROCESS,
            "pid:1",
            "rule",
            "summary",
            kind=EvidenceKind.BEHAVIOR,
            severity=Severity.HIGH,
            confidence=0.99,
            auto_action_eligible=True,
        )


def test_exact_evidence_can_be_marked_auto_action_eligible():
    item = Observation(
        "x",
        Surface.PROCESS,
        "pid:1",
        "rule",
        "summary",
        kind=EvidenceKind.EXACT_MATCH,
        severity=Severity.CRITICAL,
        confidence=1.0,
        auto_action_eligible=True,
    )
    assert item.auto_action_eligible


def test_incomplete_coverage_requires_reason():
    with pytest.raises(ValueError):
        SensorReport(_descriptor(), Coverage.PARTIAL)


def test_cross_sensor_observations_rejected():
    descriptor = _descriptor()
    item = Observation("other", Surface.PROCESS, "pid:1", "rule", "summary")
    with pytest.raises(ValueError):
        SensorReport(descriptor, Coverage.COMPLETE, (item,))


def test_collector_failures_are_isolated_and_details_not_leaked():
    class Broken:
        descriptor = _descriptor("broken", Surface.GPU)

        def collect(self, context):
            raise RuntimeError("secret implementation detail")

    registry = SensorRegistry()
    registry.register(Broken())
    report, = registry.collect_all()
    assert report.coverage is Coverage.ERROR
    assert "secret implementation detail" not in report.reason


def test_duplicate_registration_rejected():
    registry = SensorRegistry()
    descriptor = _descriptor("a")
    registry.register(PlaceholderSensor(descriptor))
    with pytest.raises(ValueError):
        registry.register(PlaceholderSensor(descriptor))


def test_observation_buffer_is_bounded():
    buffer = ObservationBuffer(capacity=2)
    descriptor = _descriptor()
    for i in range(3):
        obs = Observation("x", Surface.PROCESS, str(i), "r", "test")
        buffer.publish(
            SensorReport(descriptor, Coverage.COMPLETE, (obs,), inspected_items=1)
        )
    assert [x.subject for x in buffer.snapshot()] == ["1", "2"]


def test_budget_guard_stops_at_hard_limits():
    guard = BudgetGuard(
        ScanBudget(max_items=2, max_bytes=10, max_seconds=60)
    )
    assert guard.take(items=1, byte_count=4)
    assert guard.take(items=1, byte_count=6)
    assert not guard.take(items=1)
    assert not guard.take(items=0, byte_count=1)
    assert guard.items == 2
    assert guard.bytes == 10


def test_coverage_summary_never_calls_missing_surfaces_fully_covered():
    complete = SensorReport(_descriptor("a"), Coverage.COMPLETE)
    missing = SensorReport(
        _descriptor("b", Surface.BROWSER),
        Coverage.NOT_IMPLEMENTED,
        reason="not connected",
    )
    summary = CoverageSummary.from_reports((complete, missing))
    assert summary.complete == 1
    assert summary.not_implemented == 1
    assert not summary.fully_covered
