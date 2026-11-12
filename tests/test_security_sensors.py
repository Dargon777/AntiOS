"""Safety and contract tests for the hardware security foundation."""
import pytest
from antios.security_sensors import (
    Coverage, Observation, ObservationBuffer, PlaceholderSensor,
    SensorRegistry, SensorReport, Surface, default_registry,
)


def test_all_surfaces_are_explicitly_unimplemented():
    reports = default_registry().collect_all()
    assert {r.surface for r in reports} == set(Surface)
    assert all(r.coverage is Coverage.NOT_IMPLEMENTED for r in reports)
    assert all(r.reason and not r.observations for r in reports)


def test_invalid_confidence_rejected():
    with pytest.raises(ValueError):
        Observation("x", Surface.RAM, "pid:1", "rule", "summary", confidence=1.2)


def test_incomplete_coverage_requires_reason():
    with pytest.raises(ValueError):
        SensorReport("x", Surface.RAM, Coverage.PARTIAL)


def test_cross_sensor_observations_rejected():
    item = Observation("other", Surface.RAM, "pid:1", "rule", "summary")
    with pytest.raises(ValueError):
        SensorReport("x", Surface.RAM, Coverage.COMPLETE, (item,))


def test_collector_failures_isolated():
    class Broken:
        name = "broken"
        surface = Surface.GPU

        def collect(self):
            raise RuntimeError("private details")

    registry = SensorRegistry()
    registry.register(Broken())
    report, = registry.collect_all()
    assert report.coverage is Coverage.ERROR
    assert "private details" not in report.reason


def test_duplicate_registration_rejected():
    registry = SensorRegistry()
    registry.register(PlaceholderSensor("a", Surface.RAM))
    with pytest.raises(ValueError):
        registry.register(PlaceholderSensor("a", Surface.GPU))


def test_buffer_is_bounded():
    buffer = ObservationBuffer(capacity=2)
    for i in range(3):
        obs = Observation("x", Surface.RAM, str(i), "r", "test")
        buffer.publish(SensorReport("x", Surface.RAM, Coverage.COMPLETE, (obs,)))
    assert [x.subject for x in buffer.snapshot()] == ["1", "2"]
