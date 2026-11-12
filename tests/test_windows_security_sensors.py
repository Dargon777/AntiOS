"""Contract tests for Windows process, persistence and memory sensors.

The tests use fake providers so the detection policy is portable and deterministic.
Native Win32 API acceptance is covered by the Windows CI smoke tests.
"""
from antios.detection_signatures import DEFAULT_DETECTION_SIGNATURES
from antios.security_sensors import Coverage, ScanBudget, ScanContext
from antios.windows_security_sensors import (
    MEM_COMMIT,
    MEM_IMAGE,
    MEM_PRIVATE,
    PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,
    MemoryInspection,
    MemoryRegion,
    PersistenceEntry,
    PersistenceSnapshot,
    ProcessRecord,
    ProcessSnapshot,
    WindowsMemorySensor,
    WindowsPersistenceSensor,
    WindowsProcessSensor,
    _command_executable,
    _looks_like_pe,
)


class FakeProcesses:
    def __init__(self, processes, *, unresolved=0, truncated=False):
        self.value = ProcessSnapshot(tuple(processes), unresolved, truncated)

    def snapshot(self, max_items):
        return self.value


class FakePersistence:
    def __init__(self, entries, *, issues=(), truncated=False, uncovered=()):
        self.value = PersistenceSnapshot(
            tuple(entries), tuple(issues), truncated, tuple(uncovered)
        )

    def snapshot(self, max_items):
        return self.value


class FakeMemory:
    def __init__(self, values):
        self.values = dict(values)

    def inspect(self, process, budget):
        return self.values.get(process.pid, MemoryInspection())


def _pe_prefix():
    data = bytearray(512)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\x00\x00"
    return bytes(data)


def test_command_executable_handles_quoted_windows_command():
    assert _command_executable(
        r'"C:\Program Files\Example\agent.exe" --background'
    ) == r"C:\Program Files\Example\agent.exe"


def test_pe_header_requires_mz_and_pe_signature():
    assert _looks_like_pe(_pe_prefix())
    assert not _looks_like_pe(b"MZ" + b"\x00" * 100)
    assert not _looks_like_pe(b"not-a-pe")


def test_process_sensor_marks_user_writable_execution_and_stable_identity():
    provider = FakeProcesses([
        ProcessRecord(
            42, 4, "agent.exe", r"C:\Users\alice\AppData\Local\Temp\agent.exe",
            creation_time=12345,
        )
    ])
    sensor = WindowsProcessSensor(
        provider,
        user_writable_roots=(r"C:\Users\alice\AppData\Local\Temp",),
    )
    report = sensor.collect(ScanContext(run_id="process-test"))
    assert report.coverage is Coverage.COMPLETE
    item, = report.evidence
    assert item.subject == "process:42:12345"
    assert item.attributes["pid"] == 42
    assert item.attributes["user_writable_execution"] is True
    assert item.risk_score > 0


def test_process_sensor_reports_inaccessible_paths_as_partial_not_clean():
    sensor = WindowsProcessSensor(
        FakeProcesses([
            ProcessRecord(4, 0, "System", "", creation_time=100),
        ], unresolved=1),
        user_writable_roots=(),
    )
    report = sensor.collect(ScanContext())
    assert report.coverage is Coverage.PARTIAL
    assert report.skipped_items == 1
    assert "inaccessible" in report.reason


def test_persistence_sensor_inventories_normal_entry_without_calling_it_malware():
    sensor = WindowsPersistenceSensor(
        FakePersistence([
            PersistenceEntry(
                "service",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Example",
                "Example",
                r'"C:\Program Files\Example\service.exe" --service',
                scope="machine",
                target=r"C:\Program Files\Example\service.exe",
            )
        ]),
        user_writable_roots=(r"C:\Users\alice",),
    )
    report = sensor.collect(ScanContext())
    assert report.coverage is Coverage.COMPLETE
    item, = report.evidence
    assert item.attributes["persistence_entry"] is True
    assert item.attributes["user_writable_target"] is False
    assert item.risk_score == 0


def test_persistence_sensor_flags_user_writable_autorun_for_review_only():
    sensor = WindowsPersistenceSensor(
        FakePersistence([
            PersistenceEntry(
                "run-key",
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "Updater",
                r'"C:\Users\alice\AppData\Roaming\updater.exe"',
                scope="user",
                target=r"C:\Users\alice\AppData\Roaming\updater.exe",
            )
        ]),
        user_writable_roots=(r"C:\Users\alice\AppData",),
    )
    report = sensor.collect(ScanContext())
    item, = report.evidence
    assert item.attributes["user_writable_target"] is True
    assert item.risk_score >= 40
    assert item.attributes["persistence_kind"] == "run-key"


def test_persistence_sensor_keeps_uncovered_sources_visible():
    sensor = WindowsPersistenceSensor(
        FakePersistence([], uncovered=("vendor-extension",)),
        user_writable_roots=(),
    )
    report = sensor.collect(ScanContext())
    assert report.coverage is Coverage.PARTIAL
    assert "vendor-extension" in report.reason


def test_memory_sensor_ignores_mapped_executable_image_region():
    process = ProcessRecord(10, 4, "normal.exe", r"C:\Program Files\App\normal.exe", 100)
    memory = FakeMemory({
        10: MemoryInspection((
            MemoryRegion(
                0x1000, 0x2000, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_IMAGE,
                _pe_prefix(),
            ),
        ), bytes_read=len(_pe_prefix()))
    })
    sensor = WindowsMemorySensor(FakeProcesses([process]), memory)
    report = sensor.collect(
        ScanContext(budget=ScanBudget(allow_privileged=True))
    )
    assert report.coverage is Coverage.COMPLETE
    assert not report.evidence


def test_memory_sensor_emits_private_executable_pe_evidence_without_raw_bytes():
    process = ProcessRecord(
        42, 4, "agent.exe", r"C:\Users\alice\AppData\Local\Temp\agent.exe",
        12345,
    )
    prefix = _pe_prefix()
    memory = FakeMemory({
        42: MemoryInspection((
            MemoryRegion(
                0x400000, 0x3000, MEM_COMMIT,
                PAGE_EXECUTE_READWRITE, MEM_PRIVATE, prefix,
            ),
        ), bytes_read=len(prefix))
    })
    sensor = WindowsMemorySensor(FakeProcesses([process]), memory)
    report = sensor.collect(
        ScanContext(
            run_id="ram-test",
            budget=ScanBudget(max_items=100, max_bytes=65536,
                              max_seconds=10, allow_privileged=True),
        )
    )
    assert report.coverage is Coverage.COMPLETE
    item, = report.evidence
    assert item.subject == "process:42:12345"
    assert item.attributes["private_executable"] is True
    assert item.attributes["embedded_pe"] is True
    assert item.attributes["writable_executable"] is True
    assert "prefix" not in item.attributes
    assert "raw" not in item.attributes


def test_memory_access_denial_is_partial_coverage_not_no_threats():
    process = ProcessRecord(4, 0, "System", r"C:\Windows\System32\ntoskrnl.exe", 1)
    sensor = WindowsMemorySensor(
        FakeProcesses([process]),
        FakeMemory({4: MemoryInspection(access_denied=True)}),
    )
    report = sensor.collect(
        ScanContext(budget=ScanBudget(allow_privileged=True))
    )
    assert report.coverage is Coverage.PARTIAL
    assert report.skipped_items == 1
    assert "denied" in report.reason


def test_process_and_memory_evidence_feed_existing_same_subject_signature():
    process = ProcessRecord(
        42, 4, "agent.exe", r"C:\Users\alice\AppData\Local\Temp\agent.exe",
        12345,
    )
    process_report = WindowsProcessSensor(
        FakeProcesses([process]),
        user_writable_roots=(r"C:\Users\alice\AppData\Local\Temp",),
    ).collect(ScanContext(run_id="same-run"))
    memory_report = WindowsMemorySensor(
        FakeProcesses([process]),
        FakeMemory({
            42: MemoryInspection((
                MemoryRegion(
                    0x400000, 0x3000, MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE, MEM_PRIVATE, _pe_prefix(),
                ),
            ))
        }),
    ).collect(ScanContext(
        run_id="same-run",
        budget=ScanBudget(allow_privileged=True),
    ))

    findings = DEFAULT_DETECTION_SIGNATURES.evaluate(
        (*process_report.evidence, *memory_report.evidence)
    )
    rules = {item.attributes.get("rule_id") for item in findings}
    assert "memory.private-executable-pe" in rules
    assert "temp-execution-private-memory" in rules
    assert all(item.subject == "process:42:12345" for item in findings)
    fused = next(
        item for item in findings
        if item.attributes.get("rule_id") == "temp-execution-private-memory"
    )
    assert fused.attributes["pid"] == 42
    assert fused.attributes["creation_time"] == 12345
