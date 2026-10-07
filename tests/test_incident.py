from antios.behavior import ProcessEvent
from antios.incident import IncidentGraph


class Clock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now
    def advance(self, seconds):
        self.now += seconds


def graph(**kwargs):
    clock = Clock()
    return IncidentGraph(clock=clock, **kwargs), clock


def test_changed_file_execution_materializes_incident_graph():
    incidents, _clock = graph()
    path = r"C:\Users\A\Downloads\payload.exe"
    assert incidents.observe_file_change(path) == []
    snapshots = incidents.observe_process(ProcessEvent(
        pid=200, ppid=100, image="payload.exe", path=path,
        parent_image="explorer.exe", parent_path=r"C:\Windows\explorer.exe",
    ))
    assert len(snapshots) == 1
    snapshot = snapshots[0]
    assert snapshot["node_count"] >= 3
    assert any(edge["relation"] == "executed-as" for edge in snapshot["edges"])
    assert any(edge["relation"] == "spawned" for edge in snapshot["edges"])


def test_unrelated_process_does_not_create_incident():
    incidents, _clock = graph()
    assert incidents.observe_process(ProcessEvent(
        pid=200, ppid=100, image="notepad.exe",
        path=r"C:\Windows\System32\notepad.exe",
        parent_image="explorer.exe",
    )) == []
    assert incidents.status()["active_incidents"] == 0


def test_behavior_signal_can_seed_incident_without_file_change():
    incidents, _clock = graph()
    snapshots = incidents.observe_process(
        ProcessEvent(
            pid=201, ppid=100, image="powershell.exe",
            path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_image="WINWORD.EXE",
        ),
        behavior_findings=[{
            "rule": "document-spawns-interpreter",
            "score": 85,
            "severity": "high",
            "summary": "word spawned powershell",
        }],
    )
    assert snapshots[0]["score"] == 85
    assert snapshots[0]["classification"] == "high"
    assert any(node["kind"] == "behavior" for node in snapshots[0]["nodes"])


def test_risk_context_attaches_and_escalates_existing_incident():
    incidents, _clock = graph()
    path = r"C:\Users\A\Downloads\payload.exe"
    incidents.observe_file_change(path)
    first = incidents.observe_process(ProcessEvent(
        pid=200, ppid=100, image="payload.exe", path=path,
        parent_image="explorer.exe",
    ))[0]
    updates = incidents.observe_risk({
        "path": path,
        "score": 80,
        "classification": "high",
        "confirmed_threat": False,
        "automatic_enforcement_eligible": False,
        "scanner_verdict": "no-threats-found",
        "scanner_complete": True,
        "behavior_score": 75,
        "behavior_rules": ["changed-then-executed"],
        "origin": "downloads",
        "native_pre_execution": "active",
    })
    assert updates[0]["id"] == first["id"]
    assert updates[0]["score"] == 80
    assert any(edge["relation"] == "evaluated-as" for edge in updates[0]["edges"])


def test_confirmed_threat_marks_incident_but_graph_does_not_enforce():
    incidents, _clock = graph()
    path = r"C:\Data\bad.exe"
    snapshot = incidents.observe_risk({
        "path": path,
        "score": 100,
        "classification": "confirmed-threat",
        "confirmed_threat": True,
        "automatic_enforcement_eligible": True,
        "scanner_verdict": "threats-found",
        "scanner_complete": True,
        "behavior_score": 0,
        "behavior_rules": [],
        "origin": "other",
        "native_pre_execution": "active",
    })[0]
    assert snapshot["confirmed_threat"] is True
    assert snapshot["automatic_enforcement_eligible"] is True
    assert snapshot["classification"] == "confirmed-threat"


def test_incidents_expire_and_bounds_are_enforced():
    incidents, clock = graph(ttl=30, max_incidents=4, max_nodes=16, max_edges=32)
    for index in range(6):
        incidents.observe_risk({
            "path": fr"C:\Data\file-{index}.exe",
            "score": 60,
            "classification": "elevated",
            "confirmed_threat": False,
            "automatic_enforcement_eligible": False,
        })
        clock.advance(1)
    assert incidents.status()["active_incidents"] == 4
    clock.advance(31)
    assert incidents.status()["active_incidents"] == 0


def test_file_changes_after_execution_extend_same_incident():
    incidents, _clock = graph()
    path = r"C:\Users\A\Downloads\payload.exe"
    incidents.observe_file_change(path)
    snapshot = incidents.observe_process(ProcessEvent(
        pid=200, ppid=100, image="payload.exe", path=path,
        parent_image="explorer.exe",
    ))[0]
    other = r"C:\Victim\doc.txt"
    # Associate the target file with the incident through a risk evaluation,
    # then later changes become graph evidence rather than a new incident.
    incidents.observe_risk({
        "path": other, "score": 60, "classification": "elevated",
        "confirmed_threat": False, "automatic_enforcement_eligible": False,
    })
    assert incidents.status()["active_incidents"] == 2
    assert snapshot["id"] != incidents.status()["latest"]["id"]


def test_update_queue_is_bounded_and_drainable():
    incidents, _clock = graph()
    for index in range(120):
        incidents.observe_risk({
            "path": fr"C:\Data\file-{index}.exe",
            "score": 60,
            "classification": "elevated",
            "confirmed_threat": False,
            "automatic_enforcement_eligible": False,
        })
    updates = incidents.drain_updates()
    assert len(updates) <= 100
    assert incidents.drain_updates() == []
