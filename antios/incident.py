"""Bounded local incident graph for AntiOS Resident Guard.

The graph correlates already-observed evidence. It does not collect additional
sensitive data, terminate processes or make automatic enforcement decisions.
"""
from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass
import ntpath
import time
from typing import Iterable

from .behavior import ProcessEvent


def _path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(value or ""))


def _name(value: str) -> str:
    return ntpath.basename(value or "").lower()


def _classification_for_score(score: int, *, confirmed: bool = False) -> str:
    if confirmed:
        return "confirmed-threat"
    if score >= 90:
        return "critical-behavior"
    if score >= 75:
        return "high"
    if score >= 60:
        return "elevated"
    if score >= 40:
        return "observe"
    return "low"


@dataclass(frozen=True)
class IncidentNode:
    id: str
    kind: str
    label: str
    at: float
    data: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class IncidentEdge:
    source: str
    target: str
    relation: str
    at: float

    def to_dict(self) -> dict:
        return asdict(self)


class _Incident:
    def __init__(self, incident_id: str, at: float):
        self.id = incident_id
        self.started_at = at
        self.updated_at = at
        self.score = 0
        self.classification = "observe"
        self.confirmed_threat = False
        self.automatic_enforcement_eligible = False
        self.nodes: dict[str, IncidentNode] = {}
        self.edges: list[IncidentEdge] = []
        self.edge_keys: set[tuple[str, str, str]] = set()

    def touch(self, at: float) -> None:
        self.updated_at = max(self.updated_at, at)


class IncidentGraph:
    """Explainable, bounded correlation graph over Guard evidence."""

    def __init__(self, *, clock=time.monotonic, ttl=120.0, max_incidents=32,
                 max_nodes=64, max_edges=128):
        if not 30 <= ttl <= 900:
            raise ValueError("incident ttl must be between 30 and 900 seconds")
        if not 4 <= max_incidents <= 128:
            raise ValueError("max_incidents must be between 4 and 128")
        if not 16 <= max_nodes <= 256:
            raise ValueError("max_nodes must be between 16 and 256")
        if not 32 <= max_edges <= 512:
            raise ValueError("max_edges must be between 32 and 512")
        self.clock = clock
        self.ttl = float(ttl)
        self.max_incidents = int(max_incidents)
        self.max_nodes = int(max_nodes)
        self.max_edges = int(max_edges)
        self.recent_files = deque(maxlen=4096)
        self.recent_processes = deque(maxlen=512)
        self.incidents: dict[str, _Incident] = {}
        self.path_index: dict[str, str] = {}
        self.pid_index: dict[int, str] = {}
        self.pending_updates = deque(maxlen=100)
        self.total_created = 0
        self._counter = 0
        self.latest_id: str | None = None

    def _now(self, supplied: float = 0.0) -> float:
        return float(supplied or self.clock())

    def _expire(self, now: float) -> None:
        expired = [
            incident_id for incident_id, incident in self.incidents.items()
            if now - incident.updated_at > self.ttl
        ]
        for incident_id in expired:
            del self.incidents[incident_id]
        if expired:
            dead = set(expired)
            self.path_index = {
                key: value for key, value in self.path_index.items()
                if value not in dead
            }
            self.pid_index = {
                key: value for key, value in self.pid_index.items()
                if value not in dead
            }
            if self.latest_id in dead:
                self.latest_id = max(
                    self.incidents,
                    key=lambda key: self.incidents[key].updated_at,
                    default=None,
                )
        while self.recent_files and now - self.recent_files[0][0] > self.ttl:
            self.recent_files.popleft()
        while self.recent_processes and now - self.recent_processes[0][0] > self.ttl:
            self.recent_processes.popleft()

    def _new(self, now: float) -> _Incident:
        self._expire(now)
        if len(self.incidents) >= self.max_incidents:
            oldest = min(self.incidents.values(), key=lambda item: item.updated_at)
            old_id = oldest.id
            del self.incidents[old_id]
            self.path_index = {
                key: value for key, value in self.path_index.items()
                if value != old_id
            }
            self.pid_index = {
                key: value for key, value in self.pid_index.items()
                if value != old_id
            }
        self._counter += 1
        incident_id = f"INC-{self._counter:06d}"
        incident = _Incident(incident_id, now)
        self.incidents[incident_id] = incident
        self.total_created += 1
        self.latest_id = incident_id
        return incident

    def _node(self, incident: _Incident, node: IncidentNode) -> bool:
        if node.id in incident.nodes:
            incident.touch(node.at)
            return False
        if len(incident.nodes) >= self.max_nodes:
            return False
        incident.nodes[node.id] = node
        incident.touch(node.at)
        return True

    def _edge(self, incident: _Incident, source: str, target: str,
              relation: str, at: float) -> bool:
        key = (source, target, relation)
        if key in incident.edge_keys or len(incident.edges) >= self.max_edges:
            return False
        incident.edge_keys.add(key)
        incident.edges.append(IncidentEdge(source, target, relation, at))
        incident.touch(at)
        return True

    def _queue_update(self, incident: _Incident, reason: str) -> None:
        self.latest_id = incident.id
        self.pending_updates.append({
            "reason": reason,
            "incident": self.snapshot(incident.id),
        })

    def _recent_change(self, normalized: str, now: float) -> float | None:
        for changed_at, path in reversed(self.recent_files):
            if path == normalized and now - changed_at <= self.ttl:
                return changed_at
        return None

    def observe_file_change(self, path: str, *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        normalized = _path(path)
        if not normalized:
            return []
        self.recent_files.append((now, normalized))
        incident_id = self.path_index.get(normalized)
        if not incident_id or incident_id not in self.incidents:
            return []
        incident = self.incidents[incident_id]
        file_id = f"file:{normalized}"
        changed_id = f"change:{normalized}:{int(now * 1000)}"
        self._node(incident, IncidentNode(
            file_id, "file", path, now, {"path": path},
        ))
        self._node(incident, IncidentNode(
            changed_id, "file-change", "file changed", now, {"path": path},
        ))
        self._edge(incident, file_id, changed_id, "modified", now)
        process_nodes = [
            node for node in incident.nodes.values() if node.kind == "process"
        ]
        if process_nodes:
            latest = max(process_nodes, key=lambda node: node.at)
            self._edge(incident, latest.id, changed_id, "correlated-write", now)
        self._queue_update(incident, "file-change")
        return [self.snapshot(incident.id)]

    def observe_process(self, event: ProcessEvent, *,
                        behavior_findings: Iterable[dict] = ()) -> list[dict]:
        now = self._now(event.at)
        self._expire(now)
        child_path = _path(event.path)
        parent_path = _path(event.parent_path)
        findings = [item for item in behavior_findings if isinstance(item, dict)]
        behavior_score = max(
            (int(item.get("score", 0)) for item in findings
             if isinstance(item.get("score", 0), int)),
            default=0,
        )

        incident = None
        changed_at = self._recent_change(child_path, now) if child_path else None
        if event.ppid in self.pid_index:
            incident = self.incidents.get(self.pid_index[event.ppid])
        if incident is None and child_path in self.path_index:
            incident = self.incidents.get(self.path_index[child_path])
        if incident is None and changed_at is not None:
            incident = self._new(now)
        if incident is None and behavior_score >= 60:
            incident = self._new(now)
        if incident is None:
            self.recent_processes.append((now, event))
            return []

        child_id = f"process:{event.pid}"
        child_label = event.path or event.image or f"pid:{event.pid}"
        self._node(incident, IncidentNode(
            child_id, "process", child_label, now,
            {"pid": event.pid, "ppid": event.ppid, "image": event.image,
             "path": event.path},
        ))
        self.pid_index[event.pid] = incident.id
        if child_path:
            self.path_index[child_path] = incident.id

        if event.ppid:
            parent_id = f"process:{event.ppid}"
            parent_label = event.parent_path or event.parent_image or f"pid:{event.ppid}"
            self._node(incident, IncidentNode(
                parent_id, "process", parent_label, now,
                {"pid": event.ppid, "image": event.parent_image,
                 "path": event.parent_path},
            ))
            self.pid_index[event.ppid] = incident.id
            if parent_path:
                self.path_index[parent_path] = incident.id
            self._edge(incident, parent_id, child_id, "spawned", now)

        if changed_at is not None and child_path:
            file_id = f"file:{child_path}"
            self._node(incident, IncidentNode(
                file_id, "file", event.path or event.image, changed_at,
                {"path": event.path, "changed_at": changed_at},
            ))
            self.path_index[child_path] = incident.id
            self._edge(incident, file_id, child_id, "executed-as", now)

        for index, finding in enumerate(findings[:16]):
            rule = str(finding.get("rule") or "behavior")
            score = int(finding.get("score", 0)) if isinstance(finding.get("score", 0), int) else 0
            signal_id = f"behavior:{incident.id}:{rule}:{index}:{int(now * 1000)}"
            self._node(incident, IncidentNode(
                signal_id, "behavior", rule, now,
                {"rule": rule, "score": score,
                 "severity": finding.get("severity"),
                 "summary": finding.get("summary")},
            ))
            self._edge(incident, child_id, signal_id, "raised-signal", now)
            incident.score = max(incident.score, min(95, max(0, score)))
            incident.classification = _classification_for_score(
                incident.score, confirmed=incident.confirmed_threat
            )

        self.recent_processes.append((now, event))
        self._queue_update(incident, "process-correlation")
        return [self.snapshot(incident.id)]

    def observe_behavior_findings(self, findings: Iterable[dict], *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        updates: list[dict] = []
        for finding in [item for item in findings if isinstance(item, dict)][:16]:
            score = finding.get("score", 0)
            score = int(score) if isinstance(score, int) else 0
            if score < 60:
                continue
            rule = str(finding.get("rule") or "behavior")
            subject = str(finding.get("subject") or "")
            normalized = _path(subject) if subject and subject != "filesystem" else ""
            incident = self.incidents.get(self.path_index.get(normalized, "")) if normalized else None

            process = next((
                event for seen_at, event in reversed(self.recent_processes)
                if now - seen_at <= self.ttl and normalized and
                _path(event.path) == normalized
            ), None)
            if incident is None and process is not None and process.pid in self.pid_index:
                incident = self.incidents.get(self.pid_index[process.pid])
            if incident is None:
                incident = self._new(now)

            anchor_id = None
            if process is not None:
                anchor_id = f"process:{process.pid}"
                self._node(incident, IncidentNode(
                    anchor_id, "process", process.path or process.image, now,
                    {"pid": process.pid, "ppid": process.ppid,
                     "image": process.image, "path": process.path},
                ))
                self.pid_index[process.pid] = incident.id
                if normalized:
                    self.path_index[normalized] = incident.id

            signal_id = f"behavior:{incident.id}:{rule}:{int(now * 1000)}"
            self._node(incident, IncidentNode(
                signal_id, "behavior", rule, now,
                {"rule": rule, "score": score,
                 "severity": finding.get("severity"),
                 "summary": finding.get("summary"),
                 "subject": subject},
            ))
            if anchor_id:
                self._edge(incident, anchor_id, signal_id, "raised-signal", now)

            if rule in {"mass-file-changes", "interpreter-with-mass-file-changes"}:
                recent = [
                    (changed_at, path) for changed_at, path in self.recent_files
                    if now - changed_at <= 10.0
                ][-32:]
                for changed_at, changed_path in recent:
                    file_id = f"file:{changed_path}"
                    self._node(incident, IncidentNode(
                        file_id, "file", changed_path, changed_at,
                        {"path": changed_path, "changed_at": changed_at},
                    ))
                    self.path_index[changed_path] = incident.id
                    self._edge(
                        incident, anchor_id or signal_id, file_id,
                        "correlated-write", now
                    )

            incident.score = max(incident.score, min(95, max(0, score)))
            incident.classification = _classification_for_score(
                incident.score, confirmed=incident.confirmed_threat
            )
            self._queue_update(incident, "behavior-correlation")
            updates.append(self.snapshot(incident.id))
        return updates

    def observe_risk(self, context: dict, *, at: float = 0.0) -> list[dict]:
        now = self._now(at)
        self._expire(now)
        path = str(context.get("path") or "")
        normalized = _path(path)
        score = context.get("score", 0)
        score = int(score) if isinstance(score, int) else 0
        confirmed = context.get("confirmed_threat") is True

        incident = self.incidents.get(self.path_index.get(normalized, "")) if normalized else None
        if incident is None and (score >= 40 or confirmed):
            incident = self._new(now)
        if incident is None:
            return []

        file_id = f"file:{normalized}" if normalized else f"file:unknown:{incident.id}"
        self._node(incident, IncidentNode(
            file_id, "file", path or "unknown file", now, {"path": path},
        ))
        if normalized:
            self.path_index[normalized] = incident.id

        verdict_id = f"risk:{incident.id}:{int(now * 1000)}"
        self._node(incident, IncidentNode(
            verdict_id, "risk", str(context.get("classification") or "unknown"),
            now,
            {
                "score": score,
                "classification": context.get("classification"),
                "scanner_verdict": context.get("scanner_verdict"),
                "scanner_complete": context.get("scanner_complete"),
                "confirmed_threat": confirmed,
                "behavior_score": context.get("behavior_score"),
                "behavior_rules": context.get("behavior_rules", []),
                "origin": context.get("origin"),
                "native_pre_execution": context.get("native_pre_execution"),
                "automatic_enforcement_eligible":
                    context.get("automatic_enforcement_eligible") is True,
            },
        ))
        self._edge(incident, file_id, verdict_id, "evaluated-as", now)
        incident.score = max(incident.score, min(100, max(0, score)))
        incident.confirmed_threat = incident.confirmed_threat or confirmed
        incident.classification = _classification_for_score(
            incident.score, confirmed=incident.confirmed_threat
        )
        incident.automatic_enforcement_eligible = (
            incident.automatic_enforcement_eligible or
            context.get("automatic_enforcement_eligible") is True
        )
        self._queue_update(incident, "risk-evaluation")
        return [self.snapshot(incident.id)]

    def snapshot(self, incident_id: str) -> dict:
        incident = self.incidents[incident_id]
        return {
            "id": incident.id,
            "started_at": incident.started_at,
            "updated_at": incident.updated_at,
            "score": incident.score,
            "classification": incident.classification,
            "confirmed_threat": incident.confirmed_threat,
            "automatic_enforcement_eligible":
                incident.automatic_enforcement_eligible,
            "node_count": len(incident.nodes),
            "edge_count": len(incident.edges),
            "nodes": [node.to_dict() for node in incident.nodes.values()],
            "edges": [edge.to_dict() for edge in incident.edges],
        }

    def drain_updates(self) -> list[dict]:
        updates = list(self.pending_updates)
        self.pending_updates.clear()
        return updates

    def status(self) -> dict:
        now = self.clock()
        self._expire(now)
        latest = self.snapshot(self.latest_id) if self.latest_id in self.incidents else None
        highest = max((item.score for item in self.incidents.values()), default=0)
        if highest >= 90:
            state = "alert"
        elif highest >= 60:
            state = "attention"
        else:
            state = "normal"
        return {
            "state": state,
            "mode": "correlation-graph",
            "active_incidents": len(self.incidents),
            "total_created": self.total_created,
            "highest_score": highest,
            "latest": latest,
            "limits": {
                "ttl_seconds": self.ttl,
                "max_incidents": self.max_incidents,
                "max_nodes_per_incident": self.max_nodes,
                "max_edges_per_incident": self.max_edges,
            },
        }
