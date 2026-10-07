# Incident Graph

AntiOS Resident Guard maintains a bounded local Incident Graph that connects
evidence already produced by Guard, behavior correlation and RiskContext.

It is a correlation and explanation layer, not a new enforcement mechanism.

## Why it exists

Individual security events are often weak in isolation:

- a file appears in Downloads;
- an executable is launched;
- a process starts a script interpreter;
- many watched files change;
- ClamAV later returns a clean, review or threat verdict.

Incident Graph connects those observations when AntiOS has a defensible relation
between them, so the user can inspect one chain instead of unrelated log lines.

A typical graph can look like:

```text
downloaded/written file
        |
    executed-as
        v
     process
        |
      spawned
        v
 PowerShell / WSH
        |
   raised-signal
        v
 behavioral finding
        |
 correlated-write
        v
 modified files
        |
   evaluated-as
        v
    RiskContext
```

## Materialization rules

Ordinary process starts do **not** create incidents.

An incident is created only when one of these relationships exists:

- a recently changed path is executed;
- behavior correlation reaches score 60 or higher;
- RiskContext reaches score 40 or higher;
- a confirmed scanner threat exists.

This prevents normal desktop activity from creating thousands of meaningless
graphs.

## Node types

Current node kinds are:

- `file`: a correlated file path;
- `file-change`: an observed modification to a file already associated with an incident;
- `process`: PID/image/path evidence from the read-only process sampler;
- `behavior`: an explainable BehaviorEngine rule;
- `risk`: the fused RiskContext decision for a scanned path.

Nodes contain only local evidence already available to AntiOS. Incident Graph
does not add command-line collection, process memory inspection or network
telemetry.

## Edge types

Current relations include:

- `executed-as`: a recently changed file became a process;
- `spawned`: observed parent PID started a child PID;
- `raised-signal`: a process is the subject of a behavior rule;
- `modified`: a known file received a later change;
- `correlated-write`: behavior correlation tied process/activity to changed files;
- `evaluated-as`: a file received a RiskContext decision.

A relation is added only when the relevant existing collector/correlation layer
already supports it. Incident Graph does not guess file ownership from temporal
proximity alone.

## Mass-change correlation

When BehaviorEngine produces `mass-file-changes` or
`interpreter-with-mass-file-changes`, Incident Graph may attach up to 32 file
paths that changed during the BehaviorEngine's ten-second mass-change window.

For interpreter correlation, the process path must match the behavior finding's
subject. AntiOS does not attribute arbitrary concurrent writes to an unrelated
process.

## Severity

Incident severity is monotonic for the life of the incident.

A later low-risk/clean evaluation cannot downgrade an earlier high-confidence
behavior chain. The incident keeps the highest observed score:

- 90-100: `critical-behavior`, unless a confirmed threat exists;
- 75-89: `high`;
- 60-74: `elevated`;
- 40-59: `observe`;
- below 40: `low`;
- confirmed threat: `confirmed-threat`.

A confirmed threat can set
`automatic_enforcement_eligible=true` because that value comes from
RiskContext. The graph itself never performs enforcement.

## Bounds

Defaults are deliberately fixed:

- active incident TTL: 120 seconds;
- maximum active incidents: 32;
- maximum nodes per incident: 64;
- maximum edges per incident: 128;
- recent file-change evidence: 4096 entries;
- recent process evidence: 512 entries;
- pending journal updates: 100.

Old incidents expire automatically. If the active incident limit is reached, the
least recently updated incident is discarded.

## Journal coalescing

Guard persists graph changes as `incident-update` events in its existing
bounded SQLite event journal.

To avoid write amplification during high file churn, multiple graph updates for
the same incident between Guard heartbeats are coalesced into a single journal
entry. The snapshot is rebuilt when drained, so the persisted event still
contains the newest nodes, edges and severity.

The existing Guard event table remains bounded to 1000 events.

## Status and UI

Guard status contains:

```json
{
  "incidents": {
    "state": "attention",
    "mode": "correlation-graph",
    "active_incidents": 1,
    "total_created": 4,
    "highest_score": 85,
    "latest": {
      "id": "INC-000004",
      "score": 85,
      "classification": "high",
      "node_count": 5,
      "edge_count": 4
    }
  }
}
```

The full latest graph is bounded and available in Guard status/journal. The
Antivirus page shows a compact incident summary below Behavior and RiskContext.
`protection-status` exposes the same capability as `incident_graph`.

The **Incidents** button in the Resident Guard card opens the structured
[Incident Viewer](INCIDENT_VIEWER.md). It reads deduplicated `incident-update`
snapshots from the same bounded SQLite journal, displays recent incidents in a
list and renders the selected graph as a causal tree with per-node evidence.

## Relationship to enforcement

Incident Graph never:

- terminates a process;
- blocks an executable;
- quarantines a file;
- changes Microsoft Defender;
- changes Windows Security Center registration;
- turns behavior-only evidence into a scanner threat.

Automatic quarantine remains gated by RiskContext's
`automatic_enforcement_eligible`, which currently requires a confirmed scanner
threat.

## Limitations

The graph is only as complete as the evidence AntiOS observes:

- Tool Help polling can miss extremely short-lived processes;
- Guard file evidence is limited to configured roots;
- command lines are not collected;
- network activity is not currently represented;
- PID reuse can make very rare ancestry cases ambiguous;
- absence of an edge means AntiOS did not establish that relation, not that the
  relation was impossible.

The graph is therefore an explainable local incident model, not a claim of full
EDR telemetry.
