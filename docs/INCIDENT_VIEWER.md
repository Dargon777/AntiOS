# Incident Viewer

The Antivirus page includes a structured Incident Viewer for the bounded local
Incident Graph maintained by Resident Guard.

It replaces the old raw Guard-history JSON popup for incident inspection.

## Data source

The viewer is read-only.

It loads Incident Graph snapshots from the existing Guard SQLite event journal
through `read_incident_history()`. No second database, telemetry channel or
remote service is introduced.

The history reader:

- reads only `incident-update` events;
- keeps the newest snapshot for each incident ID;
- includes the current live `incidents.latest` snapshot when available;
- attaches the journal wall-clock timestamp as `_journal_at`;
- sorts by journal time rather than graph monotonic time;
- returns at most 100 incidents, with the GUI requesting 50.

Sorting by wall-clock journal time is important because Incident Graph
`started_at` / `updated_at` values use `time.monotonic()` for safe TTL
calculations and are not comparable across Windows reboots.

## Layout

The viewer opens from **Antivirus → Resident Guard → Incidents**.

The left pane lists recent incidents with:

- incident ID;
- classification;
- score;
- node/edge count.

The right pane displays the selected incident as a causal tree. Each row shows:

- event/object label;
- relation to its presentation parent;
- node type;
- offset from incident start.

Selecting a node shows its evidence below the tree, including available fields
such as PID/PPID, path, behavior rule, score, scanner verdict, origin and native
pre-execution state.

The UI is localized across all seven AntiOS languages.

## DAG presentation

Incident Graph is a directed graph and a node can have multiple incoming edges.
A Treeview needs one presentation parent, so `build_incident_tree()` derives a
deterministic spanning forest for display only.

Preferred causal relations are:

1. `executed-as`
2. `spawned`
3. `raised-signal`
4. `correlated-write`
5. `modified`
6. `evaluated-as`

All incoming relation names remain attached to the presentation row, so extra
graph links are still visible in node details.

The source Incident Graph is never modified by this transformation.

## Tk safety

Real graph node IDs can contain Windows paths, backslashes and colons. The
viewer therefore uses simple internal Treeview item IDs such as `node-0`,
while retaining the real graph ID in its Python model.

This avoids relying on Tcl/Tk identifier escaping for arbitrary Windows paths.

## Privacy and enforcement

Incident Viewer only displays local evidence already stored by Guard.

It does not:

- collect new process data;
- read process memory;
- upload incident information;
- terminate processes;
- quarantine files;
- change Microsoft Defender;
- change RiskContext decisions.

Closing the viewer has no effect on the running Guard or Incident Graph.


## Response Center

The viewer also exposes a conservative
[Incident Response Center](INCIDENT_RESPONSE.md) for rescanning linked paths,
opening their location, exporting a local report and isolating only freshly
confirmed scanner threats.

Behavior/Incident Graph severity alone never enables isolation.
