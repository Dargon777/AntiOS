# Incident Response Center

The Incident Viewer includes a bounded, local Response Center for safe follow-up
actions on one selected incident.

Response Center is deliberately conservative. It can rescan linked files, open
their location, export a report, and isolate only freshly confirmed scanner
threats.

It never turns behavior scores or Incident Graph severity into destructive
authority.

## Actions

The viewer exposes four response actions:

- **Rescan linked** — scan file/process paths already represented in the
  selected Incident Graph.
- **Isolate confirmed** — quarantine only fresh scanner findings that are
  suitable for the existing quarantine revalidation path.
- **Open location** — open the selected node's local directory in Windows
  Explorer.
- **Export report** — write a local JSON report containing the incident and any
  Response Center scan/isolation results.

The Response Center does not terminate processes or provide a generic
"block/kill everything in this incident" action.

## Linked-path selection

`incident_file_paths()` extracts at most 64 unique absolute Windows paths from
`file`, `file-change`, and `process` nodes.

It does not:

- interpret labels as paths;
- accept relative strings;
- use behavior-node text as a file target;
- collect new files outside the existing graph.

Process executable paths are included because they are already explicit graph
evidence.

## Fresh rescan requirement

Isolation is disabled until the current incident has completed a fresh Response
Center scan.

The scan:

- uses the AntiOS ClamAV engine;
- preserves strict verified-peer behavior on Windows;
- uses the configured local signature file when present;
- scans linked paths sequentially;
- records per-path failures instead of treating them as clean;
- can be cancelled if the Incident Viewer is closed.

A high Incident Graph score, including `critical-behavior`, cannot enable
isolation by itself.

## Quarantine eligibility

A fresh result is eligible for the isolation button only when it contains a
finding with all of the following:

- `kind == "threat"`;
- an absolute file path from the scan result;
- a syntactically valid 64-character SHA-256 digest;
- a four-element file fingerprint.

Review findings and malformed/incomplete threat records are excluded.

Duplicate threat findings for the same normalized path and SHA-256 are
deduplicated before isolation.

## Explicit confirmation

After a fresh scan reports eligible threats, **Isolate confirmed** becomes
available.

The user must explicitly confirm the number of threats immediately before
isolation.

Response Center then passes the fresh finding into the existing
`Quarantine.add()` path. Quarantine independently reopens the file and verifies
the SHA-256 and file fingerprint before touching the original.

If the file changed after the scan, quarantine fails safely and reports the
error. Response Center does not override that protection.

## Behavior-only incidents

A behavior-only incident can be score 95 / `critical-behavior` and still have
zero isolation candidates.

Example:

```text
Incident Graph: critical-behavior / 95
Fresh response scan: no confirmed threat
Isolation candidates: 0
```

This is intentional.

## Open location

Open location uses the selected node's explicit `data.path` field. It opens
the containing directory through Windows, without invoking a shell command.

If the location no longer exists, the viewer reports the error and does not
attempt a fallback path.

## Export report

The exported JSON document contains:

- the selected Incident Graph snapshot;
- the latest Response Center scan result for that incident, if any;
- the latest isolation result for that incident, if any;
- explicit safety metadata stating that behavior-only evidence cannot trigger
  automatic enforcement and that isolation requires a fresh confirmed scanner
  finding.

Exports are local and user-initiated. AntiOS does not automatically upload
incident reports.

## UI behavior

Response Center actions run outside the Tk main thread where needed. The viewer
polls a local in-memory queue to update progress and completion text.

While a response action is active, response buttons are disabled to prevent
overlapping operations.

Closing the viewer cancels an in-progress rescan. An isolation already in
progress is allowed to finish each quarantine transaction safely rather than
being interrupted between its verification and storage steps.

## Limits and non-goals

Response Center currently does not:

- kill or suspend processes;
- delete arbitrary files;
- isolate behavior-only findings;
- disable Microsoft Defender;
- change Windows Security Center;
- upload telemetry;
- automatically remediate an entire incident;
- scan paths not already represented by the selected Incident Graph.

Those limits are deliberate.
