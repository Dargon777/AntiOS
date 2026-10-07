# RiskContext

`RiskContext` is AntiOS's explainable per-file decision layer. It combines
independent evidence without turning every suspicious signal into a malware
verdict.

The implementation lives in `antios/risk.py`.

## Evidence model

Each evaluation records:

- scanner verdict and whether the scan was complete;
- whether a confirmed scanner threat exists;
- review/heuristic state;
- recent path-specific behavior score and rule IDs;
- coarse file origin (Downloads, user Temp, Startup, Windows, Program Files or other);
- native pre-execution state: active, inactive or unknown.

Native state is **protection context**, not maliciousness evidence. Enabling or
disabling the native filter never changes a file's risk score.

## Automatic-enforcement boundary

Only a confirmed scanner threat produces:

```text
automatic_enforcement_eligible = true
```

Behavior-only, origin-only, incomplete-scan and review decisions always remain
manual/review decisions, even when the fused score is very high.

This preserves the existing separation:

- ClamAV/native content verdicts establish confirmed malicious content;
- behavior correlation adds context and prioritization;
- origin adds weak context;
- native enforcement describes whether an execution boundary is protected.

Resident Guard's explicit auto-quarantine mode now checks this field before
isolating a confirmed threat. It does not quarantine on a behavior score alone.

## Score construction

Confirmed threat:

- score 100;
- classification `confirmed-threat`;
- recommended action `quarantine-or-native-block`;
- automatic enforcement eligible.

Otherwise the scanner establishes a base:

- review/heuristic: 65;
- incomplete/untrusted scan: 50;
- complete clean scan: 0.

Recent path-specific behavior raises the base:

- behavior 90-100 -> at least 90;
- behavior 75-89 -> at least 80;
- behavior 60-74 -> at least 70;
- behavior below 60 -> at most 45 by itself.

Origin then adds only weak context:

- Startup: +15;
- user Temp: +10;
- Downloads: +5;
- Windows / Program Files / other: +0.

Non-confirmed decisions are capped at 95.

A clean file from Downloads with no behavior evidence therefore remains low
(score 5). A clean path with critical behavior may reach 90-95, but still cannot
be automatically quarantined or blocked by RiskContext.

## Classifications

| Score / evidence | Classification | Default action |
| --- | --- | --- |
| confirmed scanner threat | `confirmed-threat` | quarantine or native content block |
| 90-95 | `critical-behavior` | review immediately |
| 75-89 | `high` | review and rescan |
| 60-74 | `elevated` | review |
| 40-59 | `observe` | observe |
| 0-39 | `low` | none |

## Behavior freshness

Guard asks the behavior engine for findings whose exact subject matches the
scanned path. Evidence older than 60 seconds is excluded from the scan's
RiskContext.

Global filesystem behavior is still visible in Guard's behavior status, but it
is not blindly applied to every unrelated file being scanned.

Process sampling remains active during a scan because the isolated scan worker's
cancellation/heartbeat callback also services the 500 ms Windows process
snapshot cadence. This prevents a long scan from creating a blind period in the
correlation layer.

## Native state

Guard caches the native pre-execution probe for 15 seconds. The probe is
tri-state:

- `active`: native service and driver are running in enforcement mode;
- `inactive`: native state is known and enforcement is off;
- `unknown`: the native component is absent, unreachable or cannot be
  determined safely.

Probe failures never mark a file as more suspicious. They only reduce the
available protection context and increment the local probe-error counter.

## Persistence and UI

Every completed Guard scan updates the in-memory/latest persisted Guard status:

```json
{
  "risk": {
    "mode": "fusion",
    "evaluations": 12,
    "highest_score": 80,
    "native_pre_execution": "active",
    "native_probe_errors": 0,
    "last": {
      "score": 80,
      "classification": "high",
      "automatic_enforcement_eligible": false
    }
  }
}
```

To avoid flooding the bounded Guard history, only contexts with score >= 40,
confirmed threats, or incomplete scans are journaled as `risk-context` events.
Clean/low evaluations remain available as the latest status and counters.

The Antivirus UI displays the latest risk classification and score below
behavior monitoring. `protection-status` exposes the same fused context.

## Non-goals

RiskContext does not:

- terminate processes;
- disable or reconfigure Microsoft Defender;
- spoof Windows Security Center;
- install hooks or inject into processes;
- infer malware from file location alone;
- make behavior-only findings eligible for automatic quarantine;
- replace native pre-execution content enforcement.

Those boundaries are deliberate false-positive and coexistence controls.
