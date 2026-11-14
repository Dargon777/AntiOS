# Resident Guard

Resident Guard is AntiOS's optional background file-monitoring layer.

It watches configured locations, submits relevant file activity to the AntiOS Engine and reports detections, errors and incomplete coverage.

Guard uses the AntiOS Engine directly; current builds do not install or depend on ClamAV or an AntiOS AMSI provider.

## Limits

Guard is post-write monitoring, not a Windows kernel minifilter. It does not claim complete pre-execution blocking.

Confirmed scanner evidence can be handled according to the configured quarantine policy. Behavior-only, sensor-only or posture-only findings remain review evidence.

If a confirmed finding's exact file hash also appears in the local trusted-file
baseline, Guard records an evidence conflict and leaves the file for review.
Automatic quarantine also pauses if the baseline is unreadable or the scan
worker was interrupted. The finding remains visible for a fresh scan and a
manual decision.

If Guard cannot maintain normal monitoring, it should expose a degraded or attention state instead of silently presenting full protection.
