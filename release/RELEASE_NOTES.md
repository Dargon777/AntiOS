# AntiOS v2.0.0 alpha 9

Alpha 9 adds a read-only **Storage Cleanup** workflow.

## Storage Cleanup

The new dashboard page can scan a user-selected folder for:

- exact duplicate files;
- old large files;
- installer/archive candidates;
- empty files.

Duplicate detection is content-based:

1. files are grouped by size;
2. likely matches receive a quick first/last-block fingerprint;
3. only remaining candidates are confirmed with a full SHA-256 hash.

The dashboard shows potential reclaimable duplicate space, supports background progress and cancellation, and can open the containing folder for any result.

No file is deleted automatically.

## Honest “unused” handling

AntiOS does not claim that a file is unused based on Windows last-access timestamps. Those timestamps can be disabled, delayed or unreliable.

“Old” candidates therefore mean **last modified at least 180 days ago and at least 500 MB by default**.

## CLI

`storage-scan` / `cleanup-scan` supports custom old-file, large-file and duplicate-size thresholds plus JSON output.

## Localization

The Storage Cleanup UI is translated across all seven supported languages.

The existing Windows Health & Privacy dashboard, Store packaging and advanced CLI safety model are unchanged.
