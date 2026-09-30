# AntiOS v2.0.0 alpha 8

Alpha 8 focuses on product polish and trusted Windows distribution.

## Dashboard polish

- more spacious 1180×780 default layout;
- visible version/channel in the sidebar;
- quick actions for Windows Security, Startup Apps and Storage directly on Overview;
- improved hover/focus behavior for buttons and navigation;
- keyboard shortcuts:
  - `F5` — refresh;
  - `Ctrl+E` — export report;
  - `Ctrl+1…4` — switch dashboard pages;
- all seven interface languages remain supported.

## Windows trust

AntiOS now has two production distribution paths:

1. **Microsoft Store / MSIX**
   - dedicated GUI-only package;
   - no advanced CLI write commands in the Store package;
   - Store-ready manifest and packaging script;
   - automated Store MSIX build workflow.

2. **Direct GitHub download**
   - optional Azure Artifact Signing integration;
   - OIDC authentication from GitHub Actions;
   - SHA-256 Authenticode signing and RFC 3161 timestamping;
   - signature verification before ZIP packaging.

Direct builds remain unsigned until the repository is connected to an Artifact Signing account and `ENABLE_ARTIFACT_SIGNING=true` is configured.

The Microsoft Store signs accepted MSIX submissions itself.

The dashboard remains read-only and the advanced CLI safety model is unchanged.
