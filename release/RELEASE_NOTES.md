# AntiOS v2.0.0 alpha 10

Alpha 10 adds a dedicated persistent **Settings** experience.

## Settings hub

Open Settings from the gear button at the bottom of the sidebar or with `Ctrl+,`.

### Appearance

- Language:
  - Automatic (Windows)
  - English
  - Русский
  - Español
  - 简体中文
  - Suomi
  - Polski
  - Монгол
- Theme:
  - System
  - Dark
  - Light

System theme reads the current Windows app-theme preference. Language and theme changes rebuild the GUI immediately without repeating the health scan.

### Storage Cleanup defaults

Settings can change:

- old-file age in days;
- large-file threshold in MB;
- minimum duplicate-file size in MB;
- whether AntiOS remembers the last scanned folder.

Storage Cleanup uses these values on subsequent scans.

### Persistence

GUI preferences are stored locally in the normal per-user `antios.toml` file.

Resetting Settings restores only UI and cleanup preferences. It does not overwrite advanced CLI backup/logging/metadata configuration.

### About

The page shows the AntiOS version, alpha channel, Microsoft Store ID and links to GitHub, releases, privacy and support.

All Settings UI is localized across the seven supported languages.
