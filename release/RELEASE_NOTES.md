# AntiOS v2.0.0 alpha 6

Alpha 6 adds first-class localization for four high-reach languages:

- English
- Русский
- Español
- 简体中文

## Localization

- automatic language detection from the Windows/user locale;
- live language switcher in the dashboard without restarting the app;
- localized navigation, buttons, status badges, cards and system labels;
- localized dynamic health-check explanations and recommendations;
- localized quick-check CLI output;
- `--lang en|ru|es|zh-CN` for dashboard and quick-check commands;
- English fallback for unsupported locales or missing keys;
- translated quick-start README files for Russian, Spanish and Simplified Chinese.

Changing the dashboard language re-renders already collected results and does not repeat the system scan.

The dashboard remains read-only and the advanced CLI safety model is unchanged.
