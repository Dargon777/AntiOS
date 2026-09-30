# AntiOS v2.0.0 alpha 7

Alpha 7 expands AntiOS localization from four to seven languages.

Supported dashboard and quick-check languages:

- English
- Русский
- Español
- 简体中文
- Suomi
- Polski
- Монгол

## Localization

- automatic language detection now recognizes Finnish, Polish and Mongolian locales;
- the live dashboard language selector exposes all seven languages;
- localized health-check explanations, recommendations and dynamic status text for Finnish, Polish and Mongolian;
- `quick-check --lang fi|pl|mn` and `dashboard --lang fi|pl|mn`;
- Finnish, Polish and Mongolian quick-start README files;
- English remains the fallback if a locale or future translation key is unavailable;
- CI verifies translation-key coverage across all seven locales.

Changing the dashboard language still re-renders already collected results without repeating the system scan.

The dashboard remains read-only and the advanced CLI safety model is unchanged.
