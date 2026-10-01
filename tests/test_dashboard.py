from antios.dashboard import (
    BUG_URL,
    FEATURE_URL,
    PRIVACY_URL,
    PROJECT_URL,
    DARK_THEME,
    LIGHT_THEME,
    STATUS_STYLE,
    SUPPORT_URL,
    THEME,
    _apply_theme_palette,
    main,
)


def test_dashboard_self_test_does_not_open_window():
    assert main(["--self-test"]) == 0


def test_dashboard_community_links_are_public_project_links():
    assert PROJECT_URL == "https://github.com/Dargon777/AntiOS"
    assert "bug_report.yml" in BUG_URL
    assert "feature_request.yml" in FEATURE_URL
    assert PRIVACY_URL.endswith("/PRIVACY.md")
    assert SUPPORT_URL.endswith("/SUPPORT.md")


def test_dashboard_theme_has_required_semantic_colors():
    for key in (
        "bg",
        "sidebar",
        "surface",
        "border",
        "text",
        "muted",
        "accent",
        "ok",
        "review",
        "warn",
        "info",
    ):
        assert key in THEME
        assert THEME[key].startswith("#")


def test_every_health_level_has_visual_status_mapping():
    for level in ("ok", "advisory", "warn", "info"):
        label, foreground, background = STATUS_STYLE[level]
        assert label
        assert foreground.startswith("#")
        assert background.startswith("#")


def test_dashboard_self_test_accepts_all_locales():
    for language in ("en", "ru", "es", "zh-CN", "fi", "pl", "mn"):
        assert main(["--self-test", "--lang", language]) == 0



def test_storage_cleanup_translation_keys_exist_for_all_locales():
    from antios.i18n import SUPPORTED_LANGUAGES, Translator

    for language in SUPPORTED_LANGUAGES:
        tr = Translator(language)
        assert tr.t("nav.cleanup") != "nav.cleanup"
        assert tr.t("cleanup.scan") != "cleanup.scan"
        assert tr.t("cleanup.note", days=180) != "cleanup.note"



def test_light_and_dark_palettes_have_required_keys():
    required = {
        "bg",
        "sidebar",
        "surface",
        "surface_alt",
        "surface_hover",
        "border",
        "text",
        "muted",
        "muted_2",
        "accent",
        "accent_hover",
        "accent_text",
        "ok",
        "ok_bg",
        "review",
        "review_bg",
        "warn",
        "warn_bg",
        "info",
        "info_bg",
    }
    assert required <= set(DARK_THEME)
    assert required <= set(LIGHT_THEME)


def test_theme_palette_can_switch_without_restarting_python():
    original = dict(THEME)
    try:
        assert _apply_theme_palette("light") == "light"
        assert THEME["bg"] == LIGHT_THEME["bg"]
        assert _apply_theme_palette("dark") == "dark"
        assert THEME["bg"] == DARK_THEME["bg"]
    finally:
        THEME.clear()
        THEME.update(original)


def test_settings_translation_keys_exist_for_all_locales():
    from antios.i18n import SUPPORTED_LANGUAGES, Translator

    keys = (
        "nav.settings",
        "page.settings.subtitle",
        "settings.language",
        "settings.theme",
        "settings.theme.dark",
        "settings.theme.light",
        "settings.cleanup.title",
        "settings.save",
        "settings.reset",
        "settings.about.title",
    )
    for language in SUPPORTED_LANGUAGES:
        tr = Translator(language)
        for key in keys:
            assert tr.t(key) != key
