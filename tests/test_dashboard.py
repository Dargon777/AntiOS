from antios.dashboard import (
    BUG_URL,
    FEATURE_URL,
    PRIVACY_URL,
    PROJECT_URL,
    STATUS_STYLE,
    SUPPORT_URL,
    THEME,
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
    for language in ("en", "ru", "es", "zh-CN"):
        assert main(["--self-test", "--lang", language]) == 0
