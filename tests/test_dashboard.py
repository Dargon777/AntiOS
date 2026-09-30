from antios.dashboard import (
    BUG_URL,
    FEATURE_URL,
    PRIVACY_URL,
    PROJECT_URL,
    SUPPORT_URL,
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
