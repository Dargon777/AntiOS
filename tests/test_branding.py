from pathlib import Path

from antios.tray import icon_asset, tray_variant


def test_all_brand_icon_assets_are_packaged_in_source_tree():
    for name in ("app_main.png", "app_taskbar.png", "tray_alert.png", "tray_ok.png"):
        path = icon_asset(name)
        assert path.is_file()
        assert path.suffix == ".png"


def test_tray_state_uses_green_only_for_active_protection():
    assert tray_variant("monitoring") == "ok"
    assert tray_variant("scanning") == "ok"

    for state in ("starting", "attention", "degraded", "failed", "stopped", None):
        assert tray_variant(state) == "alert"


def test_brand_assets_are_not_empty():
    sizes = [
        icon_asset(name).stat().st_size
        for name in ("app_main.png", "app_taskbar.png", "tray_alert.png", "tray_ok.png")
    ]
    assert all(size > 1000 for size in sizes)
