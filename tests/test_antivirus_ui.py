import hashlib
import json
import importlib.util
import os
import time

import pytest

from antios.antivirus_i18n import MESSAGES
from antios.i18n import SUPPORTED_LANGUAGES, Translator


def test_antivirus_catalog_is_complete_and_formats_in_every_locale():
    keys = set(MESSAGES["en"])
    for language in SUPPORTED_LANGUAGES:
        assert keys == set(MESSAGES[language])
        tr = Translator(language)
        assert tr.t("nav.antivirus") == MESSAGES[language]["title"]
        assert "17" in tr.t("av.progress", count=17)
        assert "sample.txt" in tr.t("av.restore_confirm", path="sample.txt")


@pytest.mark.skipif(importlib.util.find_spec("tkinter") is None or
                   (os.name != "nt" and not os.environ.get("DISPLAY")),
                   reason="Native Tk display unavailable")
def test_real_tk_page_scan_and_theme_rebuild_share_job_results(tmp_path, monkeypatch):
    import tkinter as tk
    from antios.dashboard import Dashboard

    root = tk.Tk()
    root.withdraw()
    callback_errors = []
    root.report_callback_exception = lambda _kind, error, _trace: callback_errors.append(error)
    try:
        target = tmp_path / "benign.txt"
        target.write_bytes(b"benign UI fixture")
        signatures = tmp_path / "signatures.json"
        signatures.write_text(json.dumps({"schema": 1, "sha256": {
            hashlib.sha256(target.read_bytes()).hexdigest(): "Benign UI test fixture"}}))
        app = Dashboard(root, language="ru", auto_refresh=False)
        app.antivirus_path = target
        app.antivirus_signatures = signatures
        app.show_page("antivirus")
        app.antivirus_panel._scan()
        # Rebuild while a job is running: no destroyed-widget callback may fire.
        app.theme_mode = "light"
        app._rebuild_ui("antivirus")
        deadline = time.monotonic() + 10
        while app.antivirus_busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert not app.antivirus_busy
        assert app.antivirus_result["summary"]["threats"] == 1
        panel = app.antivirus_panel
        assert len(panel.tree.get_children()) == 1 + len(app.antivirus_result["issues"])
        assert panel.rows["0"]["name"] == "Benign UI test fixture"
        panel.tree.selection_set("0")
        panel._selection_changed()
        assert str(panel.quarantine_button["state"]) == "normal"
        assert str(panel.restore_button["state"]) == "disabled"
        assert target.exists()
        root.deiconify()
        root.geometry("960x650")
        root.update()
        assert panel.export_button.winfo_ismapped()
        assert panel.export_button.winfo_rooty() + panel.export_button.winfo_height() <= root.winfo_rooty() + root.winfo_height()
        for language in SUPPORTED_LANGUAGES:
            app.language = language
            app.tr = Translator(language)
            app._rebuild_ui("antivirus")
            root.update()
            assert app.antivirus_panel.status["text"]
        app.antivirus_panel._scan()
        app.antivirus_panel._cancel()
        deadline = time.monotonic() + 10
        while app.antivirus_busy and time.monotonic() < deadline:
            root.update()
            time.sleep(0.01)
        assert not app.antivirus_busy
        assert app.antivirus_result["summary"]["cancelled"]
        assert str(app.antivirus_panel.cancel_button["state"]) == "disabled"
        assert app.antivirus_panel.t("stopped") in app.antivirus_panel.status["text"]
        assert not callback_errors
    finally:
        root.destroy()
