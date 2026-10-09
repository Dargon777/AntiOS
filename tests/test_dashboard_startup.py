from types import SimpleNamespace

from antios import dashboard_startup
from antios.dashboard import main


def test_dashboard_self_test_accepts_background_flag():
    assert main(["--self-test", "--background"]) == 0


def test_dashboard_startup_status_parses_script_json(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        return SimpleNamespace(
            stdout='{"enabled":true,"state":"Ready","task":"AntiOS Control Center"}'
        )

    monkeypatch.setattr(dashboard_startup, "_run_script", fake_run)

    payload = dashboard_startup.dashboard_startup_status()

    assert payload["enabled"] is True
    assert payload["state"] == "Ready"
    assert calls == [("-Status", "-Json")]


def test_enable_dashboard_startup_uses_managed_unsigned_guardrail(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args == ("-Status", "-Json"):
            return SimpleNamespace(stdout='{"enabled":true,"state":"Ready"}')
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(dashboard_startup, "_run_script", fake_run)

    payload = dashboard_startup.set_dashboard_startup(True)

    assert payload["enabled"] is True
    assert calls[0] == ("-Apply", "-AllowManagedUnsigned")
    assert calls[1] == ("-Status", "-Json")


def test_disable_dashboard_startup_unregisters_only_dashboard_task(monkeypatch):
    calls = []

    def fake_run(*args):
        calls.append(args)
        if args == ("-Status", "-Json"):
            return SimpleNamespace(stdout='{"enabled":false,"state":"Absent"}')
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(dashboard_startup, "_run_script", fake_run)

    payload = dashboard_startup.set_dashboard_startup(False)

    assert payload["enabled"] is False
    assert calls[0] == ("-Uninstall", "-Apply")
    assert calls[1] == ("-Status", "-Json")


def test_reconcile_dashboard_startup_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(
        dashboard_startup,
        "dashboard_startup_status",
        lambda: {"enabled": True, "state": "Ready"},
    )
    monkeypatch.setattr(
        dashboard_startup,
        "set_dashboard_startup",
        lambda enabled: calls.append(enabled),
    )

    payload = dashboard_startup.reconcile_dashboard_startup(True)

    assert payload["enabled"] is True
    assert calls == []
