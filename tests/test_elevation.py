from types import SimpleNamespace

from antios import elevation


class Function:
    def __init__(self, result):
        self.result = result
        self.calls = []
    def __call__(self, *args):
        self.calls.append(args)
        return self.result


def shell_mock(monkeypatch, admin=False, status=42):
    shell = SimpleNamespace(IsUserAnAdmin=Function(admin), ShellExecuteW=Function(status))
    monkeypatch.setattr(elevation, 'os', SimpleNamespace(name='nt', getcwd=lambda: 'C:\\work folder'))
    monkeypatch.setattr(elevation.ctypes, 'WinDLL', lambda *a, **k: shell, raising=False)
    return shell


def test_already_admin_does_not_prompt(monkeypatch):
    shell = shell_mock(monkeypatch, admin=True)
    assert elevation.ensure_administrator() is None
    assert not shell.ShellExecuteW.calls


def test_source_launch_uses_runas_and_preserves_language(monkeypatch):
    shell = shell_mock(monkeypatch)
    monkeypatch.setattr(elevation.sys, 'frozen', False, raising=False)
    assert elevation.ensure_administrator('ru') == 0
    call = shell.ShellExecuteW.calls[0]
    assert call[1] == 'runas'
    assert call[3] == '-m antios dashboard --lang ru'


def test_frozen_launch_quotes_arguments_and_denial_does_not_continue(monkeypatch):
    shell = shell_mock(monkeypatch, status=5)
    monkeypatch.setattr(elevation.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(elevation.sys, 'argv', ['AntiOS.exe', '--config', 'C:\\a b\\settings.toml', 'dashboard'])
    assert elevation.ensure_administrator() == 1
    assert '"C:\\a b\\settings.toml"' in shell.ShellExecuteW.calls[0][3]



def test_privileged_action_allowlist_rejects_unknown_operations():
    import pytest
    with pytest.raises(ValueError, match="Unsupported privileged"):
        elevation.request_protection_elevation("arbitrary-command")


def test_explicit_repair_uses_only_managed_cli_with_fixed_arguments(monkeypatch):
    from pathlib import Path
    shell = shell_mock(monkeypatch, status=42)
    monkeypatch.setattr(
        elevation, "managed_cli_path",
        lambda: Path("C:/Program Files/AntiOS/AntiOS.exe"),
    )
    elevation.request_protection_elevation("repair")
    call = shell.ShellExecuteW.calls[0]
    assert call[1] == "runas"
    assert call[2].endswith("AntiOS.exe")
    assert call[3] == "protection-repair --yes --update-signatures --json"
    elevation.request_protection_elevation("bootstrap")
    assert shell.ShellExecuteW.calls[1][3] == "protection-bootstrap --yes --json"


def test_denied_uac_never_reports_success(monkeypatch):
    import pytest
    from pathlib import Path

    shell_mock(monkeypatch, status=5)
    monkeypatch.setattr(
        elevation, "managed_cli_path",
        lambda: Path("C:/Program Files/AntiOS/AntiOS.exe"),
    )
    with pytest.raises(PermissionError, match="denied"):
        elevation.request_protection_elevation("repair")
