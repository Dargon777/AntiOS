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
    shell_mock(monkeypatch, status=42)
    calls = []
    monkeypatch.setattr(
        elevation, "managed_cli_path",
        lambda: Path("C:/Program Files/AntiOS/AntiOS.exe"),
    )
    monkeypatch.setattr(
        elevation, "_run_elevated_cli",
        lambda path, args, *, timeout_seconds:
            calls.append((str(path), args, timeout_seconds)) or {"completed": True, "exit_code": 0},
    )
    assert elevation.request_protection_elevation("repair")["completed"] is True
    assert calls[0][0].endswith("AntiOS.exe")
    assert calls[0][1] == ["protection-repair", "--yes", "--update-signatures", "--json"]
    assert calls[0][2] == 360
    elevation.request_protection_elevation("bootstrap")
    assert calls[1][1] == ["protection-bootstrap", "--yes", "--json"]
    assert calls[1][2] == 1200


def test_denied_uac_never_reports_success(monkeypatch):
    import pytest
    from pathlib import Path

    shell_mock(monkeypatch, status=5)
    monkeypatch.setattr(
        elevation, "managed_cli_path",
        lambda: Path("C:/Program Files/AntiOS/AntiOS.exe"),
    )
    monkeypatch.setattr(
        elevation, "_run_elevated_cli",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            PermissionError("Administrator consent was cancelled")
        ),
    )
    with pytest.raises(PermissionError, match="cancelled"):
        elevation.request_protection_elevation("repair")



def test_os_process_handle_reports_success_and_closes(monkeypatch):
    """Exercise the ShellExecuteEx/Wait/GetExitCode contract without Windows."""
    import ctypes
    from pathlib import Path

    calls = []
    class Native:
        def __init__(self, fn):
            self.fn = fn
        def __call__(self, *args):
            return self.fn(*args)

    def shell_exec(pointer):
        request = pointer._obj
        assert request.lpVerb == "runas"
        assert request.fMask & 0x40
        assert request.fMask & 0x100
        assert request.lpParameters == "protection-repair --yes"
        request.hProcess = 9123
        calls.append("launch")
        return 1

    def finish(handle, timeout):
        assert handle == 9123 and timeout == 360000
        calls.append("wait")
        return 0

    def exit_code(handle, result):
        assert handle == 9123
        result._obj.value = 0
        calls.append("exitcode")
        return 1

    shell = SimpleNamespace(ShellExecuteExW=Native(shell_exec))
    ole = SimpleNamespace(
        CoInitializeEx=Native(lambda *_args: 0),
        CoUninitialize=Native(lambda: None),
    )
    kernel = SimpleNamespace(
        WaitForSingleObject=Native(finish),
        GetExitCodeProcess=Native(exit_code),
        CloseHandle=Native(lambda handle: calls.append(("close", handle)) or 1),
    )
    monkeypatch.setattr(elevation, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        elevation.ctypes, "WinDLL",
        lambda name, **kwargs: (
            shell if name == "shell32" else ole if name == "ole32" else kernel
        ),
        raising=False,
    )

    result = elevation._run_elevated_cli(
        Path("C:/Program Files/AntiOS/AntiOS.exe"),
        ["protection-repair", "--yes"], timeout_seconds=360,
    )
    assert result == {"completed": True, "exit_code": 0}
    assert calls == ["launch", "wait", "exitcode", ("close", 9123)]


def test_os_elevated_process_failure_and_timeout_close_handle(monkeypatch):
    import ctypes
    from pathlib import Path
    import pytest

    closed = []
    class Native:
        def __init__(self, fn):
            self.fn = fn
        def __call__(self, *args):
            return self.fn(*args)

    def launch(pointer):
        pointer._obj.hProcess = 77
        return 1

    outcomes = [258, 0]
    shell = SimpleNamespace(ShellExecuteExW=Native(launch))
    ole = SimpleNamespace(
        CoInitializeEx=Native(lambda *_args: 0),
        CoUninitialize=Native(lambda: None),
    )
    kernel = SimpleNamespace(
        WaitForSingleObject=Native(lambda *_args: outcomes.pop(0)),
        GetExitCodeProcess=Native(
            lambda _handle, result: setattr(result._obj, "value", 2) or 1
        ),
        CloseHandle=Native(lambda handle: closed.append(handle) or 1),
    )
    monkeypatch.setattr(elevation, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        elevation.ctypes, "WinDLL",
        lambda name, **kwargs: (
            shell if name == "shell32" else ole if name == "ole32" else kernel
        ),
        raising=False,
    )
    cli = Path("C:/Program Files/AntiOS/AntiOS.exe")
    with pytest.raises(TimeoutError, match="unverified"):
        elevation._run_elevated_cli(cli, ["protection-repair"], timeout_seconds=1)
    with pytest.raises(RuntimeError, match="exit code 2"):
        elevation._run_elevated_cli(cli, ["protection-repair"], timeout_seconds=1)
    assert closed == [77, 77]



def test_managed_cli_requires_protected_install_acl(tmp_path, monkeypatch):
    """Never elevate a replaceable executable even beneath Program Files."""
    import sys
    import pytest
    from pathlib import Path
    from antios import windows_acl

    root = tmp_path / "Program Files"
    installed = root / "AntiOS"
    installed.mkdir(parents=True)
    gui = installed / "AntiOS-GUI.exe"
    cli = installed / "AntiOS.exe"
    gui.write_bytes(b"gui")
    cli.write_bytes(b"cli")

    class Key:
        def __init__(self, name):
            self.name = name
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    fake_reg = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        OpenKey=lambda _hive, name: Key(name),
        QueryValueEx=lambda key, _value: (
            str(installed) if key.name == r"SOFTWARE\DargonITP\AntiOS" else str(root),
            1,
        ),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake_reg)
    monkeypatch.setattr(elevation.sys, "frozen", True, raising=False)
    monkeypatch.setattr(elevation.sys, "executable", str(gui))

    calls = []
    monkeypatch.setattr(
        windows_acl, "assert_protected_install",
        lambda executable, trusted_root: calls.append((executable, trusted_root)),
    )
    assert elevation.managed_cli_path() == cli.resolve()
    assert calls == [(cli.resolve(), root.resolve())]

    def refuse(_executable, _root):
        raise PermissionError("Unsafe inherited ACL")
    monkeypatch.setattr(windows_acl, "assert_protected_install", refuse)
    with pytest.raises(PermissionError, match="Unsafe inherited ACL"):
        elevation.managed_cli_path()
