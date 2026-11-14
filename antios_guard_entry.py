"""Non-elevating, dedicated resident scanner and its isolated scan worker."""
import os
import sys


def _detach_console() -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    if not kernel32.FreeConsole():
        raise ctypes.WinError(ctypes.get_last_error())


def run_entry() -> int:
    args = sys.argv[1:]
    packaged = getattr(sys, "frozen", False) or "__compiled__" in globals()
    if (os.name == "nt" and packaged and args[:1] == ["run"]
            and not {"-h", "--help"}.intersection(args[1:])):
        # Task Scheduler executes this console-subsystem binary directly.
        # Detach before importing the engine so console closure cannot end Guard.
        from contextlib import redirect_stderr, redirect_stdout

        _detach_console()
        with open(os.devnull, "w", encoding="utf-8") as sink, redirect_stdout(sink), redirect_stderr(sink):
            from antios.guard import main

            return main()
    from antios.scan_process import WORKER_FLAG, worker_main

    if len(args) == 3 and args[0] == WORKER_FLAG:
        return worker_main(*args[1:])
    from antios.guard import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run_entry())
