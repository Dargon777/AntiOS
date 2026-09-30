from __future__ import annotations

import argparse
import json
import os
import threading
import webbrowser
from pathlib import Path
from typing import Any

from .consumer import evaluate_health
from .core import scan
from .health import collect_health
from .registry import WindowsRegistryBackend, is_windows

PROJECT_URL = "https://github.com/Dargon777/AntiOS"
RELEASES_URL = PROJECT_URL + "/releases"
BUG_URL = PROJECT_URL + "/issues/new?template=bug_report.yml"
FEATURE_URL = PROJECT_URL + "/issues/new?template=feature_request.yml"
PRIVACY_URL = PROJECT_URL + "/blob/master/PRIVACY.md"
SUPPORT_URL = PROJECT_URL + "/blob/master/SUPPORT.md"


def _open_url(url: str) -> None:
    webbrowser.open(url, new=2)


def collect_dashboard_data() -> dict[str, Any]:
    if not is_windows():
        raise RuntimeError("AntiOS Dashboard currently requires Windows.")
    backend = WindowsRegistryBackend()
    scan_data = scan(backend)
    health_data = collect_health()
    evaluation = evaluate_health(scan_data, health_data)
    return {
        "scan": scan_data,
        "health": health_data,
        "evaluation": evaluation,
    }


def _format_bytes(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return "Unknown"
    gb = float(value) / (1024 ** 3)
    return f"{gb:.1f} GB"


def _open_settings(uri: str) -> None:
    if os.name != "nt":
        return
    os.startfile(uri)  # type: ignore[attr-defined]


class Dashboard:
    def __init__(self, root: Any) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.data: dict[str, Any] | None = None

        root.title("AntiOS — Windows Health & Privacy")
        root.geometry("940x660")
        root.minsize(820, 560)

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill="both", expand=True)

        top = ttk.Frame(outer)
        top.pack(fill="x")

        ttk.Label(
            top,
            text="AntiOS",
            font=("Segoe UI", 24, "bold"),
        ).pack(side="left")
        ttk.Label(
            top,
            text="Windows Health & Privacy",
            font=("Segoe UI", 12),
        ).pack(side="left", padx=(12, 0), pady=(8, 0))

        self.refresh_button = ttk.Button(top, text="Refresh", command=self.refresh)
        self.refresh_button.pack(side="right")

        self.status_title = ttk.Label(
            outer,
            text="Checking your PC…",
            font=("Segoe UI", 16, "bold"),
        )
        self.status_title.pack(anchor="w", pady=(18, 2))

        self.status_summary = ttk.Label(
            outer,
            text="AntiOS is collecting read-only system information.",
        )
        self.status_summary.pack(anchor="w", pady=(0, 14))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        self.overview = ttk.Frame(notebook, padding=10)
        self.security = ttk.Frame(notebook, padding=10)
        self.startup = ttk.Frame(notebook, padding=10)
        self.system = ttk.Frame(notebook, padding=10)

        notebook.add(self.overview, text="Overview")
        notebook.add(self.security, text="Security")
        notebook.add(self.startup, text="Startup")
        notebook.add(self.system, text="System")

        self.checks = ttk.Treeview(
            self.overview,
            columns=("status", "item", "detail"),
            show="headings",
            selectmode="browse",
        )
        self.checks.heading("status", text="Status")
        self.checks.heading("item", text="Check")
        self.checks.heading("detail", text="Details")
        self.checks.column("status", width=90, anchor="center", stretch=False)
        self.checks.column("item", width=170, stretch=False)
        self.checks.column("detail", width=560)
        self.checks.pack(fill="both", expand=True)

        self.security_text = tk.Text(
            self.security,
            wrap="word",
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.security_text.pack(fill="both", expand=True)
        self.security_text.configure(state="disabled")

        self.startup_tree = ttk.Treeview(
            self.startup,
            columns=("name", "location", "user"),
            show="headings",
        )
        self.startup_tree.heading("name", text="Application")
        self.startup_tree.heading("location", text="Location")
        self.startup_tree.heading("user", text="User")
        self.startup_tree.column("name", width=280)
        self.startup_tree.column("location", width=380)
        self.startup_tree.column("user", width=180)
        self.startup_tree.pack(fill="both", expand=True)

        self.system_text = tk.Text(
            self.system,
            wrap="word",
            relief="flat",
            font=("Segoe UI", 10),
        )
        self.system_text.pack(fill="both", expand=True)
        self.system_text.configure(state="disabled")

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(12, 0))

        ttk.Button(
            actions,
            text="Windows Security",
            command=lambda: _open_settings("windowsdefender:"),
        ).pack(side="left")
        ttk.Button(
            actions,
            text="Startup apps",
            command=lambda: _open_settings("ms-settings:startupapps"),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="Storage",
            command=lambda: _open_settings("ms-settings:storagesense"),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            actions,
            text="Export report…",
            command=self.export_report,
        ).pack(side="right")

        community = ttk.Frame(outer)
        community.pack(fill="x", pady=(10, 0))

        ttk.Button(
            community,
            text="Report a problem",
            command=lambda: _open_url(BUG_URL),
        ).pack(side="left")
        ttk.Button(
            community,
            text="Suggest a feature",
            command=lambda: _open_url(FEATURE_URL),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            community,
            text="GitHub / Star",
            command=lambda: _open_url(PROJECT_URL),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            community,
            text="Support development",
            command=lambda: _open_url(SUPPORT_URL),
        ).pack(side="left", padx=(8, 0))
        ttk.Button(
            community,
            text="Privacy",
            command=lambda: _open_url(PRIVACY_URL),
        ).pack(side="right")

        ttk.Label(
            outer,
            text=(
                "No telemetry: checks run locally. Dashboard checks are read-only. "
                "Advanced identity changes remain CLI-only and dry-run by default."
            ),
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(10, 0))

        self.refresh()

    def _set_text(self, widget: Any, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    def refresh(self) -> None:
        self.refresh_button.configure(state="disabled")
        self.status_title.configure(text="Checking your PC…")
        self.status_summary.configure(text="This usually takes a few seconds.")
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        try:
            data = collect_dashboard_data()
        except Exception as exc:
            self.root.after(0, lambda: self._show_error(str(exc)))
            return
        self.root.after(0, lambda: self._render(data))

    def _show_error(self, message: str) -> None:
        self.refresh_button.configure(state="normal")
        self.status_title.configure(text="AntiOS could not complete the check")
        self.status_summary.configure(text=message)

    def _render(self, data: dict[str, Any]) -> None:
        self.data = data
        self.refresh_button.configure(state="normal")

        evaluation = data["evaluation"]
        health = data["health"]
        scan_data = data["scan"]

        self.status_title.configure(text=evaluation.get("headline", "Check complete"))
        summary = evaluation.get("summary", {})
        self.status_summary.configure(
            text=(
                f"{summary.get('ok', 0)} OK  •  "
                f"{summary.get('advisory', 0)} to review  •  "
                f"{summary.get('warn', 0)} warning(s)"
            )
        )

        for item in self.checks.get_children():
            self.checks.delete(item)
        labels = {
            "ok": "OK",
            "advisory": "Review",
            "warn": "Warning",
            "info": "Info",
        }
        for check in evaluation.get("checks", []):
            self.checks.insert(
                "",
                "end",
                values=(
                    labels.get(check.get("level"), "Info"),
                    check.get("title", ""),
                    check.get("detail", ""),
                ),
            )

        security = scan_data.get("system", {}).get("security", {})
        defender = health.get("defender", {})
        bitlocker = health.get("bitlocker", {})
        sec_lines = [
            "Microsoft Defender",
            f"  Antivirus enabled: {defender.get('antivirus_enabled', 'Unknown')}",
            f"  Real-time protection: {defender.get('real_time_protection', 'Unknown')}",
            f"  Signature age: {defender.get('signature_age_days', 'Unknown')} day(s)",
            "",
            "Device encryption",
            f"  BitLocker protection: {bitlocker.get('protection_status', 'Unknown')}",
            f"  Encryption: {bitlocker.get('encryption_percentage', 'Unknown')}%",
            "",
            "Platform security",
            f"  Secure Boot: {security.get('secure_boot', {}).get('enabled', 'Unknown')}",
            f"  TPM present: {security.get('tpm', {}).get('present', 'Unknown')}",
            f"  TPM ready: {security.get('tpm', {}).get('ready', 'Unknown')}",
        ]
        self._set_text(self.security_text, "\n".join(sec_lines))

        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)
        for entry in health.get("startup", {}).get("entries", []):
            self.startup_tree.insert(
                "",
                "end",
                values=(
                    entry.get("name") or "(unnamed)",
                    entry.get("location") or "",
                    entry.get("user") or "",
                ),
            )

        system = scan_data.get("system", {})
        win = system.get("windows", {})
        host = system.get("host", {})
        storage = health.get("storage", {})
        uptime = health.get("uptime", {})
        reboot = health.get("pending_reboot", {})
        sys_lines = [
            "Windows",
            f"  Version: {win.get('generation') or 'Unknown'} {win.get('display_version') or ''}".rstrip(),
            f"  Build: {win.get('full_build') or 'Unknown'}",
            f"  Edition: {win.get('edition_id') or 'Unknown'}",
            "",
            "Computer",
            f"  Name: {host.get('computer_name') or 'Unknown'}",
            f"  Architecture: {host.get('architecture') or 'Unknown'}",
            f"  Processor: {host.get('processor') or 'Unknown'}",
            "",
            "Storage",
            f"  Free: {_format_bytes(storage.get('free_bytes'))}",
            f"  Total: {_format_bytes(storage.get('total_bytes'))}",
            f"  Free percentage: {storage.get('percent_free', 'Unknown')}%",
            "",
            "Session",
            f"  Uptime: {uptime.get('days', 'Unknown')} day(s)",
            f"  Restart pending: {reboot.get('pending', 'Unknown')}",
        ]
        self._set_text(self.system_text, "\n".join(sys_lines))

    def export_report(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.data:
            messagebox.showinfo("AntiOS", "Run a check before exporting a report.")
            return

        target = filedialog.asksaveasfilename(
            title="Export AntiOS report",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            initialfile="antios-report.json",
        )
        if not target:
            return

        Path(target).write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        messagebox.showinfo("AntiOS", f"Report saved to:\n{target}")


def launch() -> int:
    if not is_windows():
        raise RuntimeError("AntiOS Dashboard currently requires Windows.")

    import tkinter as tk

    root = tk.Tk()
    Dashboard(root)
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AntiOS Windows Health & Privacy Dashboard")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate dashboard imports without opening a window.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        return 0
    return launch()
