from __future__ import annotations

import argparse
import ctypes
import json
import os
import threading
import webbrowser
from pathlib import Path
from typing import Any, Callable

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

THEME = {
    "bg": "#090D14",
    "sidebar": "#0E1420",
    "surface": "#111925",
    "surface_alt": "#151F2D",
    "surface_hover": "#1B2737",
    "border": "#263347",
    "text": "#F2F5FA",
    "muted": "#8996A8",
    "muted_2": "#66758A",
    "accent": "#6EA8FE",
    "accent_hover": "#8AB9FF",
    "ok": "#59D499",
    "ok_bg": "#102A25",
    "review": "#F3C969",
    "review_bg": "#2C2513",
    "warn": "#FF7B82",
    "warn_bg": "#2E171D",
    "info": "#7CAEF8",
    "info_bg": "#132239",
}

STATUS_STYLE = {
    "ok": ("OK", THEME["ok"], THEME["ok_bg"]),
    "advisory": ("REVIEW", THEME["review"], THEME["review_bg"]),
    "warn": ("WARNING", THEME["warn"], THEME["warn_bg"]),
    "info": ("INFO", THEME["info"], THEME["info_bg"]),
}


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


def _friendly_bool(value: Any) -> str:
    if value is True:
        return "On"
    if value is False:
        return "Off"
    return "Unknown"


def _open_settings(uri: str) -> None:
    if os.name != "nt":
        return
    os.startfile(uri)  # type: ignore[attr-defined]


def _enable_dark_titlebar(root: Any) -> None:
    """Ask modern Windows to render a dark native title bar."""
    if os.name != "nt":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1)
        # DWMWA_USE_IMMERSIVE_DARK_MODE is 20 on modern Windows.
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            20,
            ctypes.byref(value),
            ctypes.sizeof(value),
        )
    except Exception:
        # Cosmetic only. The dashboard must still work if DWM rejects it.
        pass


class ScrollFrame:
    def __init__(self, parent: Any, tk: Any) -> None:
        self.tk = tk
        self.frame = tk.Frame(parent, bg=THEME["bg"])
        self.canvas = tk.Canvas(
            self.frame,
            bg=THEME["bg"],
            highlightthickness=0,
            bd=0,
        )
        self.scrollbar = tk.Scrollbar(
            self.frame,
            orient="vertical",
            command=self.canvas.yview,
            relief="flat",
            bd=0,
            width=10,
        )
        self.inner = tk.Frame(self.canvas, bg=THEME["bg"])
        self.window = self.canvas.create_window(
            (0, 0),
            window=self.inner,
            anchor="nw",
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.inner.bind(
            "<Configure>",
            lambda _event: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            ),
        )
        self.canvas.bind(
            "<Configure>",
            lambda event: self.canvas.itemconfigure(
                self.window,
                width=event.width,
            ),
        )

        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _bind_wheel(self, _event: Any) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_wheel(self, _event: Any) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event: Any) -> None:
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


class Dashboard:
    def __init__(self, root: Any) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.data: dict[str, Any] | None = None
        self.pages: dict[str, Any] = {}
        self.nav_buttons: dict[str, Any] = {}
        self.active_page = "overview"
        self._check_rows: list[Any] = []

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page("overview")
        self.refresh()

    def _configure_root(self) -> None:
        root = self.root
        root.title("AntiOS — Windows Health & Privacy")
        root.geometry("1120x760")
        root.minsize(920, 640)
        root.configure(bg=THEME["bg"])
        root.option_add("*Font", ("Segoe UI", 10))
        _enable_dark_titlebar(root)

    def _configure_ttk(self) -> None:
        style = self.ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "AntiOS.Treeview",
            background=THEME["surface"],
            fieldbackground=THEME["surface"],
            foreground=THEME["text"],
            borderwidth=0,
            relief="flat",
            rowheight=36,
            font=("Segoe UI", 10),
        )
        style.map(
            "AntiOS.Treeview",
            background=[("selected", THEME["surface_hover"])],
            foreground=[("selected", THEME["text"])],
        )
        style.configure(
            "AntiOS.Treeview.Heading",
            background=THEME["surface_alt"],
            foreground=THEME["muted"],
            borderwidth=0,
            relief="flat",
            padding=(10, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "AntiOS.Treeview.Heading",
            background=[("active", THEME["surface_hover"])],
        )

    def _build_shell(self) -> None:
        tk = self.tk

        self.sidebar = tk.Frame(
            self.root,
            bg=THEME["sidebar"],
            width=220,
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        brand.pack(fill="x", padx=22, pady=(24, 26))

        mark = tk.Label(
            brand,
            text="A",
            width=3,
            height=1,
            bg=THEME["accent"],
            fg="#08111F",
            font=("Segoe UI", 14, "bold"),
            bd=0,
        )
        mark.pack(side="left")

        brand_text = tk.Frame(brand, bg=THEME["sidebar"])
        brand_text.pack(side="left", padx=(11, 0))

        tk.Label(
            brand_text,
            text="AntiOS",
            bg=THEME["sidebar"],
            fg=THEME["text"],
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text="Health & Privacy",
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        tk.Label(
            self.sidebar,
            text="DASHBOARD",
            bg=THEME["sidebar"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", padx=22, pady=(0, 8))

        for key, label in [
            ("overview", "Overview"),
            ("security", "Security"),
            ("startup", "Startup apps"),
            ("system", "System"),
        ]:
            self._create_nav_button(key, label)

        spacer = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        spacer.pack(fill="both", expand=True)

        trust = tk.Frame(
            self.sidebar,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        trust.pack(fill="x", padx=14, pady=(0, 14))

        tk.Label(
            trust,
            text="●  LOCAL MODE",
            bg=THEME["surface"],
            fg=THEME["ok"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", padx=12, pady=(11, 4))
        tk.Label(
            trust,
            text="No automatic telemetry\nDashboard is read-only",
            justify="left",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 11))

        sidebar_links = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        sidebar_links.pack(fill="x", padx=14, pady=(0, 16))

        self._text_link(
            sidebar_links,
            "GitHub",
            lambda: _open_url(PROJECT_URL),
        ).pack(side="left")
        self._text_link(
            sidebar_links,
            "Privacy",
            lambda: _open_url(PRIVACY_URL),
        ).pack(side="right")

        self.content = tk.Frame(self.root, bg=THEME["bg"])
        self.content.pack(side="left", fill="both", expand=True)

        self.header = tk.Frame(self.content, bg=THEME["bg"])
        self.header.pack(fill="x", padx=30, pady=(24, 18))

        title_block = tk.Frame(self.header, bg=THEME["bg"])
        title_block.pack(side="left")

        self.page_title = tk.Label(
            title_block,
            text="Overview",
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI", 22, "bold"),
        )
        self.page_title.pack(anchor="w")

        self.page_subtitle = tk.Label(
            title_block,
            text="A quick read-only look at your Windows PC.",
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        )
        self.page_subtitle.pack(anchor="w", pady=(3, 0))

        header_actions = tk.Frame(self.header, bg=THEME["bg"])
        header_actions.pack(side="right")

        self.export_button = self._button(
            header_actions,
            "Export report",
            self.export_report,
            kind="secondary",
        )
        self.export_button.pack(side="left", padx=(0, 10))

        self.refresh_button = self._button(
            header_actions,
            "Refresh",
            self.refresh,
            kind="primary",
        )
        self.refresh_button.pack(side="left")

        self.page_host = tk.Frame(self.content, bg=THEME["bg"])
        self.page_host.pack(
            fill="both",
            expand=True,
            padx=30,
            pady=(0, 22),
        )

    def _build_pages(self) -> None:
        for name in ("overview", "security", "startup", "system"):
            frame = self.tk.Frame(self.page_host, bg=THEME["bg"])
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = frame

        self._build_overview(self.pages["overview"])
        self._build_security(self.pages["security"])
        self._build_startup(self.pages["startup"])
        self._build_system(self.pages["system"])

    def _build_overview(self, parent: Any) -> None:
        tk = self.tk

        self.hero = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.hero.pack(fill="x")

        hero_left = tk.Frame(self.hero, bg=THEME["surface"])
        hero_left.pack(side="left", fill="both", expand=True, padx=24, pady=22)

        self.hero_kicker = tk.Label(
            hero_left,
            text="CHECKING",
            bg=THEME["surface"],
            fg=THEME["accent"],
            font=("Segoe UI Semibold", 9),
        )
        self.hero_kicker.pack(anchor="w")

        self.status_title = tk.Label(
            hero_left,
            text="Checking your PC…",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 20, "bold"),
        )
        self.status_title.pack(anchor="w", pady=(5, 5))

        self.status_summary = tk.Label(
            hero_left,
            text="AntiOS is collecting read-only system information.",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        )
        self.status_summary.pack(anchor="w")

        hero_right = tk.Frame(self.hero, bg=THEME["surface"])
        hero_right.pack(side="right", padx=24, pady=22)

        self.summary_chips: dict[str, Any] = {}
        for key, label, fg, bg in [
            ("ok", "OK", THEME["ok"], THEME["ok_bg"]),
            ("advisory", "REVIEW", THEME["review"], THEME["review_bg"]),
            ("warn", "WARN", THEME["warn"], THEME["warn_bg"]),
        ]:
            chip = tk.Frame(hero_right, bg=bg)
            chip.pack(side="left", padx=(8, 0))
            value = tk.Label(
                chip,
                text="0",
                bg=bg,
                fg=fg,
                font=("Segoe UI", 15, "bold"),
            )
            value.pack(padx=14, pady=(8, 0))
            tk.Label(
                chip,
                text=label,
                bg=bg,
                fg=fg,
                font=("Segoe UI Semibold", 8),
            ).pack(padx=14, pady=(0, 8))
            self.summary_chips[key] = value

        section = tk.Frame(parent, bg=THEME["bg"])
        section.pack(fill="x", pady=(22, 10))

        tk.Label(
            section,
            text="Checks",
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(side="left")

        tk.Label(
            section,
            text="Why each result was produced",
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(10, 0), pady=(2, 0))

        self.check_scroll = ScrollFrame(parent, tk)
        self.check_scroll.frame.pack(fill="both", expand=True)

    def _build_security(self, parent: Any) -> None:
        self.security_grid = self.tk.Frame(parent, bg=THEME["bg"])
        self.security_grid.pack(fill="both", expand=True)

        for col in range(2):
            self.security_grid.grid_columnconfigure(col, weight=1, uniform="security")

        self.security_cards: dict[str, dict[str, Any]] = {}
        specs = [
            ("defender", "Microsoft Defender", "Built-in antivirus protection", 0, 0),
            ("encryption", "Device encryption", "BitLocker protection status", 0, 1),
            ("secure_boot", "Secure Boot", "Boot-chain protection", 1, 0),
            ("tpm", "TPM", "Hardware-backed security", 1, 1),
        ]
        for key, title, subtitle, row, col in specs:
            card = self._metric_card(
                self.security_grid,
                title,
                subtitle,
            )
            card["frame"].grid(
                row=row,
                column=col,
                sticky="nsew",
                padx=(0 if col == 0 else 8, 8 if col == 0 else 0),
                pady=(0 if row == 0 else 8, 8 if row == 0 else 0),
            )
            self.security_grid.grid_rowconfigure(row, weight=1)
            self.security_cards[key] = card

        actions = self.tk.Frame(parent, bg=THEME["bg"])
        actions.pack(fill="x", pady=(18, 0))
        self._button(
            actions,
            "Open Windows Security",
            lambda: _open_settings("windowsdefender:"),
            kind="primary",
        ).pack(side="left")

    def _build_startup(self, parent: Any) -> None:
        tk = self.tk

        summary = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        summary.pack(fill="x", pady=(0, 14))

        left = tk.Frame(summary, bg=THEME["surface"])
        left.pack(side="left", padx=18, pady=15)

        self.startup_count = tk.Label(
            left,
            text="—",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 20, "bold"),
        )
        self.startup_count.pack(side="left")

        tk.Label(
            left,
            text=" startup entries detected",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        ).pack(side="left", pady=(5, 0))

        self._button(
            summary,
            "Open Startup Apps",
            lambda: _open_settings("ms-settings:startupapps"),
            kind="secondary",
        ).pack(side="right", padx=14, pady=12)

        table = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        table.pack(fill="both", expand=True)

        self.startup_tree = self.ttk.Treeview(
            table,
            columns=("name", "location", "user"),
            show="headings",
            style="AntiOS.Treeview",
        )
        self.startup_tree.heading("name", text="APPLICATION")
        self.startup_tree.heading("location", text="LOCATION")
        self.startup_tree.heading("user", text="USER")
        self.startup_tree.column("name", width=280)
        self.startup_tree.column("location", width=360)
        self.startup_tree.column("user", width=170)

        scrollbar = tk.Scrollbar(
            table,
            orient="vertical",
            command=self.startup_tree.yview,
            width=10,
            bd=0,
            relief="flat",
        )
        self.startup_tree.configure(yscrollcommand=scrollbar.set)

        self.startup_tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scrollbar.pack(side="right", fill="y")

    def _build_system(self, parent: Any) -> None:
        tk = self.tk

        self.system_grid = tk.Frame(parent, bg=THEME["bg"])
        self.system_grid.pack(fill="both", expand=True)

        for col in range(2):
            self.system_grid.grid_columnconfigure(col, weight=1, uniform="system")

        self.system_cards: dict[str, dict[str, Any]] = {}
        specs = [
            ("windows", "Windows", "Operating system", 0, 0),
            ("computer", "Computer", "Hardware overview", 0, 1),
            ("storage", "Storage", "System drive", 1, 0),
            ("session", "Session", "Current Windows session", 1, 1),
        ]
        for key, title, subtitle, row, col in specs:
            card = self._metric_card(
                self.system_grid,
                title,
                subtitle,
                multiline=True,
            )
            card["frame"].grid(
                row=row,
                column=col,
                sticky="nsew",
                padx=(0 if col == 0 else 8, 8 if col == 0 else 0),
                pady=(0 if row == 0 else 8, 8 if row == 0 else 0),
            )
            self.system_grid.grid_rowconfigure(row, weight=1)
            self.system_cards[key] = card

        actions = tk.Frame(parent, bg=THEME["bg"])
        actions.pack(fill="x", pady=(18, 0))

        self._button(
            actions,
            "Storage settings",
            lambda: _open_settings("ms-settings:storagesense"),
            kind="secondary",
        ).pack(side="left")

    def _create_nav_button(self, key: str, text: str) -> None:
        button = self.tk.Button(
            self.sidebar,
            text=text,
            command=lambda: self.show_page(key),
            anchor="w",
            padx=22,
            pady=11,
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            activebackground=THEME["surface_hover"],
            activeforeground=THEME["text"],
            bd=0,
            relief="flat",
            cursor="hand2",
            font=("Segoe UI Semibold", 10),
        )
        button.pack(fill="x", padx=8, pady=1)
        self.nav_buttons[key] = button

    def _button(
        self,
        parent: Any,
        text: str,
        command: Callable[[], Any],
        *,
        kind: str = "secondary",
    ) -> Any:
        if kind == "primary":
            bg = THEME["accent"]
            fg = "#08111F"
            active_bg = THEME["accent_hover"]
        else:
            bg = THEME["surface_alt"]
            fg = THEME["text"]
            active_bg = THEME["surface_hover"]

        return self.tk.Button(
            parent,
            text=text,
            command=command,
            padx=15,
            pady=8,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            bd=0,
            relief="flat",
            cursor="hand2",
            font=("Segoe UI Semibold", 9),
        )

    def _text_link(
        self,
        parent: Any,
        text: str,
        command: Callable[[], Any],
    ) -> Any:
        return self.tk.Button(
            parent,
            text=text,
            command=command,
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            activebackground=THEME["sidebar"],
            activeforeground=THEME["text"],
            bd=0,
            relief="flat",
            cursor="hand2",
            font=("Segoe UI", 8),
        )

    def _metric_card(
        self,
        parent: Any,
        title: str,
        subtitle: str,
        *,
        multiline: bool = False,
    ) -> dict[str, Any]:
        tk = self.tk

        frame = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )

        header = tk.Frame(frame, bg=THEME["surface"])
        header.pack(fill="x", padx=20, pady=(18, 8))

        tk.Label(
            header,
            text=title,
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w")

        tk.Label(
            header,
            text=subtitle,
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(2, 0))

        value = tk.Label(
            frame,
            text="Checking…",
            justify="left",
            anchor="nw",
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 15 if not multiline else 11, "bold" if not multiline else "normal"),
        )
        value.pack(fill="both", expand=True, padx=20, pady=(8, 6))

        detail = tk.Label(
            frame,
            text="",
            justify="left",
            anchor="nw",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            wraplength=360,
        )
        detail.pack(fill="x", padx=20, pady=(0, 18))

        return {
            "frame": frame,
            "value": value,
            "detail": detail,
        }

    def _status_card(
        self,
        parent: Any,
        check: dict[str, Any],
    ) -> Any:
        tk = self.tk
        level = str(check.get("level") or "info")
        label, color, badge_bg = STATUS_STYLE.get(
            level,
            STATUS_STYLE["info"],
        )

        card = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )

        stripe = tk.Frame(card, bg=color, width=4)
        stripe.pack(side="left", fill="y")
        stripe.pack_propagate(False)

        body = tk.Frame(card, bg=THEME["surface"])
        body.pack(side="left", fill="both", expand=True, padx=16, pady=14)

        top = tk.Frame(body, bg=THEME["surface"])
        top.pack(fill="x")

        badge = tk.Label(
            top,
            text=label,
            bg=badge_bg,
            fg=color,
            padx=8,
            pady=3,
            font=("Segoe UI Semibold", 8),
        )
        badge.pack(side="left")

        tk.Label(
            top,
            text=str(check.get("title") or "Check"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left", padx=(10, 0))

        detail = tk.Label(
            body,
            text=str(check.get("detail") or ""),
            justify="left",
            anchor="w",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            wraplength=650,
        )
        detail.pack(fill="x", pady=(9, 0))

        action = check.get("action")
        if action:
            tk.Label(
                body,
                text=str(action),
                justify="left",
                anchor="w",
                bg=THEME["surface"],
                fg=THEME["muted_2"],
                font=("Segoe UI", 9),
                wraplength=650,
            ).pack(fill="x", pady=(5, 0))

        uri = check.get("settings_uri")
        if uri:
            self._button(
                card,
                "Open",
                lambda u=str(uri): _open_settings(u),
                kind="secondary",
            ).pack(side="right", padx=14, pady=14)

        return card

    def show_page(self, name: str) -> None:
        if name not in self.pages:
            return

        titles = {
            "overview": ("Overview", "A quick read-only look at your Windows PC."),
            "security": ("Security", "Protection features reported by Windows."),
            "startup": ("Startup apps", "Common applications configured to start with Windows."),
            "system": ("System", "Windows, hardware and session information."),
        }

        self.active_page = name
        self.pages[name].tkraise()

        title, subtitle = titles[name]
        self.page_title.configure(text=title)
        self.page_subtitle.configure(text=subtitle)

        for key, button in self.nav_buttons.items():
            selected = key == name
            button.configure(
                bg=THEME["surface_alt"] if selected else THEME["sidebar"],
                fg=THEME["text"] if selected else THEME["muted"],
            )

    def refresh(self) -> None:
        self.refresh_button.configure(
            state="disabled",
            text="Checking…",
        )
        self.hero_kicker.configure(text="CHECKING", fg=THEME["accent"])
        self.status_title.configure(text="Checking your PC…")
        self.status_summary.configure(
            text="AntiOS is collecting read-only system information."
        )
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        try:
            data = collect_dashboard_data()
        except Exception as exc:
            self.root.after(0, lambda: self._show_error(str(exc)))
            return
        self.root.after(0, lambda: self._render(data))

    def _show_error(self, message: str) -> None:
        self.refresh_button.configure(state="normal", text="Refresh")
        self.hero_kicker.configure(text="CHECK FAILED", fg=THEME["warn"])
        self.status_title.configure(text="AntiOS could not complete the check")
        self.status_summary.configure(text=message)

    def _render(self, data: dict[str, Any]) -> None:
        self.data = data
        self.refresh_button.configure(state="normal", text="Refresh")

        evaluation = data["evaluation"]
        health = data["health"]
        scan_data = data["scan"]

        overall = evaluation.get("overall")
        if overall == "needs-attention":
            kicker = ("NEEDS ATTENTION", THEME["warn"])
        elif overall == "review":
            kicker = ("REVIEW", THEME["review"])
        else:
            kicker = ("ALL CLEAR", THEME["ok"])

        self.hero_kicker.configure(text=kicker[0], fg=kicker[1])
        self.status_title.configure(
            text=evaluation.get("headline", "Check complete")
        )

        summary = evaluation.get("summary", {})
        self.status_summary.configure(
            text=(
                "Read-only check completed. "
                f"{summary.get('info', 0)} informational item(s)."
            )
        )
        for key, widget in self.summary_chips.items():
            widget.configure(text=str(summary.get(key, 0)))

        for row in self._check_rows:
            row.destroy()
        self._check_rows.clear()

        for check in evaluation.get("checks", []):
            card = self._status_card(self.check_scroll.inner, check)
            card.pack(fill="x", pady=(0, 10))
            self._check_rows.append(card)

        self._render_security(scan_data, health)
        self._render_startup(health)
        self._render_system(scan_data, health)

    def _render_security(
        self,
        scan_data: dict[str, Any],
        health: dict[str, Any],
    ) -> None:
        security = scan_data.get("system", {}).get("security", {})
        defender = health.get("defender", {})
        bitlocker = health.get("bitlocker", {})

        defender_enabled = defender.get("antivirus_enabled")
        realtime = defender.get("real_time_protection")
        defender_value = (
            "Protected"
            if defender_enabled is True and realtime is True
            else "Needs review"
            if defender.get("available")
            else "Unavailable"
        )
        defender_detail = (
            f"Antivirus: {_friendly_bool(defender_enabled)}   •   "
            f"Real-time: {_friendly_bool(realtime)}   •   "
            f"Signatures: {defender.get('signature_age_days', 'Unknown')} day(s) old"
        )

        self.security_cards["defender"]["value"].configure(
            text=defender_value,
            fg=THEME["ok"] if defender_value == "Protected" else THEME["review"],
        )
        self.security_cards["defender"]["detail"].configure(text=defender_detail)

        protection = bitlocker.get("protection_status")
        encryption = bitlocker.get("encryption_percentage")
        self.security_cards["encryption"]["value"].configure(
            text=str(protection or "Unavailable"),
            fg=THEME["ok"] if str(protection).lower() == "on" else THEME["review"],
        )
        self.security_cards["encryption"]["detail"].configure(
            text=f"Encryption: {encryption if encryption is not None else 'Unknown'}%"
        )

        secure_boot = security.get("secure_boot", {}).get("enabled")
        self.security_cards["secure_boot"]["value"].configure(
            text=_friendly_bool(secure_boot),
            fg=THEME["ok"] if secure_boot is True else THEME["review"],
        )
        self.security_cards["secure_boot"]["detail"].configure(
            text="Secure Boot helps protect the Windows boot chain."
        )

        tpm = security.get("tpm", {})
        tpm_ready = tpm.get("ready")
        tpm_present = tpm.get("present")
        tpm_value = (
            "Ready"
            if tpm_present is True and tpm_ready is True
            else "Present, not ready"
            if tpm_present is True
            else "Not detected"
            if tpm_present is False
            else "Unknown"
        )
        self.security_cards["tpm"]["value"].configure(
            text=tpm_value,
            fg=THEME["ok"] if tpm_value == "Ready" else THEME["review"],
        )
        self.security_cards["tpm"]["detail"].configure(
            text="Trusted Platform Module state reported by Windows."
        )

    def _render_startup(self, health: dict[str, Any]) -> None:
        startup = health.get("startup", {})
        count = startup.get("count")
        self.startup_count.configure(
            text=str(count) if isinstance(count, int) else "—"
        )

        for item in self.startup_tree.get_children():
            self.startup_tree.delete(item)

        for index, entry in enumerate(startup.get("entries", [])):
            tag = "even" if index % 2 == 0 else "odd"
            self.startup_tree.insert(
                "",
                "end",
                values=(
                    entry.get("name") or "(unnamed)",
                    entry.get("location") or "",
                    entry.get("user") or "",
                ),
                tags=(tag,),
            )

        self.startup_tree.tag_configure("even", background=THEME["surface"])
        self.startup_tree.tag_configure("odd", background=THEME["surface_alt"])

    def _render_system(
        self,
        scan_data: dict[str, Any],
        health: dict[str, Any],
    ) -> None:
        system = scan_data.get("system", {})
        win = system.get("windows", {})
        host = system.get("host", {})
        storage = health.get("storage", {})
        uptime = health.get("uptime", {})
        reboot = health.get("pending_reboot", {})

        self.system_cards["windows"]["value"].configure(
            text=(
                f"{win.get('generation') or 'Windows'}\n"
                f"{win.get('edition_id') or 'Edition unknown'}\n"
                f"Version {win.get('display_version') or 'Unknown'}\n"
                f"Build {win.get('full_build') or 'Unknown'}"
            )
        )
        self.system_cards["windows"]["detail"].configure(
            text="Windows version information read from the local system."
        )

        self.system_cards["computer"]["value"].configure(
            text=(
                f"{host.get('computer_name') or 'Unknown computer'}\n"
                f"{host.get('architecture') or 'Unknown architecture'}\n"
                f"{host.get('processor') or 'Processor unavailable'}"
            )
        )
        self.system_cards["computer"]["detail"].configure(
            text="Local computer identity and hardware overview."
        )

        free = _format_bytes(storage.get("free_bytes"))
        total = _format_bytes(storage.get("total_bytes"))
        percent = storage.get("percent_free")
        self.system_cards["storage"]["value"].configure(
            text=(
                f"{free} free\n"
                f"{total} total\n"
                f"{percent if percent is not None else 'Unknown'}% available"
            )
        )
        self.system_cards["storage"]["detail"].configure(
            text="System-drive capacity reported by Windows."
        )

        self.system_cards["session"]["value"].configure(
            text=(
                f"Uptime: {uptime.get('days', 'Unknown')} day(s)\n"
                f"Restart pending: {_friendly_bool(reboot.get('pending'))}"
            )
        )
        self.system_cards["session"]["detail"].configure(
            text="Current Windows session and common restart markers."
        )

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

    if os.name == "nt":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    Dashboard(root)
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="AntiOS Windows Health & Privacy Dashboard"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate dashboard imports without opening a window.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        # Also validates that the theme/status structures are importable.
        assert "bg" in THEME and "ok" in STATUS_STYLE
        return 0
    return launch()
