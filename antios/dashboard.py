from __future__ import annotations

import argparse
import ctypes
import json
import os
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .consumer import evaluate_health
from .core import scan
from .health import collect_health
from .i18n import LANGUAGE_NAMES, Translator, detect_language, normalize_language
from .registry import WindowsRegistryBackend, is_windows
from .storage_cleanup import (
    DEFAULT_OLD_DAYS,
    default_scan_path,
    format_bytes,
    scan_storage,
)

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


def collect_dashboard_data(language: str = "en") -> dict[str, Any]:
    tr = Translator(language)
    if not is_windows():
        raise RuntimeError(tr.t("error.dashboard_windows"))
    backend = WindowsRegistryBackend()
    scan_data = scan(backend)
    health_data = collect_health()
    evaluation = evaluate_health(
        scan_data,
        health_data,
        language=language,
    )
    return {
        "scan": scan_data,
        "health": health_data,
        "evaluation": evaluation,
    }


def _format_bytes(value: Any, tr: Translator | None = None) -> str:
    if not isinstance(value, (int, float)):
        return (tr or Translator("en")).t("value.unknown")
    gb = float(value) / (1024 ** 3)
    return f"{gb:.1f} GB"


def _friendly_bool(value: Any, tr: Translator | None = None) -> str:
    translator = tr or Translator("en")
    if value is True:
        return translator.t("value.on")
    if value is False:
        return translator.t("value.off")
    return translator.t("value.unknown")


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
    def __init__(
        self,
        root: Any,
        *,
        language: str | None = None,
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.language = normalize_language(language or detect_language())
        self.tr = Translator(self.language)
        self.data: dict[str, Any] | None = None
        self.pages: dict[str, Any] = {}
        self.nav_buttons: dict[str, Any] = {}
        self.active_page = "overview"
        self._check_rows: list[Any] = []
        self.storage_path = default_scan_path()
        self.storage_result: dict[str, Any] | None = None
        self._storage_cancel = threading.Event()

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page("overview")
        self.refresh()

    def t(self, key: str, **values: Any) -> str:
        return self.tr.t(key, **values)

    def _configure_root(self) -> None:
        root = self.root
        root.title(self.t("app.title"))
        root.geometry("1180x780")
        root.minsize(960, 650)
        root.configure(bg=THEME["bg"])
        root.option_add("*Font", ("Segoe UI", 10))
        root.bind("<F5>", lambda _event: self.refresh())
        root.bind("<Control-e>", lambda _event: self.export_report())
        root.bind("<Control-E>", lambda _event: self.export_report())
        root.bind("<Control-1>", lambda _event: self.show_page("overview"))
        root.bind("<Control-2>", lambda _event: self.show_page("security"))
        root.bind("<Control-3>", lambda _event: self.show_page("startup"))
        root.bind("<Control-4>", lambda _event: self.show_page("system"))
        root.bind("<Control-5>", lambda _event: self.show_page("cleanup"))
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
            width=236,
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
            text=self.t("brand.subtitle"),
            bg=THEME["sidebar"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text=f"v{__version__}  •  alpha",
            bg=THEME["sidebar"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(2, 0))

        tk.Label(
            self.sidebar,
            text=self.t("sidebar.dashboard"),
            bg=THEME["sidebar"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", padx=22, pady=(0, 8))

        for key, label in [
            ("overview", self.t("nav.overview")),
            ("security", self.t("nav.security")),
            ("startup", self.t("nav.startup")),
            ("system", self.t("nav.system")),
            ("cleanup", self.t("nav.cleanup")),
        ]:
            self._create_nav_button(key, label)

        language_box = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        language_box.pack(fill="x", padx=14, pady=(18, 8))

        tk.Label(
            language_box,
            text=self.t("language.label"),
            bg=THEME["sidebar"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", padx=8, pady=(0, 6))

        self.language_display_to_code = {
            label: code for code, label in LANGUAGE_NAMES.items()
        }
        self.language_var = tk.StringVar(
            value=LANGUAGE_NAMES[self.language]
        )
        self.language_combo = self.ttk.Combobox(
            language_box,
            textvariable=self.language_var,
            values=list(self.language_display_to_code),
            state="readonly",
            width=18,
        )
        self.language_combo.pack(fill="x", padx=8)
        self.language_combo.bind(
            "<<ComboboxSelected>>",
            self._on_language_selected,
        )

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
            text=self.t("sidebar.local_mode"),
            bg=THEME["surface"],
            fg=THEME["ok"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", padx=12, pady=(11, 4))
        tk.Label(
            trust,
            text=self.t("sidebar.no_telemetry"),
            justify="left",
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 7))
        tk.Label(
            trust,
            text="F5  •  Ctrl+E  •  Ctrl+1…5",
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=12, pady=(0, 11))

        sidebar_links = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        sidebar_links.pack(fill="x", padx=14, pady=(0, 16))

        self._text_link(
            sidebar_links,
            self.t("sidebar.github"),
            lambda: _open_url(PROJECT_URL),
        ).pack(side="left")
        self._text_link(
            sidebar_links,
            self.t("sidebar.privacy"),
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
            text=self.t("nav.overview"),
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI", 22, "bold"),
        )
        self.page_title.pack(anchor="w")

        self.page_subtitle = tk.Label(
            title_block,
            text=self.t("page.overview.subtitle"),
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        )
        self.page_subtitle.pack(anchor="w", pady=(3, 0))

        header_actions = tk.Frame(self.header, bg=THEME["bg"])
        header_actions.pack(side="right")

        self.export_button = self._button(
            header_actions,
            f"↓  {self.t('button.export')}",
            self.export_report,
            kind="secondary",
        )
        self.export_button.pack(side="left", padx=(0, 10))

        self.refresh_button = self._button(
            header_actions,
            f"↻  {self.t('button.refresh')}",
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
        for name in ("overview", "security", "startup", "system", "cleanup"):
            frame = self.tk.Frame(self.page_host, bg=THEME["bg"])
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = frame

        self._build_overview(self.pages["overview"])
        self._build_security(self.pages["security"])
        self._build_startup(self.pages["startup"])
        self._build_system(self.pages["system"])
        self._build_cleanup(self.pages["cleanup"])

    def _build_overview(self, parent: Any) -> None:
        tk = self.tk

        self.hero = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        self.hero.pack(fill="x", pady=(0, 14))

        hero_left = tk.Frame(self.hero, bg=THEME["surface"])
        hero_left.pack(side="left", fill="both", expand=True, padx=24, pady=22)

        self.hero_kicker = tk.Label(
            hero_left,
            text=self.t("overview.checking_kicker"),
            bg=THEME["surface"],
            fg=THEME["accent"],
            font=("Segoe UI Semibold", 9),
        )
        self.hero_kicker.pack(anchor="w")

        self.status_title = tk.Label(
            hero_left,
            text=self.t("overview.checking_title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 20, "bold"),
        )
        self.status_title.pack(anchor="w", pady=(5, 5))

        self.status_summary = tk.Label(
            hero_left,
            text=self.t("overview.checking_detail"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        )
        self.status_summary.pack(anchor="w")

        hero_right = tk.Frame(self.hero, bg=THEME["surface"])
        hero_right.pack(side="right", padx=24, pady=22)

        self.summary_chips: dict[str, Any] = {}
        for key, label, fg, bg in [
            ("ok", self.t("summary.ok"), THEME["ok"], THEME["ok_bg"]),
            ("advisory", self.t("summary.review"), THEME["review"], THEME["review_bg"]),
            ("warn", self.t("summary.warn"), THEME["warn"], THEME["warn_bg"]),
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

        quick_actions = tk.Frame(parent, bg=THEME["bg"])
        quick_actions.pack(fill="x", pady=(0, 18))

        self._button(
            quick_actions,
            self.t("button.windows_security"),
            lambda: _open_settings("windowsdefender:"),
            kind="secondary",
        ).pack(side="left")
        self._button(
            quick_actions,
            self.t("button.startup_apps"),
            lambda: _open_settings("ms-settings:startupapps"),
            kind="secondary",
        ).pack(side="left", padx=(8, 0))
        self._button(
            quick_actions,
            self.t("button.storage_settings"),
            lambda: _open_settings("ms-settings:storagesense"),
            kind="secondary",
        ).pack(side="left", padx=(8, 0))

        section = tk.Frame(parent, bg=THEME["bg"])
        section.pack(fill="x", pady=(0, 10))

        tk.Label(
            section,
            text=self.t("overview.checks"),
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(side="left")

        tk.Label(
            section,
            text=self.t("overview.why"),
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
            ("defender", self.t("security.defender.title"), self.t("security.defender.subtitle"), 0, 0),
            ("encryption", self.t("security.encryption.title"), self.t("security.encryption.subtitle"), 0, 1),
            ("secure_boot", self.t("security.secure_boot.title"), self.t("security.secure_boot.subtitle"), 1, 0),
            ("tpm", self.t("security.tpm.title"), self.t("security.tpm.subtitle"), 1, 1),
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
            self.t("button.windows_security"),
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
            text=self.t("startup.entries"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 10),
        ).pack(side="left", pady=(5, 0))

        self._button(
            summary,
            self.t("button.startup_apps"),
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
        self.startup_tree.heading("name", text=self.t("startup.application"))
        self.startup_tree.heading("location", text=self.t("startup.location"))
        self.startup_tree.heading("user", text=self.t("startup.user"))
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
            ("windows", self.t("system.windows.title"), self.t("system.windows.subtitle"), 0, 0),
            ("computer", self.t("system.computer.title"), self.t("system.computer.subtitle"), 0, 1),
            ("storage", self.t("system.storage.title"), self.t("system.storage.subtitle"), 1, 0),
            ("session", self.t("system.session.title"), self.t("system.session.subtitle"), 1, 1),
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
            self.t("button.storage_settings"),
            lambda: _open_settings("ms-settings:storagesense"),
            kind="secondary",
        ).pack(side="left")

    def _build_cleanup(self, parent: Any) -> None:
        tk = self.tk

        controls = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        controls.pack(fill="x", pady=(0, 14))

        left = tk.Frame(controls, bg=THEME["surface"])
        left.pack(side="left", fill="x", expand=True, padx=18, pady=14)

        tk.Label(
            left,
            text=self.t("cleanup.path"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")

        self.cleanup_path_label = tk.Label(
            left,
            text=str(self.storage_path),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 10),
            anchor="w",
        )
        self.cleanup_path_label.pack(fill="x", pady=(4, 0))

        buttons = tk.Frame(controls, bg=THEME["surface"])
        buttons.pack(side="right", padx=14, pady=12)

        self.cleanup_choose_button = self._button(
            buttons,
            self.t("cleanup.choose"),
            self._choose_cleanup_folder,
            kind="secondary",
        )
        self.cleanup_choose_button.pack(side="left")

        self.cleanup_scan_button = self._button(
            buttons,
            self.t("cleanup.scan"),
            self._start_cleanup_scan,
            kind="primary",
        )
        self.cleanup_scan_button.pack(side="left", padx=(8, 0))

        self.cleanup_cancel_button = self._button(
            buttons,
            self.t("cleanup.cancel"),
            self._cancel_cleanup_scan,
            kind="secondary",
        )
        self.cleanup_cancel_button.configure(state="disabled")
        self.cleanup_cancel_button.pack(side="left", padx=(8, 0))

        self.cleanup_status = tk.Label(
            parent,
            text=self.t("cleanup.status.ready"),
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.cleanup_status.pack(fill="x", pady=(0, 10))

        summary = tk.Frame(parent, bg=THEME["bg"])
        summary.pack(fill="x", pady=(0, 14))
        for column in range(5):
            summary.grid_columnconfigure(column, weight=1, uniform="cleanup")

        self.cleanup_summary: dict[str, Any] = {}
        summary_specs = [
            ("duplicate_groups", self.t("cleanup.summary.duplicates")),
            ("duplicate_reclaimable_bytes", self.t("cleanup.summary.reclaimable")),
            ("old_large_files", self.t("cleanup.summary.old")),
            ("installer_archives", self.t("cleanup.summary.archives")),
            ("empty_files", self.t("cleanup.summary.empty")),
        ]
        for column, (key, title) in enumerate(summary_specs):
            card = tk.Frame(
                summary,
                bg=THEME["surface"],
                highlightthickness=1,
                highlightbackground=THEME["border"],
            )
            card.grid(
                row=0,
                column=column,
                sticky="nsew",
                padx=(0 if column == 0 else 4, 0 if column == 4 else 4),
            )
            value = tk.Label(
                card,
                text="—",
                bg=THEME["surface"],
                fg=THEME["text"],
                font=("Segoe UI", 15, "bold"),
            )
            value.pack(anchor="w", padx=13, pady=(11, 2))
            tk.Label(
                card,
                text=title,
                bg=THEME["surface"],
                fg=THEME["muted"],
                font=("Segoe UI", 8),
                wraplength=150,
                justify="left",
            ).pack(anchor="w", padx=13, pady=(0, 11))
            self.cleanup_summary[key] = value

        tk.Label(
            parent,
            text=self.t("cleanup.note", days=DEFAULT_OLD_DAYS),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=850,
        ).pack(fill="x", pady=(0, 10))

        table = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        table.pack(fill="both", expand=True)

        self.cleanup_tree = self.ttk.Treeview(
            table,
            columns=("type", "size", "modified", "path"),
            show="headings",
            style="AntiOS.Treeview",
            selectmode="browse",
        )
        self.cleanup_tree.heading("type", text=self.t("cleanup.column.type"))
        self.cleanup_tree.heading("size", text=self.t("cleanup.column.size"))
        self.cleanup_tree.heading("modified", text=self.t("cleanup.column.modified"))
        self.cleanup_tree.heading("path", text=self.t("cleanup.column.path"))
        self.cleanup_tree.column("type", width=155, stretch=False)
        self.cleanup_tree.column("size", width=100, stretch=False)
        self.cleanup_tree.column("modified", width=115, stretch=False)
        self.cleanup_tree.column("path", width=520)

        scrollbar = tk.Scrollbar(
            table,
            orient="vertical",
            command=self.cleanup_tree.yview,
            width=10,
            bd=0,
            relief="flat",
        )
        self.cleanup_tree.configure(yscrollcommand=scrollbar.set)
        self.cleanup_tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        scrollbar.pack(side="right", fill="y")
        self.cleanup_tree.bind("<Double-1>", lambda _event: self._open_cleanup_selection())

        bottom = tk.Frame(parent, bg=THEME["bg"])
        bottom.pack(fill="x", pady=(12, 0))
        self.cleanup_open_button = self._button(
            bottom,
            self.t("cleanup.open_folder"),
            self._open_cleanup_selection,
            kind="secondary",
        )
        self.cleanup_open_button.pack(side="left")

        if self.storage_result:
            self._render_cleanup_result(self.storage_result)

    def _choose_cleanup_folder(self) -> None:
        from tkinter import filedialog

        selected = filedialog.askdirectory(
            title=self.t("cleanup.dialog.title"),
            initialdir=str(self.storage_path),
            mustexist=True,
        )
        if not selected:
            return
        self.storage_path = Path(selected)
        self.cleanup_path_label.configure(text=str(self.storage_path))
        self.cleanup_status.configure(text=self.t("cleanup.status.ready"))

    def _start_cleanup_scan(self) -> None:
        self._storage_cancel = threading.Event()
        self.cleanup_scan_button.configure(
            state="disabled",
            text=self.t("cleanup.scanning"),
        )
        self.cleanup_choose_button.configure(state="disabled")
        self.cleanup_cancel_button.configure(state="normal")
        self.cleanup_status.configure(
            text=self.t("cleanup.status.progress", count=0)
        )

        def progress(payload: dict[str, Any]) -> None:
            phase = payload.get("phase")
            if phase == "hashing":
                message = self.t(
                    "cleanup.status.hashing",
                    count=payload.get("files_hashed", 0),
                )
            else:
                message = self.t(
                    "cleanup.status.progress",
                    count=payload.get("files_scanned", 0),
                )
            self.root.after(
                0,
                lambda text=message: self.cleanup_status.configure(text=text)
                if self.cleanup_status.winfo_exists()
                else None,
            )

        def worker() -> None:
            try:
                result = scan_storage(
                    self.storage_path,
                    progress=progress,
                    cancelled=self._storage_cancel.is_set,
                )
            except Exception as exc:
                self.root.after(
                    0,
                    lambda error=str(exc): self._finish_cleanup_error(error),
                )
                return
            self.root.after(0, lambda: self._finish_cleanup_scan(result))

        threading.Thread(target=worker, daemon=True).start()

    def _cancel_cleanup_scan(self) -> None:
        self._storage_cancel.set()
        self.cleanup_status.configure(text=self.t("cleanup.status.cancelled"))

    def _finish_cleanup_error(self, error: str) -> None:
        self.cleanup_scan_button.configure(
            state="normal",
            text=self.t("cleanup.scan"),
        )
        self.cleanup_choose_button.configure(state="normal")
        self.cleanup_cancel_button.configure(state="disabled")
        self.cleanup_status.configure(
            text=self.t("cleanup.status.error", error=error)
        )

    def _finish_cleanup_scan(self, result: dict[str, Any]) -> None:
        self.cleanup_scan_button.configure(
            state="normal",
            text=self.t("cleanup.scan"),
        )
        self.cleanup_choose_button.configure(state="normal")
        self.cleanup_cancel_button.configure(state="disabled")

        if result.get("cancelled"):
            self.cleanup_status.configure(text=self.t("cleanup.status.cancelled"))
            return

        self.storage_result = result
        self._render_cleanup_result(result)
        self.cleanup_status.configure(
            text=self.t(
                "cleanup.status.done",
                count=result.get("summary", {}).get("files_scanned", 0),
            )
        )

    def _render_cleanup_result(self, result: dict[str, Any]) -> None:
        summary = result.get("summary", {})
        self.cleanup_summary["duplicate_groups"].configure(
            text=str(summary.get("duplicate_groups", 0))
        )
        self.cleanup_summary["duplicate_reclaimable_bytes"].configure(
            text=format_bytes(summary.get("duplicate_reclaimable_bytes", 0))
        )
        for key in ("old_large_files", "installer_archives", "empty_files"):
            self.cleanup_summary[key].configure(text=str(summary.get(key, 0)))

        for item in self.cleanup_tree.get_children():
            self.cleanup_tree.delete(item)

        rows: dict[str, dict[str, Any]] = {}

        def add_row(
            path: str,
            kind: str,
            size: int,
            modified: float | None,
        ) -> None:
            row = rows.setdefault(
                path,
                {
                    "types": [],
                    "size": size,
                    "modified": modified,
                    "path": path,
                },
            )
            if kind not in row["types"]:
                row["types"].append(kind)

        for group in result.get("duplicates", []):
            for path in group.get("paths", []):
                try:
                    modified = Path(path).stat().st_mtime
                except OSError:
                    modified = None
                add_row(
                    path,
                    self.t("cleanup.type.duplicate"),
                    int(group.get("size_bytes", 0)),
                    modified,
                )

        for key, type_key in (
            ("old_large_files", "cleanup.type.old"),
            ("installer_archives", "cleanup.type.archive"),
            ("empty_files", "cleanup.type.empty"),
        ):
            for item in result.get(key, []):
                add_row(
                    str(item.get("path", "")),
                    self.t(type_key),
                    int(item.get("size_bytes", 0)),
                    item.get("modified"),
                )

        ordered = sorted(
            rows.values(),
            key=lambda row: (-int(row["size"]), str(row["path"]).casefold()),
        )
        for index, row in enumerate(ordered):
            modified = (
                datetime.fromtimestamp(float(row["modified"])).strftime("%Y-%m-%d")
                if isinstance(row["modified"], (int, float))
                else "—"
            )
            self.cleanup_tree.insert(
                "",
                "end",
                values=(
                    " + ".join(row["types"]),
                    format_bytes(row["size"]),
                    modified,
                    row["path"],
                ),
                tags=("even" if index % 2 == 0 else "odd",),
            )

        self.cleanup_tree.tag_configure("even", background=THEME["surface"])
        self.cleanup_tree.tag_configure("odd", background=THEME["surface_alt"])

        if not ordered:
            self.cleanup_status.configure(text=self.t("cleanup.none"))

    def _open_cleanup_selection(self) -> None:
        selection = self.cleanup_tree.selection()
        if not selection:
            return
        values = self.cleanup_tree.item(selection[0], "values")
        if len(values) < 4:
            return
        path = Path(str(values[3]))
        target = path.parent if path.parent.exists() else self.storage_path
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]

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
        button.bind(
            "<Enter>",
            lambda _event, widget=button, nav_key=key: (
                widget.configure(bg=THEME["surface_hover"])
                if self.active_page != nav_key
                else None
            ),
        )
        button.bind(
            "<Leave>",
            lambda _event, widget=button, nav_key=key: widget.configure(
                bg=THEME["surface_alt"]
                if self.active_page == nav_key
                else THEME["sidebar"]
            ),
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

        button = self.tk.Button(
            parent,
            text=text,
            command=command,
            padx=15,
            pady=8,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            disabledforeground=THEME["muted_2"],
            bd=0,
            relief="flat",
            cursor="hand2",
            takefocus=True,
            font=("Segoe UI Semibold", 9),
        )
        button.bind(
            "<Enter>",
            lambda _event, widget=button, color=active_bg: (
                widget.configure(bg=color)
                if str(widget.cget("state")) != "disabled"
                else None
            ),
        )
        button.bind(
            "<Leave>",
            lambda _event, widget=button, color=bg: (
                widget.configure(bg=color)
                if str(widget.cget("state")) != "disabled"
                else None
            ),
        )
        return button

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
        _fallback_label, color, badge_bg = STATUS_STYLE.get(
            level,
            STATUS_STYLE["info"],
        )
        status_key = "advisory" if level == "advisory" else level
        label = self.t(f"status.{status_key}")

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
                self.t("button.open"),
                lambda u=str(uri): _open_settings(u),
                kind="secondary",
            ).pack(side="right", padx=14, pady=14)

        return card

    def _on_language_selected(self, _event: Any = None) -> None:
        selected = self.language_var.get()
        code = self.language_display_to_code.get(selected)
        if not code or code == self.language:
            return

        existing = self.data
        active_page = self.active_page
        self._storage_cancel.set()

        self.language = code
        self.tr = Translator(code)

        for child in self.root.winfo_children():
            child.destroy()

        self.pages = {}
        self.nav_buttons = {}
        self._check_rows = []

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page(active_page)

        if existing:
            localized = {
                "scan": existing["scan"],
                "health": existing["health"],
                "evaluation": evaluate_health(
                    existing["scan"],
                    existing["health"],
                    language=self.language,
                ),
            }
            self._render(localized)
        else:
            self.refresh()

    def show_page(self, name: str) -> None:
        if name not in self.pages:
            return

        titles = {
            "overview": (self.t("nav.overview"), self.t("page.overview.subtitle")),
            "security": (self.t("nav.security"), self.t("page.security.subtitle")),
            "startup": (self.t("nav.startup"), self.t("page.startup.subtitle")),
            "system": (self.t("nav.system"), self.t("page.system.subtitle")),
            "cleanup": (self.t("nav.cleanup"), self.t("page.cleanup.subtitle")),
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
            text=self.t("button.checking"),
        )
        self.hero_kicker.configure(
            text=self.t("overview.checking_kicker"),
            fg=THEME["accent"],
        )
        self.status_title.configure(
            text=self.t("overview.checking_title")
        )
        self.status_summary.configure(
            text=self.t("overview.checking_detail")
        )
        threading.Thread(target=self._worker, daemon=True).start()

    def _worker(self) -> None:
        try:
            data = collect_dashboard_data(self.language)
        except Exception as exc:
            self.root.after(0, lambda: self._show_error(str(exc)))
            return
        self.root.after(0, lambda: self._render(data))

    def _show_error(self, message: str) -> None:
        self.refresh_button.configure(
            state="normal",
            text=f"↻  {self.t('button.refresh')}",
        )
        self.hero_kicker.configure(
            text=self.t("overview.check_failed"),
            fg=THEME["warn"],
        )
        self.status_title.configure(
            text=self.t("error.failed_title")
        )
        self.status_summary.configure(text=message)

    def _render(self, data: dict[str, Any]) -> None:
        self.data = data
        self.refresh_button.configure(
            state="normal",
            text=self.t("button.refresh"),
        )

        evaluation = data["evaluation"]
        health = data["health"]
        scan_data = data["scan"]

        overall = evaluation.get("overall")
        if overall == "needs-attention":
            kicker = (self.t("overview.needs_attention"), THEME["warn"])
        elif overall == "review":
            kicker = (self.t("overview.review"), THEME["review"])
        else:
            kicker = (self.t("overview.all_clear"), THEME["ok"])

        self.hero_kicker.configure(text=kicker[0], fg=kicker[1])
        self.status_title.configure(
            text=evaluation.get("headline", "Check complete")
        )

        summary = evaluation.get("summary", {})
        self.status_summary.configure(
            text=self.t(
                "overview.completed",
                count=summary.get("info", 0),
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
            self.t("security.protected")
            if defender_enabled is True and realtime is True
            else self.t("security.needs_review")
            if defender.get("available")
            else self.t("security.unavailable")
        )
        defender_detail = self.t(
            "security.defender.detail",
            antivirus=_friendly_bool(defender_enabled, self.tr),
            realtime=_friendly_bool(realtime, self.tr),
            age=defender.get("signature_age_days", self.t("value.unknown")),
        )

        self.security_cards["defender"]["value"].configure(
            text=defender_value,
            fg=THEME["ok"]
            if defender_enabled is True and realtime is True
            else THEME["review"],
        )
        self.security_cards["defender"]["detail"].configure(text=defender_detail)

        protection = bitlocker.get("protection_status")
        encryption = bitlocker.get("encryption_percentage")
        self.security_cards["encryption"]["value"].configure(
            text=str(protection or "Unavailable"),
            fg=THEME["ok"] if str(protection).lower() == "on" else THEME["review"],
        )
        self.security_cards["encryption"]["detail"].configure(
            text=self.t(
                "security.encryption.detail",
                percent=encryption
                if encryption is not None
                else self.t("value.unknown"),
            )
        )

        secure_boot = security.get("secure_boot", {}).get("enabled")
        self.security_cards["secure_boot"]["value"].configure(
            text=_friendly_bool(secure_boot, self.tr),
            fg=THEME["ok"] if secure_boot is True else THEME["review"],
        )
        self.security_cards["secure_boot"]["detail"].configure(
            text=self.t("security.secure_boot.detail")
        )

        tpm = security.get("tpm", {})
        tpm_ready = tpm.get("ready")
        tpm_present = tpm.get("present")
        tpm_value = (
            self.t("security.tpm.ready")
            if tpm_present is True and tpm_ready is True
            else self.t("security.tpm.present_not_ready")
            if tpm_present is True
            else self.t("security.tpm.not_detected")
            if tpm_present is False
            else self.t("security.tpm.unknown")
        )
        self.security_cards["tpm"]["value"].configure(
            text=tpm_value,
            fg=THEME["ok"]
            if tpm_present is True and tpm_ready is True
            else THEME["review"],
        )
        self.security_cards["tpm"]["detail"].configure(
            text=self.t("security.tpm.detail")
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
            text=self.t(
                "system.windows.value",
                generation=win.get("generation") or self.t("value.windows"),
                edition=win.get("edition_id") or self.t("value.edition_unknown"),
                version=win.get("display_version") or self.t("value.unknown"),
                build=win.get("full_build") or self.t("value.unknown"),
            )
        )
        self.system_cards["windows"]["detail"].configure(
            text=self.t("system.windows.detail")
        )

        self.system_cards["computer"]["value"].configure(
            text=self.t(
                "system.computer.value",
                name=host.get("computer_name") or self.t("value.computer_unknown"),
                architecture=host.get("architecture") or self.t("value.arch_unknown"),
                processor=host.get("processor") or self.t("value.processor_unknown"),
            )
        )
        self.system_cards["computer"]["detail"].configure(
            text=self.t("system.computer.detail")
        )

        free = _format_bytes(storage.get("free_bytes"), self.tr)
        total = _format_bytes(storage.get("total_bytes"), self.tr)
        percent = storage.get("percent_free")
        self.system_cards["storage"]["value"].configure(
            text=self.t(
                "system.storage.value",
                free=free,
                total=total,
                percent=percent
                if percent is not None
                else self.t("value.unknown"),
            )
        )
        self.system_cards["storage"]["detail"].configure(
            text=self.t("system.storage.detail")
        )

        self.system_cards["session"]["value"].configure(
            text=self.t(
                "system.session.value",
                days=uptime.get("days", self.t("value.unknown")),
                pending=_friendly_bool(reboot.get("pending"), self.tr),
            )
        )
        self.system_cards["session"]["detail"].configure(
            text=self.t("system.session.detail")
        )

    def export_report(self) -> None:
        from tkinter import filedialog, messagebox

        if not self.data:
            messagebox.showinfo("AntiOS", self.t("export.no_data"))
            return

        target = filedialog.asksaveasfilename(
            title=self.t("export.title"),
            defaultextension=".json",
            filetypes=[(self.t("export.filetype"), "*.json")],
            initialfile="antios-report.json",
        )
        if not target:
            return

        Path(target).write_text(
            json.dumps(self.data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        messagebox.showinfo(
            "AntiOS",
            self.t("export.saved", path=target),
        )


def launch(language: str | None = None) -> int:
    tr = Translator(normalize_language(language or detect_language()))
    if not is_windows():
        raise RuntimeError(tr.t("error.dashboard_windows"))

    import tkinter as tk

    if os.name == "nt":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    root = tk.Tk()
    Dashboard(root, language=language)
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
    parser.add_argument(
        "--lang",
        choices=list(LANGUAGE_NAMES),
        help="UI language: en, ru, es, zh-CN, fi, pl, mn. Defaults to Windows locale.",
    )
    args = parser.parse_args(argv)
    if args.self_test:
        assert "bg" in THEME and "ok" in STATUS_STYLE
        return 0
    return launch(args.lang)
