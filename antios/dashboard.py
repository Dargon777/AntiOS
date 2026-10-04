from __future__ import annotations

import argparse
import ctypes
import json
import os
import queue
import threading
import webbrowser
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .antivirus_ui import AntivirusPanel
from .config import (
    AppConfig,
    CleanupConfig,
    UIConfig,
    default_config_path,
    load_config,
    save_config,
)
from .consumer import evaluate_health
from .core import scan
from .health import collect_health
from .i18n import LANGUAGE_NAMES, Translator, detect_language, normalize_language
from .registry import WindowsRegistryBackend, is_windows
from .storage_cleanup import (
    DEFAULT_OLD_DAYS,
    cleanup_files,
    default_cleanup_backup_path,
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

DARK_THEME = {
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
    "accent_text": "#08111F",
    "ok": "#59D499",
    "ok_bg": "#102A25",
    "review": "#F3C969",
    "review_bg": "#2C2513",
    "warn": "#FF7B82",
    "warn_bg": "#2E171D",
    "info": "#7CAEF8",
    "info_bg": "#132239",
}

LIGHT_THEME = {
    "bg": "#F4F7FB",
    "sidebar": "#FFFFFF",
    "surface": "#FFFFFF",
    "surface_alt": "#EEF2F7",
    "surface_hover": "#E3E9F2",
    "border": "#D7DEE8",
    "text": "#172033",
    "muted": "#5F6F84",
    "muted_2": "#7A8798",
    "accent": "#3B82F6",
    "accent_hover": "#2563EB",
    "accent_text": "#FFFFFF",
    "ok": "#15803D",
    "ok_bg": "#ECFDF3",
    "review": "#A16207",
    "review_bg": "#FFF7D6",
    "warn": "#C2414A",
    "warn_bg": "#FFF0F1",
    "info": "#2563EB",
    "info_bg": "#EEF4FF",
}

THEME = dict(DARK_THEME)
STATUS_STYLE: dict[str, tuple[str, str, str]] = {}


def _refresh_status_style() -> None:
    STATUS_STYLE.clear()
    STATUS_STYLE.update({
        "ok": ("OK", THEME["ok"], THEME["ok_bg"]),
        "advisory": ("REVIEW", THEME["review"], THEME["review_bg"]),
        "warn": ("WARNING", THEME["warn"], THEME["warn_bg"]),
        "info": ("INFO", THEME["info"], THEME["info_bg"]),
    })


def _system_theme() -> str:
    if os.name != "nt":
        return "dark"
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            value, _kind = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "light" if int(value) else "dark"
    except Exception:
        return "dark"


def _apply_theme_palette(mode: str) -> str:
    resolved = _system_theme() if mode == "system" else mode
    palette = LIGHT_THEME if resolved == "light" else DARK_THEME
    THEME.clear()
    THEME.update(palette)
    _refresh_status_style()
    return resolved


_refresh_status_style()

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


def _enable_dark_titlebar(root: Any, dark: bool = True) -> None:
    """Ask modern Windows to render the native title bar to match the app."""
    if os.name != "nt":
        return
    try:
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(1 if dark else 0)
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
        auto_refresh: bool = True,
    ) -> None:
        import tkinter as tk
        from tkinter import ttk

        self.root = root
        self.tk = tk
        self.ttk = ttk
        self.config_path = default_config_path()
        try:
            self.config = load_config(self.config_path)
        except (OSError, ValueError):
            self.config = AppConfig()

        self.language_setting = (
            normalize_language(language)
            if language
            else self.config.ui.language
        )
        detected_language = detect_language()
        self.language = normalize_language(
            detected_language
            if self.language_setting == "auto"
            else self.language_setting
        )
        self.tr = Translator(self.language)

        self.theme_mode = self.config.ui.theme
        self.resolved_theme = _apply_theme_palette(self.theme_mode)

        self.data: dict[str, Any] | None = None
        self.pages: dict[str, Any] = {}
        self.nav_buttons: dict[str, Any] = {}
        self.active_page = "overview"
        self._check_rows: list[Any] = []

        configured_path = Path(self.config.cleanup.last_path).expanduser()
        self.storage_path = (
            configured_path
            if self.config.cleanup.remember_folder
            and self.config.cleanup.last_path
            and configured_path.is_dir()
            else default_scan_path()
        )
        self.storage_result: dict[str, Any] | None = None
        self._storage_cancel = threading.Event()
        self._storage_action_busy = False
        self.antivirus_path = default_scan_path()
        self.antivirus_signatures: Path | None = None
        self.antivirus_engine = "clamav"
        self.antivirus_result: dict[str, Any] | None = None
        self.antivirus_items: list[dict] = []
        self.antivirus_queue: queue.Queue = queue.Queue()
        self.antivirus_cancel = threading.Event()
        self.antivirus_busy = False
        self.antivirus_cancelable = False
        self.guard_probe_busy = False

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page("overview")
        if auto_refresh:
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
        root.bind("<Control-6>", lambda _event: self.show_page("antivirus"))
        root.bind("<Control-comma>", lambda _event: self.show_page("settings"))
        root.protocol("WM_DELETE_WINDOW", self._close)
        _enable_dark_titlebar(root, self.resolved_theme == "dark")

    def _close(self) -> None:
        self._storage_cancel.set()
        self.antivirus_cancel.set()
        self.root.destroy()

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

        style.configure(
            "AntiOS.Horizontal.TProgressbar",
            troughcolor=THEME["surface_alt"],
            background=THEME["accent"],
            bordercolor=THEME["border"],
            lightcolor=THEME["accent"],
            darkcolor=THEME["accent"],
            thickness=7,
        )

        style.configure(
            "AntiOS.TCombobox",
            fieldbackground=THEME["surface_alt"],
            background=THEME["surface_alt"],
            foreground=THEME["text"],
            arrowcolor=THEME["muted"],
            bordercolor=THEME["border"],
            lightcolor=THEME["border"],
            darkcolor=THEME["border"],
            padding=(8, 6),
        )
        style.map(
            "AntiOS.TCombobox",
            fieldbackground=[("readonly", THEME["surface_alt"])],
            foreground=[("readonly", THEME["text"])],
            selectbackground=[("readonly", THEME["surface_alt"])],
            selectforeground=[("readonly", THEME["text"])],
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
            fg=THEME["accent_text"],
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
            wraplength=142,
            justify="left",
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text=f"v{__version__}  •  DargonITP",
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
            ("antivirus", self.t("nav.antivirus")),
            ("startup", self.t("nav.startup")),
            ("system", self.t("nav.system")),
            ("cleanup", self.t("nav.cleanup")),
        ]:
            self._create_nav_button(key, label)

        spacer = tk.Frame(self.sidebar, bg=THEME["sidebar"])
        spacer.pack(fill="both", expand=True)

        self.settings_button = self.tk.Button(
            self.sidebar,
            text=f"⚙  {self.t('nav.settings')}",
            command=lambda: self.show_page("settings"),
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
            takefocus=True,
            font=("Segoe UI Semibold", 10),
        )
        self.settings_button.bind(
            "<Enter>",
            lambda _event: (
                self.settings_button.configure(bg=THEME["surface_hover"])
                if self.active_page != "settings"
                else None
            ),
        )
        self.settings_button.bind(
            "<Leave>",
            lambda _event: self.settings_button.configure(
                bg=THEME["surface_alt"]
                if self.active_page == "settings"
                else THEME["sidebar"]
            ),
        )
        self.settings_button.pack(fill="x", padx=8, pady=(0, 10))

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
            wraplength=180,
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=12, pady=(0, 7))
        tk.Label(
            trust,
            text="F5  •  Ctrl+E  •  Ctrl+,",
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
        title_block.pack(side="left", fill="both", expand=True)

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
            justify="left",
        )
        self.page_subtitle.pack(anchor="w", pady=(3, 0))

        header_actions = tk.Frame(self.header, bg=THEME["bg"])
        header_actions.pack(side="right", before=title_block)
        self.header.bind(
            "<Configure>",
            lambda event: self.page_subtitle.configure(
                wraplength=max(150, event.width - header_actions.winfo_reqwidth() - 20)
            ),
        )

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
        for name in ("overview", "security", "antivirus", "startup", "system", "cleanup", "settings"):
            frame = self.tk.Frame(self.page_host, bg=THEME["bg"])
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.pages[name] = frame

        self._build_overview(self.pages["overview"])
        self._build_security(self.pages["security"])
        self.antivirus_panel = AntivirusPanel(self, self.pages["antivirus"], THEME)
        self._build_startup(self.pages["startup"])
        self._build_system(self.pages["system"])
        self._build_cleanup(self.pages["cleanup"])
        self._build_settings(self.pages["settings"])

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
        controls.pack(fill="x", pady=(0, 12))

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

        status_row = tk.Frame(parent, bg=THEME["bg"])
        status_row.pack(fill="x", pady=(0, 8))
        self.cleanup_status = tk.Label(
            status_row,
            text=self.t("cleanup.status.ready"),
            bg=THEME["bg"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.cleanup_status.pack(side="left", fill="x", expand=True)
        self.cleanup_selection_label = tk.Label(
            status_row,
            text=self.t("cleanup.selection_none"),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 9),
            anchor="e",
        )
        self.cleanup_selection_label.pack(side="right")

        self.cleanup_progress = self.ttk.Progressbar(
            parent,
            mode="indeterminate",
            style="AntiOS.Horizontal.TProgressbar",
        )
        self.cleanup_progress.pack(fill="x", pady=(0, 12))

        summary = tk.Frame(parent, bg=THEME["bg"])
        summary.pack(fill="x", pady=(0, 12))
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
            tk.Frame(card, bg=THEME["accent"], height=2).pack(fill="x")
            value = tk.Label(
                card,
                text="—",
                bg=THEME["surface"],
                fg=THEME["text"],
                font=("Segoe UI", 15, "bold"),
            )
            value.pack(anchor="w", padx=13, pady=(10, 2))
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
            text=self.t(
                "cleanup.note",
                days=self.config.cleanup.old_days,
            ),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=900,
        ).pack(fill="x", pady=(0, 10))

        table_header = tk.Frame(parent, bg=THEME["bg"])
        table_header.pack(fill="x", pady=(0, 6))
        tk.Label(
            table_header,
            text=self.t("cleanup.results"),
            bg=THEME["bg"],
            fg=THEME["text"],
            font=("Segoe UI Semibold", 10),
        ).pack(side="left")
        tk.Label(
            table_header,
            text=self.t("cleanup.multi_hint"),
            bg=THEME["bg"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
        ).pack(side="right")

        table = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        table.pack(fill="both", expand=True)
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)

        self.cleanup_tree = self.ttk.Treeview(
            table,
            columns=("type", "size", "modified", "path"),
            show="headings",
            style="AntiOS.Treeview",
            selectmode="extended",
        )
        self.cleanup_tree.heading("type", text=self.t("cleanup.column.type"))
        self.cleanup_tree.heading("size", text=self.t("cleanup.column.size"))
        self.cleanup_tree.heading("modified", text=self.t("cleanup.column.modified"))
        self.cleanup_tree.heading("path", text=self.t("cleanup.column.path"))
        self.cleanup_tree.column("type", width=165, stretch=False)
        self.cleanup_tree.column("size", width=105, stretch=False, anchor="e")
        self.cleanup_tree.column("modified", width=115, stretch=False, anchor="center")
        self.cleanup_tree.column("path", width=520)

        vertical = tk.Scrollbar(table, orient="vertical", command=self.cleanup_tree.yview, width=10, bd=0)
        horizontal = tk.Scrollbar(table, orient="horizontal", command=self.cleanup_tree.xview, bd=0)
        self.cleanup_tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )
        self.cleanup_tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=(1, 0))
        vertical.grid(row=0, column=1, sticky="ns", pady=(1, 0))
        horizontal.grid(row=1, column=0, sticky="ew", padx=(1, 0), pady=(0, 1))
        self.cleanup_tree.bind("<Double-1>", lambda _event: self._open_cleanup_selection())
        self.cleanup_tree.bind("<<TreeviewSelect>>", lambda _event: self._cleanup_selection_changed())

        actions = tk.Frame(
            parent,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        actions.pack(fill="x", pady=(10, 0))
        left_actions = tk.Frame(actions, bg=THEME["surface"])
        left_actions.pack(side="left", padx=10, pady=10)
        right_actions = tk.Frame(actions, bg=THEME["surface"])
        right_actions.pack(side="right", padx=10, pady=10)

        self.cleanup_open_button = self._button(
            left_actions,
            self.t("cleanup.open_folder"),
            self._open_cleanup_selection,
            kind="secondary",
        )
        self.cleanup_open_button.pack(side="left")

        self.cleanup_duplicate_select_button = self._button(
            left_actions,
            self.t("cleanup.select_duplicate_copies"),
            self._select_cleanup_duplicate_copies,
            kind="secondary",
        )
        self.cleanup_duplicate_select_button.pack(side="left", padx=(6, 0))

        self.cleanup_select_all_button = self._button(
            left_actions,
            self.t("cleanup.select_all"),
            self._select_cleanup_all,
            kind="secondary",
        )
        self.cleanup_select_all_button.pack(side="left", padx=(6, 0))

        self.cleanup_clear_button = self._button(
            left_actions,
            self.t("cleanup.clear_selection"),
            self._clear_cleanup_selection,
            kind="secondary",
        )
        self.cleanup_clear_button.pack(side="left", padx=(6, 0))

        self.cleanup_backup_button = self._button(
            right_actions,
            self.t("cleanup.delete_backup"),
            lambda: self._run_cleanup_action("backup"),
            kind="primary",
        )
        self.cleanup_backup_button.pack(side="left")

        self.cleanup_delete_button = self._button(
            right_actions,
            self.t("cleanup.delete_permanent"),
            lambda: self._run_cleanup_action("delete"),
            kind="danger",
        )
        self.cleanup_delete_button.pack(side="left", padx=(8, 0))

        self.cleanup_rows: dict[str, dict[str, Any]] = {}
        self._cleanup_selection_changed()

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

        if self.config.cleanup.remember_folder:
            self.config = replace(
                self.config,
                cleanup=replace(
                    self.config.cleanup,
                    last_path=str(self.storage_path),
                ),
            )
            self._persist_config()

    def _set_cleanup_busy(self, busy: bool, *, scanning: bool = False) -> None:
        for button in (
            self.cleanup_choose_button,
            self.cleanup_scan_button,
            self.cleanup_open_button,
            self.cleanup_duplicate_select_button,
            self.cleanup_select_all_button,
            self.cleanup_clear_button,
            self.cleanup_backup_button,
            self.cleanup_delete_button,
        ):
            button.configure(state="disabled" if busy else "normal")
        self.cleanup_cancel_button.configure(state="normal" if scanning else "disabled")
        self.cleanup_scan_button.configure(
            text=self.t("cleanup.scanning") if scanning else self.t("cleanup.scan")
        )
        if busy:
            self.cleanup_progress.start(12)
        else:
            self.cleanup_progress.stop()
        if not busy:
            self._cleanup_selection_changed()

    def _start_cleanup_scan(self) -> None:
        if self._storage_action_busy:
            return
        self._storage_cancel = threading.Event()
        self._set_cleanup_busy(True, scanning=True)
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
                    old_days=self.config.cleanup.old_days,
                    large_bytes=self.config.cleanup.large_mb * 1024 * 1024,
                    duplicate_min_bytes=(
                        self.config.cleanup.duplicate_min_mb * 1024 * 1024
                    ),
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
        self._set_cleanup_busy(False)
        self.cleanup_status.configure(
            text=self.t("cleanup.status.error", error=error)
        )

    def _finish_cleanup_scan(self, result: dict[str, Any]) -> None:
        self._set_cleanup_busy(False)

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

        self.cleanup_tree.delete(*self.cleanup_tree.get_children())
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

        snapshots = result.get("candidate_snapshots", {})
        for group in result.get("duplicates", []):
            for path in group.get("paths", []):
                snapshot = snapshots.get(str(path), {})
                modified_ns = snapshot.get("modified_ns")
                modified = (float(modified_ns) / 1_000_000_000
                            if isinstance(modified_ns, int) else None)
                add_row(
                    str(path),
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
        self.cleanup_rows = {}
        for index, row in enumerate(ordered):
            modified = (
                datetime.fromtimestamp(float(row["modified"])).strftime("%Y-%m-%d")
                if isinstance(row["modified"], (int, float))
                else "—"
            )
            iid = f"cleanup-{index}"
            self.cleanup_rows[iid] = row
            self.cleanup_tree.insert(
                "",
                "end",
                iid=iid,
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
        self._cleanup_selection_changed()

        if not ordered:
            self.cleanup_status.configure(text=self.t("cleanup.none"))

    def _selected_cleanup_rows(self) -> list[dict[str, Any]]:
        return [
            self.cleanup_rows[iid]
            for iid in self.cleanup_tree.selection()
            if iid in self.cleanup_rows
        ]

    def _cleanup_selection_changed(self) -> None:
        if not hasattr(self, "cleanup_tree"):
            return
        selected = self._selected_cleanup_rows()
        size = sum(int(row.get("size", 0)) for row in selected)
        if selected:
            self.cleanup_selection_label.configure(
                text=self.t(
                    "cleanup.selection",
                    count=len(selected),
                    size=format_bytes(size),
                ),
                fg=THEME["text"],
            )
        else:
            self.cleanup_selection_label.configure(
                text=self.t("cleanup.selection_none"),
                fg=THEME["muted_2"],
            )

        can_act = bool(selected) and not self._storage_action_busy
        state = "normal" if can_act else "disabled"
        self.cleanup_open_button.configure(state=state)
        self.cleanup_backup_button.configure(state=state)
        self.cleanup_delete_button.configure(state=state)
        self.cleanup_clear_button.configure(state=state)

    def _select_cleanup_all(self) -> None:
        children = self.cleanup_tree.get_children()
        if children:
            self.cleanup_tree.selection_set(children)
            self._cleanup_selection_changed()

    def _clear_cleanup_selection(self) -> None:
        self.cleanup_tree.selection_remove(self.cleanup_tree.selection())
        self._cleanup_selection_changed()

    def _select_cleanup_duplicate_copies(self) -> None:
        if not self.storage_result:
            return
        disposable: set[str] = set()
        for group in self.storage_result.get("duplicates", []):
            paths = [str(path) for path in group.get("paths", [])]
            disposable.update(paths[1:])
        matches = [
            iid
            for iid, row in self.cleanup_rows.items()
            if str(row.get("path")) in disposable
        ]
        if matches:
            self.cleanup_tree.selection_set(matches)
        else:
            self.cleanup_tree.selection_remove(self.cleanup_tree.selection())
        self._cleanup_selection_changed()

    def _open_cleanup_selection(self) -> None:
        selected = self._selected_cleanup_rows()
        if not selected:
            return
        path = Path(str(selected[0]["path"]))
        target = path.parent if path.parent.exists() else self.storage_path
        if os.name == "nt":
            os.startfile(str(target))  # type: ignore[attr-defined]

    def _run_cleanup_action(self, mode: str) -> None:
        from tkinter import filedialog, messagebox

        if self._storage_action_busy or not self.storage_result:
            return
        selected = self._selected_cleanup_rows()
        if not selected:
            return

        total = sum(int(row.get("size", 0)) for row in selected)
        paths = [str(row["path"]) for row in selected]
        backup_root = None

        if mode == "backup":
            if not messagebox.askyesno(
                self.t("cleanup.confirm_backup_title"),
                self.t(
                    "cleanup.confirm_backup",
                    count=len(paths),
                    size=format_bytes(total),
                ),
            ):
                return
            chosen = filedialog.askdirectory(
                title=self.t("cleanup.backup_dialog_title"),
                initialdir=str(default_cleanup_backup_path().parent.parent),
                mustexist=False,
            )
            if not chosen:
                return
            backup_root = chosen
        else:
            if not messagebox.askyesno(
                self.t("cleanup.confirm_permanent_title"),
                self.t(
                    "cleanup.confirm_permanent",
                    count=len(paths),
                    size=format_bytes(total),
                ),
                icon="warning",
            ):
                return

        self._storage_action_busy = True
        self._set_cleanup_busy(True)
        self.cleanup_status.configure(text=self.t("cleanup.action_working"))

        def worker() -> None:
            try:
                result = cleanup_files(
                    self.storage_result,
                    paths,
                    mode=mode,
                    backup_root=backup_root,
                )
            except Exception as exc:
                self.root.after(
                    0,
                    lambda error=str(exc): self._finish_cleanup_action_error(error),
                )
                return
            self.root.after(0, lambda: self._finish_cleanup_action(result))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_cleanup_action_error(self, error: str) -> None:
        from tkinter import messagebox

        self._storage_action_busy = False
        self._set_cleanup_busy(False)
        self.cleanup_status.configure(
            text=self.t("cleanup.action_error", error=error)
        )
        messagebox.showerror(
            self.t("cleanup.action_error_title"),
            self.t("cleanup.action_error", error=error),
        )

    def _finish_cleanup_action(self, result: dict[str, Any]) -> None:
        from tkinter import messagebox

        self._storage_action_busy = False
        self._set_cleanup_busy(False)
        deleted = int(result.get("deleted", 0))
        errors = len(result.get("errors", []))
        freed = format_bytes(result.get("bytes_freed", 0))

        if result.get("mode") == "backup":
            message = self.t(
                "cleanup.action_done_backup",
                count=deleted,
                size=freed,
                backup=result.get("backup_dir") or "—",
                errors=errors,
            )
        else:
            message = self.t(
                "cleanup.action_done",
                count=deleted,
                size=freed,
                errors=errors,
            )

        self.cleanup_status.configure(text=message)
        if errors:
            messagebox.showwarning(self.t("cleanup.action_result_title"), message)
        else:
            messagebox.showinfo(self.t("cleanup.action_result_title"), message)

        # Refresh candidates from disk after a destructive action so the table
        # never presents stale files as still selectable.
        self._start_cleanup_scan()

    def _build_settings(self, parent: Any) -> None:
        tk = self.tk

        scroll = ScrollFrame(parent, tk)
        scroll.frame.pack(fill="both", expand=True)
        body = scroll.inner

        appearance = tk.Frame(
            body,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        appearance.pack(fill="x", pady=(0, 14))

        tk.Label(
            appearance,
            text=self.t("settings.appearance.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=20, pady=(18, 2))
        tk.Label(
            appearance,
            text=self.t("settings.appearance.subtitle"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=20, pady=(0, 16))

        appearance_grid = tk.Frame(appearance, bg=THEME["surface"])
        appearance_grid.pack(fill="x", padx=20, pady=(0, 20))
        appearance_grid.grid_columnconfigure(0, weight=1)
        appearance_grid.grid_columnconfigure(1, weight=1)

        language_group = tk.Frame(appearance_grid, bg=THEME["surface"])
        language_group.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        tk.Label(
            language_group,
            text=self.t("settings.language"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", pady=(0, 6))

        auto_language = self.t("settings.language.auto")
        self.language_display_to_code = {auto_language: "auto"}
        self.language_display_to_code.update(
            {label: code for code, label in LANGUAGE_NAMES.items()}
        )
        language_value = (
            auto_language
            if self.language_setting == "auto"
            else LANGUAGE_NAMES.get(self.language_setting, auto_language)
        )
        self.language_var = tk.StringVar(value=language_value)
        self.language_combo = self.ttk.Combobox(
            language_group,
            textvariable=self.language_var,
            values=list(self.language_display_to_code),
            state="readonly",
            style="AntiOS.TCombobox",
        )
        self.language_combo.pack(fill="x")
        self.language_combo.bind(
            "<<ComboboxSelected>>",
            self._on_language_selected,
        )

        theme_group = tk.Frame(appearance_grid, bg=THEME["surface"])
        theme_group.grid(row=0, column=1, sticky="ew", padx=(10, 0))
        tk.Label(
            theme_group,
            text=self.t("settings.theme"),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w", pady=(0, 6))

        self.theme_display_to_code = {
            self.t("settings.theme.system"): "system",
            self.t("settings.theme.dark"): "dark",
            self.t("settings.theme.light"): "light",
        }
        theme_code_to_display = {
            code: label for label, code in self.theme_display_to_code.items()
        }
        self.theme_var = tk.StringVar(
            value=theme_code_to_display.get(
                self.theme_mode,
                self.t("settings.theme.system"),
            )
        )
        self.theme_combo = self.ttk.Combobox(
            theme_group,
            textvariable=self.theme_var,
            values=list(self.theme_display_to_code),
            state="readonly",
            style="AntiOS.TCombobox",
        )
        self.theme_combo.pack(fill="x")
        self.theme_combo.bind(
            "<<ComboboxSelected>>",
            self._on_theme_selected,
        )

        cleanup = tk.Frame(
            body,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        cleanup.pack(fill="x", pady=(0, 14))

        tk.Label(
            cleanup,
            text=self.t("settings.cleanup.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=20, pady=(18, 2))
        tk.Label(
            cleanup,
            text=self.t("settings.cleanup.subtitle"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=20, pady=(0, 16))

        cleanup_grid = tk.Frame(cleanup, bg=THEME["surface"])
        cleanup_grid.pack(fill="x", padx=20)
        for column in range(3):
            cleanup_grid.grid_columnconfigure(column, weight=1, uniform="settings_cleanup")

        self.cleanup_old_days_var = tk.StringVar(
            value=str(self.config.cleanup.old_days)
        )
        self.cleanup_large_mb_var = tk.StringVar(
            value=str(self.config.cleanup.large_mb)
        )
        self.cleanup_duplicate_min_var = tk.StringVar(
            value=str(self.config.cleanup.duplicate_min_mb)
        )

        fields = [
            (
                self.t("settings.cleanup.old_days"),
                self.cleanup_old_days_var,
                0,
            ),
            (
                self.t("settings.cleanup.large_mb"),
                self.cleanup_large_mb_var,
                1,
            ),
            (
                self.t("settings.cleanup.duplicate_min_mb"),
                self.cleanup_duplicate_min_var,
                2,
            ),
        ]
        for label, variable, column in fields:
            group = tk.Frame(cleanup_grid, bg=THEME["surface"])
            group.grid(
                row=0,
                column=column,
                sticky="ew",
                padx=(0 if column == 0 else 8, 0 if column == 2 else 8),
            )
            tk.Label(
                group,
                text=label,
                bg=THEME["surface"],
                fg=THEME["muted_2"],
                font=("Segoe UI Semibold", 8),
            ).pack(anchor="w", pady=(0, 6))
            spin = tk.Spinbox(
                group,
                from_=1,
                to=1000000,
                textvariable=variable,
                bg=THEME["surface_alt"],
                fg=THEME["text"],
                buttonbackground=THEME["surface_alt"],
                insertbackground=THEME["text"],
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground=THEME["border"],
                highlightcolor=THEME["accent"],
                font=("Segoe UI", 10),
            )
            spin.pack(fill="x", ipady=6)

        self.cleanup_remember_var = tk.BooleanVar(
            value=self.config.cleanup.remember_folder
        )
        remember = tk.Checkbutton(
            cleanup,
            text=self.t("settings.cleanup.remember_folder"),
            variable=self.cleanup_remember_var,
            bg=THEME["surface"],
            fg=THEME["text"],
            activebackground=THEME["surface"],
            activeforeground=THEME["text"],
            selectcolor=THEME["surface_alt"],
            highlightthickness=0,
            bd=0,
            font=("Segoe UI", 9),
        )
        remember.pack(anchor="w", padx=20, pady=(16, 12))

        cleanup_actions = tk.Frame(cleanup, bg=THEME["surface"])
        cleanup_actions.pack(fill="x", padx=20, pady=(0, 20))
        self._button(
            cleanup_actions,
            self.t("settings.save"),
            self._save_cleanup_settings,
            kind="primary",
        ).pack(side="left")
        self._button(
            cleanup_actions,
            self.t("settings.reset"),
            self._reset_settings,
            kind="secondary",
        ).pack(side="left", padx=(8, 0))

        self.settings_status = tk.Label(
            cleanup_actions,
            text="",
            bg=THEME["surface"],
            fg=THEME["ok"],
            font=("Segoe UI", 9),
        )
        self.settings_status.pack(side="left", padx=(12, 0))

        about = tk.Frame(
            body,
            bg=THEME["surface"],
            highlightthickness=1,
            highlightbackground=THEME["border"],
        )
        about.pack(fill="x", pady=(0, 14))

        tk.Label(
            about,
            text=self.t("settings.about.title"),
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=20, pady=(18, 2))
        tk.Label(
            about,
            text=self.t("settings.about.subtitle"),
            bg=THEME["surface"],
            fg=THEME["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=20, pady=(0, 12))

        info = tk.Frame(about, bg=THEME["surface"])
        info.pack(fill="x", padx=20, pady=(0, 14))
        info_text = (
            f"{self.t('settings.about.version')}: {__version__}    •    "
            f"{self.t('settings.about.channel')}: "
            f"{self.t('settings.about.channel.alpha')}    •    "
            f"{self.t('settings.about.store')}: 9P7V8BKW2KG9"
        )
        tk.Label(
            info,
            text=info_text,
            bg=THEME["surface"],
            fg=THEME["text"],
            font=("Segoe UI", 10),
        ).pack(anchor="w")
        tk.Label(
            info,
            text=self.t(
                "settings.config_location",
                path=str(self.config_path),
            ),
            bg=THEME["surface"],
            fg=THEME["muted_2"],
            font=("Segoe UI", 8),
            wraplength=780,
            justify="left",
        ).pack(anchor="w", pady=(5, 0))

        links = tk.Frame(about, bg=THEME["surface"])
        links.pack(fill="x", padx=20, pady=(0, 20))
        for index, (label, url) in enumerate([
            (self.t("settings.github"), PROJECT_URL),
            (self.t("settings.releases"), RELEASES_URL),
            (self.t("settings.privacy"), PRIVACY_URL),
            (self.t("settings.support"), SUPPORT_URL),
        ]):
            self._button(
                links,
                label,
                lambda target=url: _open_url(target),
                kind="secondary",
            ).pack(side="left", padx=(0 if index == 0 else 8, 0))

    def _persist_config(self) -> bool:
        try:
            save_config(self.config, self.config_path)
            return True
        except OSError:
            return False

    def _rebuild_ui(self, active_page: str | None = None) -> None:
        existing = self.data
        target_page = active_page or self.active_page
        self._storage_cancel.set()

        for child in self.root.winfo_children():
            child.destroy()

        self.pages = {}
        self.nav_buttons = {}
        self._check_rows = []

        self._configure_root()
        self._configure_ttk()
        self._build_shell()
        self._build_pages()
        self.show_page(target_page)

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

    def _save_cleanup_settings(self) -> None:
        try:
            old_days = int(self.cleanup_old_days_var.get())
            large_mb = int(self.cleanup_large_mb_var.get())
            duplicate_min_mb = int(self.cleanup_duplicate_min_var.get())
            if min(old_days, large_mb, duplicate_min_mb) < 1:
                raise ValueError
        except (TypeError, ValueError):
            self.settings_status.configure(
                text=self.t("settings.invalid_number"),
                fg=THEME["warn"],
            )
            return

        remember = bool(self.cleanup_remember_var.get())
        last_path = str(self.storage_path) if remember else ""
        cleanup = CleanupConfig(
            old_days=old_days,
            large_mb=large_mb,
            duplicate_min_mb=duplicate_min_mb,
            remember_folder=remember,
            last_path=last_path,
        )
        self.config = replace(self.config, cleanup=cleanup)
        if self._persist_config():
            self.settings_status.configure(
                text=self.t("settings.saved"),
                fg=THEME["ok"],
            )
        else:
            self.settings_status.configure(
                text=self.t("settings.status.save_failed"),
                fg=THEME["warn"],
            )

    def _reset_settings(self) -> None:
        from tkinter import messagebox

        if not messagebox.askyesno(
            "AntiOS",
            self.t("settings.reset.confirm"),
        ):
            return

        self.config = replace(
            self.config,
            ui=UIConfig(),
            cleanup=CleanupConfig(),
        )
        self.language_setting = self.config.ui.language
        self.language = normalize_language(detect_language())
        self.tr = Translator(self.language)
        self.theme_mode = self.config.ui.theme
        self.resolved_theme = _apply_theme_palette(self.theme_mode)
        self.storage_path = default_scan_path()
        self._persist_config()
        self._rebuild_ui("settings")
        if hasattr(self, "settings_status"):
            self.settings_status.configure(
                text=self.t("settings.reset.done"),
                fg=THEME["ok"],
            )

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
            fg = THEME["accent_text"]
            active_bg = THEME["accent_hover"]
        elif kind == "danger":
            bg = THEME["warn"]
            fg = "#FFFFFF"
            active_bg = THEME["warn"]
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
        setting = self.language_display_to_code.get(selected)
        if not setting or setting == self.language_setting:
            return

        self.language_setting = setting
        self.language = normalize_language(
            detect_language() if setting == "auto" else setting
        )
        self.tr = Translator(self.language)
        self.config = replace(
            self.config,
            ui=UIConfig(
                language=self.language_setting,
                theme=self.theme_mode,
            ),
        )
        self._persist_config()
        self._rebuild_ui("settings")

    def _on_theme_selected(self, _event: Any = None) -> None:
        selected = self.theme_var.get()
        mode = self.theme_display_to_code.get(selected)
        if not mode or mode == self.theme_mode:
            return

        self.theme_mode = mode
        self.resolved_theme = _apply_theme_palette(mode)
        self.config = replace(
            self.config,
            ui=UIConfig(
                language=self.language_setting,
                theme=self.theme_mode,
            ),
        )
        self._persist_config()
        self._rebuild_ui("settings")

    def show_page(self, name: str) -> None:
        if name not in self.pages:
            return

        titles = {
            "overview": (self.t("nav.overview"), self.t("page.overview.subtitle")),
            "security": (self.t("nav.security"), self.t("page.security.subtitle")),
            "antivirus": (self.t("nav.antivirus"), self.t("av.subtitle")),
            "startup": (self.t("nav.startup"), self.t("page.startup.subtitle")),
            "system": (self.t("nav.system"), self.t("page.system.subtitle")),
            "cleanup": (self.t("nav.cleanup"), self.t("page.cleanup.subtitle")),
            "settings": (self.t("nav.settings"), self.t("page.settings.subtitle")),
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

        if hasattr(self, "settings_button"):
            settings_selected = name == "settings"
            self.settings_button.configure(
                bg=THEME["surface_alt"]
                if settings_selected
                else THEME["sidebar"],
                fg=THEME["text"]
                if settings_selected
                else THEME["muted"],
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
        self.antivirus_panel.render_provider_status(health)
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

        payload = dict(self.data)
        if self.storage_result is not None:
            payload["storage_cleanup"] = self.storage_result
        if self.antivirus_result is not None:
            payload["antivirus"] = self.antivirus_result

        Path(target).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
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
        description="AntiOS Antivirus & Windows Diagnostics Dashboard"
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Validate dashboard imports without opening a window.",
    )
    parser.add_argument(
        "--ui-self-test",
        action="store_true",
        help="Build the hidden Windows GUI, Antivirus and Settings pages, then exit.",
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
    if args.ui_self_test:
        if not is_windows():
            return 0
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        dashboard = Dashboard(
            root,
            language=args.lang,
            auto_refresh=False,
        )
        dashboard.show_page("settings")
        root.update_idletasks()
        dashboard.show_page("antivirus")
        root.update_idletasks()
        root.destroy()
        return 0
    from .elevation import ensure_administrator
    elevation_status = ensure_administrator(args.lang)
    if elevation_status is not None:
        return elevation_status
    return launch(args.lang)
