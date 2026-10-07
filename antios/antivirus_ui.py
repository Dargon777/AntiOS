"""Modern Antivirus page.

The primary surface is intentionally consumer-facing: protection state, scanning,
Resident Guard, results and quarantine. Engine/provider controls live under the
collapsed advanced section instead of competing with the main actions.
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .quarantine import Quarantine
from .scan_process import run_scan_process
from .windows_antivirus import defender_action


_ACTIVE_GUARD_STATES = {
    "starting",
    "scanning",
    "monitoring",
    "degraded",
    "attention",
    "unresponsive",
}
_HEALTHY_GUARD_STATES = {"monitoring", "scanning"}


class AntivirusPanel:
    def __init__(self, app: Any, parent: Any, palette: dict) -> None:
        self.app, self.parent, self.palette = app, parent, palette
        self.rows: dict[str, dict] = {}
        self.items: dict[str, dict] = {}
        self.mode = "findings"
        self.after_id = None
        self.last_guard_probe = 0.0
        self.last_protection_probe = 0.0
        self.protection_probe_busy = False
        self.layered_active = False
        self.guard_state = "not-running"
        self.advanced_visible = False
        self.labels: list[Any] = []
        self.buttons: list[Any] = []
        # ClamAV is the product engine. AMSI remains a CLI compatibility path.
        self.engine_var = self.app.tk.StringVar(value="clamav")
        self.app.antivirus_engine = "clamav"
        self._build()
        parent.bind("<Destroy>", self._destroy, add="+")
        parent.bind("<Configure>", self._resize, add="+")
        self._render_result()
        self._render_items()
        self._set_busy()
        self._poll()

    def t(self, key: str, **values: Any) -> str:
        return self.app.t("av." + key, **values)

    def _card(self, parent: Any, *, bg: str | None = None) -> Any:
        return self.app.tk.Frame(
            parent,
            bg=bg or self.palette["surface"],
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            bd=0,
        )

    def _label(
        self,
        parent: Any,
        text: str,
        *,
        bg: str | None = None,
        fg: str | None = None,
        font: tuple | None = None,
        **kwargs: Any,
    ) -> Any:
        label = self.app.tk.Label(
            parent,
            text=text,
            bg=bg or self.palette["bg"],
            fg=fg or self.palette["muted"],
            anchor="w",
            justify="left",
            font=font or ("Segoe UI", 9),
            **kwargs,
        )
        self.labels.append(label)
        return label

    def _resize(self, event: Any) -> None:
        if event.widget != self.parent or event.width <= 150:
            return
        wrap = max(180, event.width - 100)
        for label in self.labels:
            try:
                label.configure(wraplength=wrap)
            except Exception:
                pass
        try:
            self.scan_path_label.configure(wraplength=max(220, int(event.width * 0.48)))
        except Exception:
            pass

    def _build(self) -> None:
        tk, outer = self.app.tk, self.parent
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(2, weight=1, minsize=210)

        # Protection hero.
        self.hero = self._card(outer)
        self.hero.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.hero.grid_columnconfigure(1, weight=1)

        self.hero_accent = tk.Frame(self.hero, bg=self.palette["warn"], width=4)
        self.hero_accent.grid(row=0, column=0, rowspan=2, sticky="ns")

        hero_text = tk.Frame(self.hero, bg=self.palette["surface"])
        hero_text.grid(row=0, column=1, sticky="nsew", padx=20, pady=17)

        kicker_row = tk.Frame(hero_text, bg=self.palette["surface"])
        kicker_row.pack(fill="x")
        self.protection_dot = tk.Label(
            kicker_row,
            text="●",
            bg=self.palette["surface"],
            fg=self.palette["warn"],
            font=("Segoe UI", 10, "bold"),
        )
        self.protection_dot.pack(side="left", padx=(0, 7))
        self.protection_kicker = tk.Label(
            kicker_row,
            text=self.t("resident_title"),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI Semibold", 8),
        )
        self.protection_kicker.pack(side="left")

        self.protection_title = tk.Label(
            hero_text,
            text=self.t("protection_off"),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 19, "bold"),
            anchor="w",
        )
        self.protection_title.pack(fill="x", pady=(4, 3))
        self.protection_detail = tk.Label(
            hero_text,
            text=self.t("protection_off_detail"),
            bg=self.palette["surface"],
            fg=self.palette["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
        )
        self.protection_detail.pack(fill="x")

        self.engine_chip = tk.Label(
            self.hero,
            text=self.t("managed_engine"),
            bg=self.palette["surface_alt"],
            fg=self.palette["muted"],
            font=("Segoe UI Semibold", 8),
            padx=12,
            pady=7,
        )
        self.engine_chip.grid(row=0, column=2, sticky="ne", padx=18, pady=18)

        # Primary work cards.
        primary = tk.Frame(outer, bg=self.palette["bg"])
        primary.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        primary.grid_columnconfigure(0, weight=3, uniform="av-primary")
        primary.grid_columnconfigure(1, weight=2, uniform="av-primary")

        scan_card = self._card(primary)
        scan_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        scan_body = tk.Frame(scan_card, bg=self.palette["surface"])
        scan_body.pack(fill="both", expand=True, padx=18, pady=15)

        tk.Label(
            scan_body,
            text=self.t("scan_title"),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            scan_body,
            text=self.t("scan_hint"),
            bg=self.palette["surface"],
            fg=self.palette["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(2, 11))

        target = tk.Frame(scan_body, bg=self.palette["surface_alt"])
        target.pack(fill="x", pady=(0, 10))
        target_left = tk.Frame(target, bg=self.palette["surface_alt"])
        target_left.pack(side="left", fill="x", expand=True, padx=12, pady=9)
        tk.Label(
            target_left,
            text=self.t("scan_target"),
            bg=self.palette["surface_alt"],
            fg=self.palette["muted_2"],
            font=("Segoe UI Semibold", 8),
        ).pack(anchor="w")
        self.scan_path_label = tk.Label(
            target_left,
            text=str(self.app.antivirus_path),
            bg=self.palette["surface_alt"],
            fg=self.palette["text"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
        )
        self.scan_path_label.pack(fill="x", pady=(2, 0))
        # Backward-compatible alias used by older tests/integrations.
        self._path_text = self.scan_path_label

        choose = tk.Frame(scan_body, bg=self.palette["surface"])
        choose.pack(fill="x")
        file_button = self.app._button(
            choose, self.t("file"), lambda: self._choose(False), kind="secondary"
        )
        file_button.pack(side="left")
        folder_button = self.app._button(
            choose, self.t("folder"), lambda: self._choose(True), kind="secondary"
        )
        folder_button.pack(side="left", padx=(7, 0))
        self.scan_button = self.app._button(
            choose, self.t("scan"), self._scan, kind="primary"
        )
        self.scan_button.pack(side="right")
        self.cancel_button = self.app._button(
            choose, self.t("stop"), self._cancel, kind="danger"
        )
        self.cancel_button.pack(side="right", padx=(0, 7))
        self.buttons.extend((file_button, folder_button, self.scan_button))

        self.status = tk.Label(
            scan_body,
            text=self.t("ready"),
            bg=self.palette["surface"],
            fg=self.palette["muted"],
            font=("Segoe UI", 8),
            anchor="w",
            justify="left",
        )
        self.status.pack(fill="x", pady=(10, 0))

        guard_card = self._card(primary)
        guard_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        guard_body = tk.Frame(guard_card, bg=self.palette["surface"])
        guard_body.pack(fill="both", expand=True, padx=18, pady=15)

        tk.Label(
            guard_body,
            text=self.t("resident_title"),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")
        tk.Label(
            guard_body,
            text=self.t("resident_hint"),
            bg=self.palette["surface"],
            fg=self.palette["muted"],
            font=("Segoe UI", 9),
            justify="left",
        ).pack(anchor="w", pady=(2, 12))

        self.guard_state_label = tk.Label(
            guard_body,
            text=self.t("guard_inactive_short"),
            bg=self.palette["surface"],
            fg=self.palette["warn"],
            font=("Segoe UI Semibold", 10),
            anchor="w",
        )
        self.guard_state_label.pack(fill="x", pady=(0, 10))

        guard_actions = tk.Frame(guard_body, bg=self.palette["surface"])
        guard_actions.pack(fill="x")
        self.guard_start_button = self.app._button(
            guard_actions, self.t("guard_start"), self._guard_toggle, kind="primary"
        )
        self.guard_start_button.pack(side="left")
        self.incident_button = self.app._button(
            guard_actions, self.t("incident_viewer_button"), self._incident_history,
            kind="secondary"
        )
        self.incident_button.pack(side="left", padx=(7, 0))
        # Backward-compatible alias for integrations that referenced the old
        # Guard history button directly.
        self.guard_history_button = self.incident_button
        self.buttons.extend((self.guard_start_button, self.incident_button))

        self.guard_status = tk.Label(
            guard_body,
            text=self.t("guard_status", state="…", count=0),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI", 8),
            anchor="w",
        )
        self.guard_status.pack(fill="x", pady=(10, 0))

        # Results.
        results = self._card(outer)
        results.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        results.grid_rowconfigure(1, weight=1)
        results.grid_columnconfigure(0, weight=1)

        results_header = tk.Frame(results, bg=self.palette["surface"])
        results_header.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 8))
        tabs = tk.Frame(results_header, bg=self.palette["surface"])
        tabs.pack(side="left")

        self.findings_tab = self.app._button(
            tabs, self.t("findings"), lambda: self._show("findings"), kind="secondary"
        )
        self.findings_tab.pack(side="left")
        self.vault_tab = self.app._button(
            tabs, self.t("vault"), lambda: self._show("vault"), kind="secondary"
        )
        self.vault_tab.pack(side="left", padx=(6, 0))

        self.results_hint = tk.Label(
            results_header,
            text=self.t("results_empty"),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI", 8),
            anchor="e",
        )
        self.results_hint.pack(side="right")

        table = tk.Frame(results, bg=self.palette["surface"])
        table.grid(row=1, column=0, sticky="nsew", padx=1, pady=(0, 1))
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)
        self.tree = self.app.ttk.Treeview(
            table,
            columns=("kind", "name", "path"),
            show="headings",
            height=8,
            selectmode="browse",
            style="AntiOS.Treeview",
        )
        for name, width in (("kind", 110), ("name", 250), ("path", 410)):
            self.tree.heading(name, text=self.t("column_" + name))
            self.tree.column(name, width=width, stretch=name == "path")
        vertical = tk.Scrollbar(table, command=self.tree.yview, width=10, bd=0)
        horizontal = tk.Scrollbar(table, orient="horizontal", command=self.tree.xview, bd=0)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._selection_changed())
        self.tree.bind("<Double-1>", lambda _event: self._details())

        actions = tk.Frame(outer, bg=self.palette["bg"])
        actions.grid(row=3, column=0, sticky="ew")

        self.quarantine_button = self.app._button(
            actions, self.t("quarantine"), self._quarantine, kind="secondary"
        )
        self.quarantine_button.pack(side="left")
        self.restore_button = self.app._button(
            actions, self.t("restore"), self._restore, kind="secondary"
        )
        self.restore_button.pack(side="left", padx=(7, 0))

        self.advanced_button = self.app._button(
            actions, self.t("advanced"), self._toggle_advanced, kind="secondary"
        )
        self.advanced_button.pack(side="right")
        self.export_button = self.app._button(
            actions, self.t("export"), self._export, kind="secondary"
        )
        self.export_button.pack(side="right", padx=(0, 7))

        # Hidden advanced area.
        self.advanced_frame = self._card(outer)
        advanced = tk.Frame(self.advanced_frame, bg=self.palette["surface"])
        advanced.pack(fill="both", expand=True, padx=18, pady=14)

        advanced_header = tk.Frame(advanced, bg=self.palette["surface"])
        advanced_header.pack(fill="x")
        advanced_text = tk.Frame(advanced_header, bg=self.palette["surface"])
        advanced_text.pack(side="left", fill="x", expand=True)
        tk.Label(
            advanced_text,
            text=self.t("advanced_title"),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
            advanced_text,
            text=self.t("advanced_hint"),
            bg=self.palette["surface"],
            fg=self.palette["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", pady=(2, 10))
        close_advanced = self.app._button(
            advanced_header,
            self.t("advanced_hide"),
            self._toggle_advanced,
            kind="secondary",
        )
        close_advanced.pack(side="right", padx=(12, 0))

        engine_row = tk.Frame(advanced, bg=self.palette["surface"])
        engine_row.pack(fill="x", pady=(0, 8))
        tk.Label(
            engine_row,
            text=self.t("engine"),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI Semibold", 8),
            width=18,
            anchor="w",
        ).pack(side="left")
        self.provider_status = tk.Label(
            engine_row,
            text=self.t("managed_engine"),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.provider_status.pack(side="left", fill="x", expand=True)

        signature_row = tk.Frame(advanced, bg=self.palette["surface"])
        signature_row.pack(fill="x", pady=(0, 8))
        tk.Label(
            signature_row,
            text=self.t("signature_title"),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI Semibold", 8),
            width=18,
            anchor="w",
        ).pack(side="left")
        self.path_label = tk.Label(
            signature_row,
            text=(
                str(self.app.antivirus_signatures)
                if self.app.antivirus_signatures
                else self.t("signatures_builtin")
            ),
            bg=self.palette["surface"],
            fg=self.palette["text"],
            font=("Segoe UI", 8),
            anchor="w",
            justify="left",
        )
        self.path_label.pack(side="left", fill="x", expand=True)
        signature_button = self.app._button(
            signature_row, self.t("signatures"), self._choose_signatures, kind="secondary"
        )
        signature_button.pack(side="right", padx=(10, 0))
        self.buttons.append(signature_button)

        defender_row = tk.Frame(advanced, bg=self.palette["surface"])
        defender_row.pack(fill="x")
        tk.Label(
            defender_row,
            text=self.t("defender_tools"),
            bg=self.palette["surface"],
            fg=self.palette["muted_2"],
            font=("Segoe UI Semibold", 8),
            width=18,
            anchor="w",
        ).pack(side="left")
        defender_buttons = tk.Frame(defender_row, bg=self.palette["surface"])
        defender_buttons.pack(side="left")
        for action in ("quick", "full", "update"):
            button = self.app._button(
                defender_buttons,
                self.t("defender_" + action),
                lambda a=action: self._defender(a),
                kind="secondary",
            )
            button.pack(side="left", padx=(0, 6))
            self.buttons.append(button)

        if self.app.data:
            self.render_provider_status(self.app.data.get("health", {}))
        self._sync_tabs()

    def _toggle_advanced(self) -> None:
        self.advanced_visible = not self.advanced_visible
        if self.advanced_visible:
            self.advanced_frame.place(
                relx=0,
                rely=1,
                anchor="sw",
                relwidth=1,
                height=190,
            )
            self.advanced_frame.lift()
            self.advanced_button.configure(text=self.t("advanced_hide"))
        else:
            self.advanced_frame.place_forget()
            self.advanced_button.configure(text=self.t("advanced"))

    def render_provider_status(self, _health: dict) -> None:
        # Defender is intentionally not the primary antivirus status anymore.
        if not self.app.antivirus_result:
            self.provider_status.configure(text=self.t("managed_engine"))

    def _choose(self, folder: bool) -> None:
        from tkinter import filedialog

        choose = filedialog.askdirectory if folder else filedialog.askopenfilename
        selected = choose(
            initialdir=str(
                self.app.antivirus_path.parent
                if self.app.antivirus_path.is_file()
                else self.app.antivirus_path
            )
        )
        if selected:
            self.app.antivirus_path = Path(selected)
            self.scan_path_label.configure(text=str(self.app.antivirus_path))

    def _choose_signatures(self) -> None:
        from tkinter import filedialog
        from .antivirus import load_signatures

        selected = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not selected:
            return
        try:
            load_signatures(selected)
        except (OSError, ValueError) as exc:
            self._error(str(exc))
            return
        self.app.antivirus_signatures = Path(selected)
        self.path_label.configure(text=str(selected))

    def _run(
        self,
        kind: str,
        operation: Callable,
        *,
        cancelable: bool = False,
    ) -> None:
        if self.app.antivirus_busy:
            return
        self.app.antivirus_busy = True
        self.app.antivirus_cancelable = cancelable
        self.app.antivirus_cancel.clear()
        self.status.configure(text=self.t("working"), fg=self.palette["muted"])
        self._set_busy()

        def worker() -> None:
            try:
                value = operation()
                self.app.antivirus_queue.put((kind, value))
            except Exception as exc:
                self.app.antivirus_queue.put(("error", str(exc)))
            finally:
                self.app.antivirus_queue.put(("idle", None))

        threading.Thread(
            target=worker,
            daemon=kind not in {"scan", "quarantined", "restored"},
        ).start()

    def _scan(self) -> None:
        path, signatures = self.app.antivirus_path, self.app.antivirus_signatures
        engine = "clamav"
        self.app.antivirus_engine = engine
        self._run(
            "scan",
            lambda: run_scan_process(
                path,
                signature_path=signatures,
                engine=engine,
                require_verified_peer=(sys.platform == "win32"),
                cancelled=self.app.antivirus_cancel.is_set,
                progress=lambda data: self.app.antivirus_queue.put(("progress", data)),
            ),
            cancelable=True,
        )

    def _cancel(self) -> None:
        if self.app.antivirus_busy and self.app.antivirus_cancelable:
            self.app.antivirus_cancel.set()
            self.status.configure(text=self.t("stopping"))
            self.cancel_button.configure(state="disabled")

    def _guard_toggle(self) -> None:
        if self.guard_state in _ACTIVE_GUARD_STATES:
            self._guard_stop()
        else:
            self._guard_start()

    def _guard_start(self) -> None:
        from tkinter import messagebox

        if messagebox.askyesno("AntiOS Guard", self.t("guard_confirm")):
            self._run(
                "guard-action",
                lambda: self.app.set_resident_protection_enabled(True),
            )

    def _guard_stop(self) -> None:
        self._run(
            "guard-action",
            lambda: self.app.set_resident_protection_enabled(False),
        )

    def _incident_history(self) -> None:
        from .guard_state import read_incident_history

        self._run("incident-history", lambda: read_incident_history(limit=50))

    def _guard_history(self) -> None:
        # Compatibility alias: the old raw JSON popup is now the structured
        # Incident Viewer.
        self._incident_history()

    def _defender(self, action: str) -> None:
        from tkinter import messagebox

        if messagebox.askyesno("AntiOS", self.t("defender_confirm")):
            self._run("defender", lambda: defender_action(action))

    def _selected(self) -> dict | None:
        selected = self.tree.selection()
        source = self.rows if self.mode == "findings" else self.items
        return source.get(selected[0]) if selected else None

    def _quarantine(self) -> None:
        from tkinter import messagebox

        finding = self._selected()
        if (
            self.mode != "findings"
            or not finding
            or finding.get("kind") != "threat"
            or finding.get("quarantined")
        ):
            return
        if messagebox.askyesno(
            "AntiOS", self.t("quarantine_confirm", path=finding["path"])
        ):
            def isolate():
                vault = Quarantine()
                item = vault.add(finding, dry_run=False)
                return {
                    "item": item,
                    "items": vault.list_items(),
                    "finding": finding,
                }

            self._run("quarantined", isolate)

    def _restore(self) -> None:
        from tkinter import messagebox

        item = self._selected()
        if self.mode != "vault" or not item or item.get("error"):
            return
        if messagebox.askyesno(
            "AntiOS", self.t("restore_confirm", path=item["original_path"])
        ):
            def restore():
                vault = Quarantine()
                value = vault.restore(item["id"], dry_run=False)
                return {"restored": value, "items": vault.list_items()}

            self._run("restored", restore)

    def _sync_tabs(self) -> None:
        active = self.findings_tab if self.mode == "findings" else self.vault_tab
        inactive = self.vault_tab if self.mode == "findings" else self.findings_tab
        active.configure(
            bg=self.palette["surface_hover"],
            fg=self.palette["text"],
        )
        inactive.configure(
            bg=self.palette["surface_alt"],
            fg=self.palette["text"],
        )

    def _show(self, mode: str) -> None:
        self.mode = mode
        self._sync_tabs()
        if mode == "vault" and not self.app.antivirus_busy:
            self._run("items", lambda: Quarantine().list_items())
        else:
            self._render_result()

    def _render_items(self) -> None:
        if self.mode != "vault":
            return
        self.tree.delete(*self.tree.get_children())
        self.items = {}
        for index, item in enumerate(self.app.antivirus_items):
            key = str(index)
            self.items[key] = item
            self.tree.insert(
                "",
                "end",
                iid=key,
                values=(
                    self.t("error_kind") if item.get("error") else self.t(item.get("state", "vault")),
                    item.get("name", item.get("error", "")),
                    item.get("original_path", item["id"]),
                ),
            )
        count = len(self.items)
        self.results_hint.configure(
            text=self.t("result_count", count=count) if count else self.t("vault_empty")
        )
        self._selection_changed()

    def _render_result(self) -> None:
        result = self.app.antivirus_result
        if result:
            metadata = result.get("engine", {})
            engine_text = metadata.get("version") or self.t("managed_engine")
            freshness = metadata.get("database_freshness")
            if freshness:
                engine_text += " · " + self.t("db_" + freshness)
            if metadata.get("detail"):
                engine_text += " · " + metadata["detail"]
            self.provider_status.configure(text=engine_text)

            summary = result["summary"]
            verdict_key = "stopped" if summary.get("cancelled") else result["verdict"]
            pieces = [
                self.t(verdict_key),
                self.t(
                    "summary_result",
                    scanned=summary["files_scanned"],
                    threats=summary["threats"],
                ),
            ]
            if summary["skipped"] or summary["errors"]:
                pieces.append(
                    self.t(
                        "summary_issues",
                        skipped=summary["skipped"],
                        errors=summary["errors"],
                    )
                )
            if result["coverage"] == "limited":
                pieces.append(self.t("limited"))
            self.status.configure(
                text=" · ".join(pieces),
                fg=self.palette["warn"] if summary["threats"] or summary["errors"] else self.palette["muted"],
            )

        if self.mode != "findings":
            return
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        values = (
            result["findings"]
            + [dict(item, kind="issue", name=item["reason"]) for item in result["issues"]]
            if result
            else []
        )
        for index, finding in enumerate(values[:1000]):
            key = str(index)
            self.rows[key] = finding
            kind = "isolated" if finding.get("quarantined") else finding["kind"]
            self.tree.insert(
                "",
                "end",
                iid=key,
                values=(self.t(kind), finding["name"], finding["path"]),
            )
        count = len(self.rows)
        self.results_hint.configure(
            text=self.t("result_count", count=count) if count else self.t("results_empty")
        )
        self._selection_changed()

    def _selection_changed(self) -> None:
        selected = self._selected()
        active = not self.app.antivirus_busy and selected is not None
        self.quarantine_button.configure(
            state=(
                "normal"
                if active
                and self.mode == "findings"
                and selected.get("kind") == "threat"
                and not selected.get("quarantined")
                else "disabled"
            )
        )
        self.restore_button.configure(
            state=(
                "normal"
                if active
                and self.mode == "vault"
                and not selected.get("error")
                else "disabled"
            )
        )

    def _details(self) -> None:
        from tkinter import messagebox

        selected = self._selected()
        if selected:
            messagebox.showinfo(
                "AntiOS",
                json.dumps(selected, indent=2, ensure_ascii=False),
            )

    def _export(self) -> None:
        from tkinter import filedialog

        if not self.app.antivirus_result:
            return
        target = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile="antios-antivirus.json",
            filetypes=[("JSON", "*.json")],
        )
        if target:
            try:
                Path(target).write_text(
                    json.dumps(
                        self.app.antivirus_result,
                        indent=2,
                        ensure_ascii=False,
                    ),
                    encoding="utf-8",
                )
            except OSError as exc:
                self._error(str(exc))

    def _error(self, message: str) -> None:
        self.status.configure(
            text=self.t("error", error=message),
            fg=self.palette["warn"],
        )

    def _sync_guard_ui(self, value: dict) -> None:
        state = str(value.get("state") or "unavailable")
        self.guard_state = state
        self.app.set_protection_state(value)
        healthy = state in _HEALTHY_GUARD_STATES

        if healthy:
            color = self.palette["ok"]
            title = self.t("protection_active")
            detail = self.t("protection_layered_detail") if self.layered_active else self.t("protection_active_detail")
            short = self.t("guard_active_short")
        elif state == "starting":
            color = self.palette["info"]
            title = self.t("protection_starting")
            detail = self.t("protection_starting_detail")
            short = self.t("guard_state_starting")
        elif state == "attention":
            color = self.palette["warn"]
            title = self.t("protection_attention")
            detail = self.t("protection_attention_detail")
            short = self.t("guard_state_attention")
        else:
            color = self.palette["warn"]
            title = self.t("protection_off")
            detail = self.t("protection_off_detail")
            short = self.t("guard_state_" + state)

        self.hero_accent.configure(bg=color)
        self.protection_dot.configure(fg=color)
        self.protection_title.configure(text=title)
        self.protection_detail.configure(text=detail)
        self.guard_state_label.configure(text=short, fg=color)
        behavior = value.get("behavior") if isinstance(value.get("behavior"), dict) else {}
        behavior_state = str(behavior.get("state") or "unavailable")
        behavior_label = self.t(
            "behavior_" + behavior_state
            if behavior_state in {"normal", "attention", "alert"}
            else "behavior_unavailable"
        )
        risk = value.get("risk") if isinstance(value.get("risk"), dict) else {}
        last_risk = risk.get("last") if isinstance(risk.get("last"), dict) else {}
        risk_class = str(last_risk.get("classification") or "unavailable")
        risk_label = self.t(
            "risk_" + risk_class
            if risk_class in {
                "low", "observe", "elevated", "high",
                "critical-behavior", "confirmed-threat"
            }
            else "risk_unavailable"
        )
        incidents = value.get("incidents") if isinstance(value.get("incidents"), dict) else {}
        latest_incident = incidents.get("latest") if isinstance(incidents.get("latest"), dict) else {}
        incident_state = str(incidents.get("state") or "unavailable")
        incident_label = self.t(
            "incident_" + incident_state
            if incident_state in {"normal", "attention", "alert"}
            else "incident_unavailable"
        )
        self.guard_status.configure(
            text=self.t(
                "guard_status",
                state=self.t("guard_state_" + state),
                count=value.get("detections", 0),
            ) + "\n" + self.t(
                "behavior_status",
                state=behavior_label,
                score=behavior.get("highest_score", 0),
                count=behavior.get("recent_findings", 0),
            ) + "\n" + self.t(
                "risk_status",
                state=risk_label,
                score=last_risk.get("score", 0),
            ) + "\n" + self.t(
                "incident_status",
                state=incident_label,
                count=incidents.get("active_incidents", 0),
                score=incidents.get("highest_score", 0),
                nodes=latest_incident.get("node_count", 0),
                edges=latest_incident.get("edge_count", 0),
            )
        )

        running = state in _ACTIVE_GUARD_STATES
        self.guard_start_button.configure(
            text=self.t("guard_stop") if running else self.t("guard_start")
        )

    def _sync_protection_ui(self, value: dict) -> None:
        caps = value.get("capabilities") if isinstance(value, dict) else {}
        if not isinstance(caps, dict):
            caps = {}
        layered = bool(
            caps.get("standalone_detection_engine") and
            caps.get("layered_with_defender") and
            (
                caps.get("resident_post_write_detection") or
                caps.get("pre_execution_blocking")
            )
        )
        self.layered_active = layered
        self.engine_chip.configure(
            text=self.t("layered_engine") if layered else self.t("managed_engine"),
            fg=self.palette["ok"] if layered else self.palette["muted"],
        )
        if self.guard_state in _HEALTHY_GUARD_STATES:
            self.protection_detail.configure(
                text=self.t("protection_layered_detail") if layered
                else self.t("protection_active_detail")
            )

    def _set_busy(self) -> None:
        busy = self.app.antivirus_busy
        for button in self.buttons:
            button.configure(state="disabled" if busy else "normal")

        guard_companion_missing = (
            getattr(sys, "frozen", False)
            and not (Path(sys.executable).parent / "AntiOS-Guard.exe").is_file()
        )
        if (
            not busy
            and guard_companion_missing
            and self.guard_state not in _ACTIVE_GUARD_STATES
        ):
            self.guard_start_button.configure(state="disabled")

        self.cancel_button.configure(
            state=(
                "normal"
                if busy
                and self.app.antivirus_cancelable
                and not self.app.antivirus_cancel.is_set()
                else "disabled"
            )
        )
        self._selection_changed()

    def _poll(self) -> None:
        if (
            os.name == "nt"
            and time.monotonic() - self.last_protection_probe >= 20
            and not self.protection_probe_busy
        ):
            self.last_protection_probe = time.monotonic()
            self.protection_probe_busy = True

            def probe_protection() -> None:
                from .protection import collect_protection_status

                try:
                    value = collect_protection_status()
                except Exception as exc:
                    value = {"error": str(exc)}
                self.app.antivirus_queue.put(("protection-state", value))

            threading.Thread(target=probe_protection, daemon=True).start()

        if (
            time.monotonic() - self.last_guard_probe >= 3
            and not self.app.guard_probe_busy
        ):
            self.last_guard_probe = time.monotonic()
            self.app.guard_probe_busy = True

            def probe_guard() -> None:
                from .guard_state import read_guard_state

                try:
                    value = read_guard_state()
                except Exception as exc:
                    value = {"state": "unavailable", "detail": str(exc)}
                self.app.antivirus_queue.put(("guard-state", value))

            threading.Thread(target=probe_guard, daemon=True).start()

        for _ in range(100):
            try:
                kind, value = self.app.antivirus_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "guard-state":
                self.app.guard_probe_busy = False
                self._sync_guard_ui(value)
                self._set_busy()
            elif kind == "protection-state":
                self.protection_probe_busy = False
                self._sync_protection_ui(value)
            elif kind == "guard-action":
                self.last_guard_probe = 0
            elif kind == "incident-history":
                from .incident_viewer import IncidentViewer

                IncidentViewer(self.app, self.palette, value, self.t)
            elif kind == "idle":
                self.app.antivirus_busy = False
                self._set_busy()
            elif kind == "error":
                self._error(value)
            elif kind == "progress" and not self.app.antivirus_cancel.is_set():
                self.status.configure(
                    text=self.t("progress", count=value["files_scanned"]),
                    fg=self.palette["muted"],
                )
            elif kind == "scan":
                self.app.antivirus_result = value
                self.mode = "findings"
                self._sync_tabs()
                self._render_result()
            elif kind == "defender":
                self.status.configure(
                    text=self.t("defender_done"),
                    fg=self.palette["muted"],
                )
                self.app.refresh()
            elif kind in {"quarantined", "restored"}:
                self.app.antivirus_items = value["items"]
                if kind == "quarantined":
                    value["finding"]["quarantined"] = value["item"]["id"]
                elif self.app.antivirus_result:
                    for finding in self.app.antivirus_result["findings"]:
                        if finding.get("quarantined") == value["restored"]["id"]:
                            finding.pop("quarantined")
                self._render_result()
                self._render_items()
                self.status.configure(
                    text=self.t("done"),
                    fg=self.palette["muted"],
                )
            elif kind == "items":
                self.app.antivirus_items = value
                self._render_items()
                self.status.configure(
                    text=self.t("ready"),
                    fg=self.palette["muted"],
                )

        self.after_id = self.app.root.after(100, self._poll)

    def _destroy(self, event: Any) -> None:
        if event.widget == self.parent and self.after_id is not None:
            self.app.root.after_cancel(self.after_id)
            self.after_id = None
