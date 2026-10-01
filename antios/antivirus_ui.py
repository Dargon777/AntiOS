"""Antivirus page. Worker threads communicate through a queue, never Tk calls."""
from __future__ import annotations

import json
import queue
import threading
from pathlib import Path
from typing import Any, Callable

from .antivirus import scan_files
from .quarantine import Quarantine, default_quarantine_path
from .windows_antivirus import defender_action


class AntivirusPanel:
    def __init__(self, app: Any, parent: Any, palette: dict) -> None:
        self.app, self.parent, self.palette = app, parent, palette
        self.rows: dict[str, dict] = {}
        self.items: dict[str, dict] = {}
        self.mode = "findings"
        self.after_id = None
        self.labels: list[Any] = []
        self._build()
        parent.bind("<Destroy>", self._destroy, add="+")
        parent.bind("<Configure>", self._resize, add="+")
        self._render_result()
        self._render_items()
        self._set_busy()
        self._poll()

    def t(self, key: str, **values: Any) -> str:
        return self.app.t("av." + key, **values)

    def _label(self, parent: Any, text: str, **kwargs: Any) -> Any:
        label = self.app.tk.Label(parent, text=text, bg=self.palette["bg"],
                                 fg=self.palette["muted"], anchor="w", justify="left",
                                 font=("Segoe UI", 9), **kwargs)
        self.labels.append(label)
        return label

    def _resize(self, event: Any) -> None:
        if event.widget == self.parent and event.width > 150:
            for label in self.labels:
                label.configure(wraplength=max(100, event.width - 8))

    def _build(self) -> None:
        tk, p = self.app.tk, self.parent
        self._label(p, self.t("note"), wraplength=810).pack(fill="x", pady=(0, 10))
        self.provider_status = self._label(p, self.t("provider_unknown"))
        self.provider_status.pack(fill="x", pady=(0, 10))
        self._path_text = self._label(p, str(self.app.antivirus_path), wraplength=810)
        self._path_text.pack(fill="x", pady=(0, 5))
        self.path_label = self._label(p, str(self.app.antivirus_signatures) if self.app.antivirus_signatures else self.t("signatures_builtin"))
        self.path_label.pack(fill="x", pady=(0, 8))
        controls = tk.Frame(p, bg=self.palette["bg"])
        controls.pack(fill="x", pady=(0, 10))
        self.buttons: list[Any] = []
        specs = [("file", lambda: self._choose(False)), ("folder", lambda: self._choose(True)),
                 ("signatures", self._choose_signatures), ("scan", self._scan)]
        for key, callback in specs:
            button = self.app._button(controls, self.t(key), callback,
                                      kind="primary" if key == "scan" else "secondary")
            button.pack(side="left", padx=(0, 6))
            self.buttons.append(button)
        self.cancel_button = self.app._button(controls, self.t("stop"), self._cancel, kind="secondary")
        self.cancel_button.pack(side="left")

        defender = tk.Frame(p, bg=self.palette["bg"])
        defender.pack(fill="x", pady=(0, 8))
        for action in ("quick", "full", "update"):
            button = self.app._button(defender, self.t("defender_" + action),
                                      lambda a=action: self._defender(a), kind="secondary")
            button.pack(side="left", padx=(0, 6))
            self.buttons.append(button)
        self.status = self._label(p, self.t("ready"), wraplength=810)
        self.status.pack(fill="x", pady=(0, 10))

        tabs = tk.Frame(p, bg=self.palette["bg"])
        tabs.pack(fill="x", pady=(0, 6))
        for mode in ("findings", "vault"):
            self.app._button(tabs, self.t(mode), lambda m=mode: self._show(m),
                             kind="secondary").pack(side="left", padx=(0, 6))
        table = tk.Frame(p, bg=self.palette["bg"])
        table.pack(fill="both", expand=True)
        table.grid_rowconfigure(0, weight=1)
        table.grid_columnconfigure(0, weight=1)
        self.tree = self.app.ttk.Treeview(table, columns=("kind", "name", "path"),
                                         show="headings", height=7, selectmode="browse",
                                         style="AntiOS.Treeview")
        for name, width in (("kind", 100), ("name", 230), ("path", 380)):
            self.tree.heading(name, text=self.t("column_" + name))
            self.tree.column(name, width=width, stretch=name == "path")
        vertical = tk.Scrollbar(table, command=self.tree.yview)
        horizontal = tk.Scrollbar(table, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._selection_changed())
        self.tree.bind("<Double-1>", lambda _event: self._details())
        actions = tk.Frame(p, bg=self.palette["bg"])
        actions.pack(side="bottom", fill="x", pady=(10, 0), before=table)
        self.quarantine_button = self.app._button(actions, self.t("quarantine"), self._quarantine, kind="secondary")
        self.quarantine_button.pack(side="left", padx=(0, 6))
        self.restore_button = self.app._button(actions, self.t("restore"), self._restore, kind="secondary")
        self.restore_button.pack(side="left", padx=(0, 6))
        self.export_button = self.app._button(actions, self.t("export"), self._export, kind="secondary")
        self.export_button.pack(side="right")
        if self.app.data:
            self.render_provider_status(self.app.data.get("health", {}))

    def render_provider_status(self, health: dict) -> None:
        state = health.get("defender", {})
        realtime = state.get("real_time_protection")
        text = self.app.t("value.on" if realtime is True else "value.off" if realtime is False else "value.unknown")
        self.provider_status.configure(text=self.t("provider_status", state=text,
                                                   days=state.get("signature_age_days", "?")))

    def _choose(self, folder: bool) -> None:
        from tkinter import filedialog
        choose = filedialog.askdirectory if folder else filedialog.askopenfilename
        selected = choose(initialdir=str(self.app.antivirus_path.parent
                                         if self.app.antivirus_path.is_file() else self.app.antivirus_path))
        if selected:
            self.app.antivirus_path = Path(selected)
            # The first path label is independent of the signature label.
            self._path_text.configure(text=str(self.app.antivirus_path))

    def _choose_signatures(self) -> None:
        from tkinter import filedialog
        selected = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if selected:
            from .antivirus import load_signatures
            try:
                load_signatures(selected)
            except (OSError, ValueError) as exc:
                self._error(str(exc))
                return
            self.app.antivirus_signatures = Path(selected)
            self.path_label.configure(text=str(selected))

    def _run(self, kind: str, operation: Callable, *, cancelable: bool = False) -> None:
        if self.app.antivirus_busy:
            return
        self.app.antivirus_busy = True
        self.app.antivirus_cancelable = cancelable
        self.app.antivirus_cancel.clear()
        self.status.configure(text=self.t("working"))
        self._set_busy()

        def worker() -> None:
            try:
                value = operation()
                self.app.antivirus_queue.put((kind, value))
            except Exception as exc:
                self.app.antivirus_queue.put(("error", str(exc)))
            finally:
                self.app.antivirus_queue.put(("idle", None))

        threading.Thread(target=worker, daemon=kind not in {"quarantined", "restored"}).start()

    def _scan(self) -> None:
        path, signatures = self.app.antivirus_path, self.app.antivirus_signatures
        self._run("scan", lambda: scan_files(
            path, signature_path=signatures, excluded_paths=(default_quarantine_path(),),
            cancelled=self.app.antivirus_cancel.is_set,
            progress=lambda data: self.app.antivirus_queue.put(("progress", data)),
        ), cancelable=True)

    def _cancel(self) -> None:
        self.app.antivirus_cancel.set()

    def _defender(self, action: str) -> None:
        from tkinter import messagebox
        if messagebox.askyesno("AntiOS", self.t("defender_confirm")):
            self._run("defender", lambda: defender_action(action))

    def _selected(self) -> dict | None:
        selected = self.tree.selection()
        return (self.rows if self.mode == "findings" else self.items).get(selected[0]) if selected else None

    def _quarantine(self) -> None:
        from tkinter import messagebox
        finding = self._selected()
        if self.mode != "findings" or not finding or finding.get("kind") != "threat" or finding.get("quarantined"):
            return
        if messagebox.askyesno("AntiOS", self.t("quarantine_confirm", path=finding["path"])):
            def isolate():
                vault = Quarantine()
                item = vault.add(finding, dry_run=False)
                return {"item": item, "items": vault.list_items(), "finding": finding}
            self._run("quarantined", isolate)

    def _restore(self) -> None:
        from tkinter import messagebox
        item = self._selected()
        if self.mode != "vault" or not item or item.get("error"):
            return
        if messagebox.askyesno("AntiOS", self.t("restore_confirm", path=item["original_path"])):
            def restore():
                vault = Quarantine()
                value = vault.restore(item["id"], dry_run=False)
                return {"restored": value, "items": vault.list_items()}
            self._run("restored", restore)

    def _show(self, mode: str) -> None:
        self.mode = mode
        if mode == "vault" and not self.app.antivirus_busy:
            self._run("items", lambda: Quarantine().list_items())
        self._render_items() if mode == "vault" else self._render_result()

    def _render_items(self) -> None:
        if self.mode != "vault":
            return
        self.tree.delete(*self.tree.get_children())
        self.items = {}
        for index, item in enumerate(self.app.antivirus_items):
            key = str(index)
            self.items[key] = item
            self.tree.insert("", "end", iid=key, values=(self.t("error_kind") if item.get("error") else self.t(item.get("state", "vault")),
                item.get("name", item.get("error", "")), item.get("original_path", item["id"])))
        self._selection_changed()

    def _render_result(self) -> None:
        result = self.app.antivirus_result
        if result:
            self.status.configure(text=self.t("result", verdict=self.t(result["verdict"]),
                scanned=result["summary"]["files_scanned"], threats=result["summary"]["threats"],
                skipped=result["summary"]["skipped"], errors=result["summary"]["errors"]) +
                ("\n" + self.t("limited") if result["coverage"] == "limited" else ""))
        if self.mode != "findings":
            return
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        values = (result["findings"] + [dict(i, kind="issue", name=i["reason"]) for i in result["issues"]]) if result else []
        for index, finding in enumerate(values[:1000]):
            key = str(index)
            self.rows[key] = finding
            kind = "isolated" if finding.get("quarantined") else finding["kind"]
            self.tree.insert("", "end", iid=key, values=(self.t(kind), finding["name"], finding["path"]))
        self._selection_changed()

    def _selection_changed(self) -> None:
        selected = self._selected()
        active = not self.app.antivirus_busy and selected is not None
        self.quarantine_button.configure(state="normal" if active and self.mode == "findings"
            and selected.get("kind") == "threat" and not selected.get("quarantined") else "disabled")
        self.restore_button.configure(state="normal" if active and self.mode == "vault"
            and not selected.get("error") else "disabled")

    def _details(self) -> None:
        from tkinter import messagebox
        selected = self._selected()
        if selected:
            messagebox.showinfo("AntiOS", json.dumps(selected, indent=2, ensure_ascii=False))

    def _export(self) -> None:
        from tkinter import filedialog
        if not self.app.antivirus_result:
            return
        target = filedialog.asksaveasfilename(defaultextension=".json", initialfile="antios-antivirus.json",
                                             filetypes=[("JSON", "*.json")])
        if target:
            try:
                Path(target).write_text(json.dumps(self.app.antivirus_result, indent=2, ensure_ascii=False), encoding="utf-8")
            except OSError as exc:
                self._error(str(exc))

    def _error(self, message: str) -> None:
        self.status.configure(text=self.t("error", error=message))

    def _set_busy(self) -> None:
        busy = self.app.antivirus_busy
        for button in self.buttons:
            button.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy and self.app.antivirus_cancelable else "disabled")
        self._selection_changed()

    def _poll(self) -> None:
        for _ in range(100):
            try:
                kind, value = self.app.antivirus_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "idle":
                self.app.antivirus_busy = False
                self._set_busy()
            elif kind == "error":
                self._error(value)
            elif kind == "progress":
                self.status.configure(text=self.t("progress", count=value["files_scanned"]))
            elif kind == "scan":
                self.app.antivirus_result = value
                self.mode = "findings"
                self._render_result()
            elif kind == "defender":
                self.status.configure(text=self.t("defender_done"))
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
                self.status.configure(text=self.t("done"))
            elif kind == "items":
                self.app.antivirus_items = value
                self._render_items()
                self.status.configure(text=self.t("ready"))
        self.after_id = self.app.root.after(100, self._poll)

    def _destroy(self, event: Any) -> None:
        if event.widget == self.parent and self.after_id is not None:
            self.app.root.after_cancel(self.after_id)
            self.after_id = None
