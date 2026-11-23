"""Оконный интерфейс для статического анализатора. Запуск: python gui.py"""
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

from report import build_report, save_json
from analyzer.common import suspicious_apis

LEVEL_COLORS = {"high": "#d9534f", "medium": "#e08e0b", "low": "#3a87ad"}

# report.py отдаёт вердикт по-русски, здесь переводим его для интерфейса
VERDICT_EN = {"высокий": "high", "средний": "medium", "низкий": "low"}
VERDICT_COLORS = {"high": "#d9534f", "medium": "#e08e0b", "low": "#3c9a3c"}

# все подозрительные имена из таблицы (+ варианты Windows с суффиксами A/W)
SUSPICIOUS = set()
for table in suspicious_apis.values():
    for api in table:
        SUSPICIOUS |= {api, api + "A", api + "W"}


def format_text_en(r):
    """Текст для вкладки Overview на английском."""
    verdict = VERDICT_EN.get(r["verdict"], r["verdict"])
    lines = [
        f"File:        {r['file_name']} ({r['size']} bytes)",
        f"Path:        {r['file']}",
        f"Format:      {r['format']}, {r['bits']}-bit, arch {r['arch']}",
        f"Entry point: {r['entry_point']}",
        f"Risk:        {verdict} ({r['risk_score']} points)",
        f"Analyzed:    {r['analyzed_at']}",
        "",
        "--- Hashes ---",
    ]
    lines += [f"{name:7} {value}" for name, value in r["hashes"].items()]

    lines += ["", "--- Sections ---"]
    for s in r["sections"]:
        lines.append(f"{s['name']:22} {s['virtual_address']:>12} {s['size']:>10}  entropy {s['entropy']:.2f}")

    lines += ["", "--- Libraries ---"]
    lines += r["libraries"] or ["(none)"]

    lines += ["", "--- Findings ---"]
    if r["findings"]:
        lines += [f"[{f['level'].upper()}] {f['message']}" for f in r["findings"]]
    else:
        lines.append("Nothing suspicious found")

    if r["notes"]:
        lines += ["", "--- Notes ---"] + r["notes"]
    return "\n".join(lines)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Static Binary Analyzer")
        self.geometry("1000x650")
        self.minsize(750, 450)
        self.report = None

        self._build_top()
        self._build_bottom()   # низ пакуем до вкладок, чтобы он не пропадал при сжатии окна
        self._build_tabs()

    # ---------- построение окна ----------
    def _build_top(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="File:").pack(side="left")
        self.path_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<Return>", lambda e: self.run())

        ttk.Button(top, text="Browse…", command=self.browse).pack(side="left")
        ttk.Button(top, text="Analyze", command=self.run).pack(side="left", padx=(6, 0))

        self.verdict = tk.Label(self, text="Select a file and click «Analyze»",
                                anchor="w", padx=10, pady=6, font=("Segoe UI", 11, "bold"))
        self.verdict.pack(fill="x")

    def _build_bottom(self):
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(side="bottom", fill="x")
        self.save_btn = ttk.Button(bottom, text="Save JSON", command=self.save, state="disabled")
        self.save_btn.pack(side="right")
        self.status = ttk.Label(bottom, text="")
        self.status.pack(side="left")

    def _build_tabs(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=8)

        # Overview: обычный Text, чтобы можно было выделить и скопировать хеши
        frame = ttk.Frame(self.tabs)
        self.overview = tk.Text(frame, wrap="none", font=("Consolas", 10))
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.overview.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=self.overview.xview)
        self.overview.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        self.overview.pack(fill="both", expand=True)
        self.tabs.add(frame, text="Overview")

        frame, self.findings_tree = self._make_tree(
            ("level", "message"), ("Level", "Description"), (90, 800))
        self.tabs.add(frame, text="Findings")

        frame, self.sections_tree = self._make_tree(
            ("name", "va", "size", "entropy"), ("Section", "Address", "Size", "Entropy"), (150, 130, 120, 100))
        self.tabs.add(frame, text="Sections")

        frame, self.imports_tree = self._make_tree((), (), (), show="tree")
        self.tabs.add(frame, text="Imports")

        for tree in (self.findings_tree, self.sections_tree, self.imports_tree):
            for level, color in LEVEL_COLORS.items():
                tree.tag_configure(level, foreground=color)

    def _make_tree(self, columns, headings, widths, show="headings"):
        frame = ttk.Frame(self.tabs)
        tree = ttk.Treeview(frame, columns=columns, show=show)
        for col, head, width in zip(columns, headings, widths):
            tree.heading(col, text=head)
            tree.column(col, width=width, anchor="w")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        return frame, tree

    # ---------- actions ----------
    def browse(self):
        path = filedialog.askopenfilename(
            title="Select a binary",
            filetypes=[("All files", "*.*"), ("PE", "*.exe *.dll *.sys"), ("ELF", "*.elf *.so *.bin")])
        if path:
            self.path_var.set(path)
            self.run()

    def run(self):
        # strip('"') — for the path copied using “Copy as Path” to work»
        path = self.path_var.get().strip().strip('"')
        if not path:
            messagebox.showwarning("No file", "Please enter a file path")
            return

        self.status.config(text="Analyzing…")
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            self.report = build_report(path)
        except Exception as e:
            self.report = None
            self.save_btn.config(state="disabled")
            self.status.config(text="Error")
            messagebox.showerror("Analysis error", f"{type(e).__name__}: {e}")
            return
        finally:
            self.config(cursor="")

        self.show(self.report)
        self.save_btn.config(state="normal")
        self.status.config(text=f"Done: {self.report['analyzed_at']}")

    def save(self):
        if not self.report:
            return
        out = filedialog.asksaveasfilename(
            defaultextension=".json",
            initialfile=Path(self.report["file_name"]).stem + "_report.json",
            filetypes=[("JSON", "*.json")])
        if out:
            save_json(self.report, out)
            self.status.config(text=f"Saved: {out}")

    # ---------- reports out ----------
    @staticmethod
    def _clear(tree):
        tree.delete(*tree.get_children())

    def show(self, r):
        verdict = VERDICT_EN.get(r["verdict"], r["verdict"])
        self.verdict.config(
            text=f"{r['file_name']}  —  risk: {verdict} "
                 f"({r['risk_score']} points, findings: {len(r['findings'])})",
            fg=VERDICT_COLORS.get(verdict, "black"))

        self.overview.delete("1.0", "end")
        self.overview.insert("1.0", format_text_en(r))

        self._clear(self.findings_tree)
        if not r["findings"]:
            self.findings_tree.insert("", "end", values=("—", "Nothing suspicious found"))
        for f in r["findings"]:
            self.findings_tree.insert("", "end", values=(f["level"].upper(), f["message"]), tags=(f["level"],))

        self._clear(self.sections_tree)
        for s in r["sections"]:
            tag = ("high",) if s["entropy"] > 7.0 else ()
            self.sections_tree.insert("", "end", tags=tag,
                                      values=(s["name"], s["virtual_address"], s["size"], f"{s['entropy']:.2f}"))

        self._clear(self.imports_tree)
        if not r["imports"]:
            self.imports_tree.insert("", "end", text="(no imports)")
        for lib, funcs in r["imports"].items():
            bad = sum(fn in SUSPICIOUS for fn in funcs)
            label = f"{lib}  ({len(funcs)} functions" + (f", suspicious: {bad})" if bad else ")")
            node = self.imports_tree.insert("", "end", text=label, open=bool(bad),
                                            tags=("high",) if bad else ())
            for fn in funcs:
                self.imports_tree.insert(node, "end", text=fn,
                                         tags=("high",) if fn in SUSPICIOUS else ())

        self.tabs.select(1)  # immediately open Findings


if __name__ == "__main__":
    App().mainloop()