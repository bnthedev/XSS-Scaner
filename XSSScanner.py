# ─ by bnthedev; for educational purposes only  ───
# ─────────────────────────────────────────────────

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
import time
import json
import os
import uuid
from datetime import datetime
import re

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg/onload=alert(1)>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<select onchange=alert('XSS')><option>1</option></select>",
    "<iframe src=javascript:alert('XSS')>",
    "<object data=javascript:alert('XSS')>",
    "<embed src=javascript:alert('XSS')>",
    "\" onmouseover=\"alert('XSS')\"",
    "' onmouseover='alert(1)'",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "%3Cscript%3Ealert('XSS')%3C%2Fscript%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script>alert(document.cookie)</script>",
    "<img src=1 onerror=alert(document.domain)>",
    "javascript:alert('XSS')",
    "data:text/html,<script>alert('XSS')</script>",
    "'\"><svg/onload=alert(1)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<img src=\"jav&#x09;ascript:alert('XSS');\">",
]

DEFAULT_PAYLOADS = list(XSS_PAYLOADS)

DETECTION_PATTERNS = [
    r"<script>alert\(['\"]?XSS['\"]?\)</script>",
    r"<script>alert\(1\)</script>",
    r"<svg[^>]*onload=alert",
    r"<img[^>]*onerror=alert",
    r"onerror=alert\(",
    r"onload=alert\(",
    r"alert\('XSS'\)",
    r"alert\(1\)",
    r"alert\(document\.",
]

STORED_MARKER_PREFIX = "xss-probe-"

BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
BORDER    = "#30363d"
GREEN     = "#3fb950"
RED       = "#f85149"
YELLOW    = "#e3b341"
BLUE      = "#58a6ff"
PURPLE    = "#bc8cff"
MUTED     = "#8b949e"
FG        = "#e6edf3"
FONT_MONO = ("Courier New", 10)
FONT_SM   = ("Segoe UI", 9)

LANGUAGES = {
    "English": "en",
    "Cestina": "cs",
    "Русский": "ru",
}

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


class I18n:
    def __init__(self, lang_dir="lang"):
        base = os.path.dirname(os.path.abspath(__file__))
        self.lang_dir = os.path.join(base, lang_dir)
        self._strings = {}
        self.load("cs")

    def load(self, code):
        path = os.path.join(self.lang_dir, f"{code}.json")
        try:
            with open(path, encoding="utf-8") as f:
                self._strings = json.load(f)
        except FileNotFoundError:
            print(f"[i18n] Language file not found: {path}")

    def t(self, key, **kwargs):
        text = self._strings.get(key, f"[{key}]")
        if kwargs:
            try:
                text = text.format(**kwargs)
            except KeyError:
                pass
        return text


class XSSScanner:
    def __init__(self, root):
        self.root = root
        self.i18n = I18n()

        self.root.configure(bg=BG)
        self.root.geometry("1100x760")
        self.root.minsize(900, 600)

        self.scanning        = False
        self.stop_flag       = False
        self.results         = []
        self.custom_payloads = []
        self._tested         = 0
        self._forms_found    = 0
        self._pages_crawled  = 0

        self._stored_markers = {}

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (XSS-Scanner/PenTest)"})

        self._translatable = []
        self._build_ui()


    def _change_language(self, lang_name):
        self.i18n.load(LANGUAGES[lang_name])
        self._apply_translations()

    def _register(self, widget, key, attr="text", **kwargs):
        self._translatable.append((widget, key, attr, kwargs))
        self._apply_one(widget, key, attr, **kwargs)

    def _apply_one(self, widget, key, attr, **kwargs):
        try:
            widget.config(**{attr: self.i18n.t(key, **kwargs)})
        except Exception:
            pass

    def _apply_translations(self):
        self.root.title(self.i18n.t("app_title"))
        for w, k, a, kw in self._translatable:
            self._apply_one(w, k, a, **kw)
        if hasattr(self, "_notebook"):
            self._notebook.tab(0, text=self.i18n.t("tab_log"))
            self._notebook.tab(1, text=self.i18n.t("tab_vulns"))
            self._notebook.tab(2, text=self.i18n.t("tab_payloads", count=len(XSS_PAYLOADS)))
        if hasattr(self, "tree"):
            for col, key in zip(
                ("URL", "Type", "Parameter", "Payload", "Severity"),
                ("col_url", "col_type", "col_param", "col_payload", "col_severity"),
            ):
                self.tree.heading(col, text=self.i18n.t(key))


    def _build_ui(self):
        topbar = tk.Frame(self.root, bg=BG2, height=52)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="⚡ XSS Scanner",
                 font=("Segoe UI", 14, "bold"), bg=BG2, fg=BLUE
                 ).pack(side="left", padx=18, pady=12)

        subtitle = tk.Label(topbar, font=FONT_SM, bg=BG2, fg=YELLOW)
        subtitle.pack(side="left", padx=4)
        self._register(subtitle, "app_subtitle")

        lang_frame = tk.Frame(topbar, bg=BG2)
        lang_frame.pack(side="right", padx=18)

        lang_lbl = tk.Label(lang_frame, font=FONT_SM, bg=BG2, fg=MUTED)
        lang_lbl.pack(side="left", padx=(0, 4))
        self._register(lang_lbl, "lang_label")

        self.lang_var = tk.StringVar(value="Cestina")
        lang_combo = ttk.Combobox(lang_frame, textvariable=self.lang_var,
                                  values=list(LANGUAGES.keys()),
                                  state="readonly", width=10, font=FONT_SM)
        lang_combo.pack(side="left")
        lang_combo.bind("<<ComboboxSelected>>",
                        lambda e: self._change_language(self.lang_var.get()))

        self.status_dot = tk.Label(topbar, font=FONT_SM, bg=BG2, fg=MUTED)
        self.status_dot.pack(side="right", padx=(0, 8))

        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=12, pady=8)

        left = tk.Frame(main, bg=BG, width=320)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._build_left(left)
        self._build_right(right)

        self._change_language("Cestina")
        self._set_status(self.i18n.t("status_idle"), MUTED)

    def _build_left(self, parent):
        sec1 = tk.Label(parent, font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED)
        sec1.pack(anchor="w", pady=(10, 3))
        self._register(sec1, "section_target")

        self.url_var = tk.StringVar(value="https://")
        tk.Entry(parent, textvariable=self.url_var, font=FONT_MONO,
                 bg=BG3, fg=FG, insertbackground=FG, bd=0,
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=BLUE).pack(fill="x", pady=(0, 8), ipady=6, padx=2)

        sec2 = tk.Label(parent, font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED)
        sec2.pack(anchor="w", pady=(6, 3))
        self._register(sec2, "section_options")

        self.opt_crawl   = tk.BooleanVar(value=True)
        self.opt_forms   = tk.BooleanVar(value=True)
        self.opt_params  = tk.BooleanVar(value=True)
        self.opt_headers = tk.BooleanVar(value=False)
        self.opt_cookies = tk.BooleanVar(value=False)
        self.opt_stored  = tk.BooleanVar(value=True)  
        self.opt_jscrawl = tk.BooleanVar(value=False)  

        for key, var in [
            ("opt_crawl",   self.opt_crawl),
            ("opt_forms",   self.opt_forms),
            ("opt_params",  self.opt_params),
            ("opt_headers", self.opt_headers),
            ("opt_cookies", self.opt_cookies),
            ("opt_stored",  self.opt_stored),
        ]:
            cb = tk.Checkbutton(parent, variable=var, font=FONT_SM,
                                bg=BG, fg=FG, selectcolor=BG3,
                                activebackground=BG, activeforeground=FG,
                                bd=0, highlightthickness=0)
            cb.pack(anchor="w", pady=1)
            self._register(cb, key)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)

        r1 = tk.Frame(parent, bg=BG)
        r1.pack(fill="x")
        l1 = tk.Label(r1, font=FONT_SM, bg=BG, fg=MUTED)
        l1.pack(side="left")
        self._register(l1, "label_delay")
        self.delay_var = tk.IntVar(value=200)
        tk.Spinbox(r1, from_=0, to=2000, width=6, textvariable=self.delay_var,
                   font=FONT_SM, bg=BG3, fg=FG, buttonbackground=BG3,
                   insertbackground=FG, bd=0,
                   highlightthickness=1, highlightbackground=BORDER).pack(side="right")

        r2 = tk.Frame(parent, bg=BG)
        r2.pack(fill="x", pady=4)
        l2 = tk.Label(r2, font=FONT_SM, bg=BG, fg=MUTED)
        l2.pack(side="left")
        self._register(l2, "label_maxpages")
        self.maxpages_var = tk.IntVar(value=20)
        tk.Spinbox(r2, from_=1, to=200, width=6, textvariable=self.maxpages_var,
                   font=FONT_SM, bg=BG3, fg=FG, buttonbackground=BG3,
                   insertbackground=FG, bd=0,
                   highlightthickness=1, highlightbackground=BORDER).pack(side="right")

        pl_lbl = tk.Label(parent, font=FONT_SM, bg=BG, fg=MUTED)
        pl_lbl.pack(anchor="w", pady=2)
        self._register(pl_lbl, "label_payloads", count=len(XSS_PAYLOADS))

        pl_btn_frame = tk.Frame(parent, bg=BG)
        pl_btn_frame.pack(fill="x", pady=(2, 0))

        self.load_pl_btn = tk.Button(
            pl_btn_frame, font=FONT_SM, bg=BG3, fg=BLUE, bd=0, cursor="hand2",
            activebackground=BORDER, command=self._load_custom_payloads)
        self.load_pl_btn.pack(side="left", ipady=4, padx=(0, 4))
        self._register(self.load_pl_btn, "btn_load_payloads")

        help_btn = tk.Button(
            pl_btn_frame, text="?", font=("Segoe UI", 9, "bold"),
            bg=BG3, fg=YELLOW, bd=0, cursor="hand2",
            activebackground=BORDER, width=2,
            command=self._show_payload_help)
        help_btn.pack(side="left", ipady=4)

        self.custom_pl_lbl = tk.Label(parent, font=FONT_SM, bg=BG, fg=MUTED, text="")
        self.custom_pl_lbl.pack(anchor="w", pady=(2, 0))

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)

        sec_pw = tk.Label(parent, font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED)
        sec_pw.pack(anchor="w", pady=(4, 3))
        self._register(sec_pw, "section_browser")

        mode_frame = tk.Frame(parent, bg=BG)
        mode_frame.pack(fill="x", pady=(0, 4))

        self.scan_mode = tk.StringVar(value="requests")

        rb_req = tk.Radiobutton(
            mode_frame, variable=self.scan_mode, value="requests",
            font=FONT_SM, bg=BG, fg=FG, selectcolor=BG3,
            activebackground=BG, activeforeground=FG,
            bd=0, highlightthickness=0,
            command=self._on_mode_change)
        rb_req.pack(side="left", padx=(0, 8))
        self._register(rb_req, "mode_requests")

        rb_pw = tk.Radiobutton(
            mode_frame, variable=self.scan_mode, value="playwright",
            font=FONT_SM, bg=BG, fg=FG, selectcolor=BG3,
            activebackground=BG, activeforeground=FG,
            bd=0, highlightthickness=0,
            command=self._on_mode_change)
        rb_pw.pack(side="left")
        self._register(rb_pw, "mode_playwright")

        self.pw_options_frame = tk.Frame(parent, bg=BG)

        self.opt_headless = tk.BooleanVar(value=True)
        cb_hl = tk.Checkbutton(
            self.pw_options_frame, variable=self.opt_headless,
            font=FONT_SM, bg=BG, fg=FG, selectcolor=BG3,
            activebackground=BG, activeforeground=FG,
            bd=0, highlightthickness=0)
        cb_hl.pack(anchor="w", pady=1)
        self._register(cb_hl, "opt_headless")

        cb_js = tk.Checkbutton(
            self.pw_options_frame, variable=self.opt_jscrawl,
            font=FONT_SM, bg=BG, fg=FG, selectcolor=BG3,
            activebackground=BG, activeforeground=FG,
            bd=0, highlightthickness=0)
        cb_js.pack(anchor="w", pady=1)
        self._register(cb_js, "opt_jscrawl")

        br_row = tk.Frame(self.pw_options_frame, bg=BG)
        br_row.pack(fill="x", pady=(2, 4))
        br_lbl = tk.Label(br_row, font=FONT_SM, bg=BG, fg=MUTED)
        br_lbl.pack(side="left")
        self._register(br_lbl, "label_browser")

        self.browser_var = tk.StringVar(value="chromium")
        br_combo = ttk.Combobox(
            br_row, textvariable=self.browser_var,
            values=["chromium", "firefox", "webkit"],
            state="readonly", width=10, font=FONT_SM)
        br_combo.pack(side="right")

        self.pw_status_lbl = tk.Label(
            self.pw_options_frame, font=FONT_SM, bg=BG,
            fg=GREEN if PLAYWRIGHT_AVAILABLE else RED)
        self.pw_status_lbl.pack(anchor="w", pady=(0, 4))
        self._register(
            self.pw_status_lbl,
            "pw_installed" if PLAYWRIGHT_AVAILABLE else "pw_not_installed")

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", pady=8)

        sec3 = tk.Label(parent, font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED)
        sec3.pack(anchor="w", pady=(4, 3))
        self._register(sec3, "section_auth")

        ck_lbl = tk.Label(parent, font=FONT_SM, bg=BG, fg=MUTED)
        ck_lbl.pack(anchor="w")
        self._register(ck_lbl, "label_cookie")
        self.cookie_entry = tk.Entry(parent, font=FONT_MONO, bg=BG3, fg=FG,
                                     insertbackground=FG, bd=0,
                                     highlightthickness=1, highlightbackground=BORDER)
        self.cookie_entry.pack(fill="x", pady=(0, 6), ipady=4, padx=2)

        au_lbl = tk.Label(parent, font=FONT_SM, bg=BG, fg=MUTED)
        au_lbl.pack(anchor="w")
        self._register(au_lbl, "label_auth")
        self.auth_entry = tk.Entry(parent, font=FONT_MONO, bg=BG3, fg=FG,
                                   insertbackground=FG, bd=0,
                                   highlightthickness=1, highlightbackground=BORDER)
        self.auth_entry.pack(fill="x", pady=(0, 8), ipady=4, padx=2)

        self.scan_btn = tk.Button(parent, font=("Segoe UI", 11, "bold"),
                                  bg=GREEN, fg="#0d1117", bd=0, cursor="hand2",
                                  activebackground="#2ea043",
                                  command=self._start_scan)
        self.scan_btn.pack(fill="x", pady=(8, 4), ipady=8)
        self._register(self.scan_btn, "btn_start")

        self.stop_btn = tk.Button(parent, font=("Segoe UI", 10),
                                  bg=BG3, fg=RED, bd=0, cursor="hand2",
                                  activebackground=BORDER,
                                  command=self._stop_scan, state="disabled")
        self.stop_btn.pack(fill="x", ipady=6)
        self._register(self.stop_btn, "btn_stop")

        self.export_btn = tk.Button(parent, font=FONT_SM, bg=BG3, fg=MUTED,
                                    bd=0, cursor="hand2", activebackground=BORDER,
                                    command=self._export)
        self.export_btn.pack(fill="x", pady=(8, 0), ipady=5)
        self._register(self.export_btn, "btn_export")

    def _on_mode_change(self):
        if self.scan_mode.get() == "playwright":
            self.pw_options_frame.pack(fill="x")
        else:
            self.pw_options_frame.pack_forget()


    def _build_right(self, parent):
        stats = tk.Frame(parent, bg=BG2)
        stats.pack(fill="x", pady=(0, 8))

        self.stat_tested = self._stat(stats, "stat_tested", "0", BLUE)
        tk.Frame(stats, bg=BORDER, width=1).pack(side="left", fill="y")
        self.stat_vulns  = self._stat(stats, "stat_vulns",  "0", RED)
        tk.Frame(stats, bg=BORDER, width=1).pack(side="left", fill="y")
        self.stat_forms  = self._stat(stats, "stat_forms",  "0", PURPLE)
        tk.Frame(stats, bg=BORDER, width=1).pack(side="left", fill="y")
        self.stat_pages  = self._stat(stats, "stat_pages",  "0", GREEN)

        self._notebook = ttk.Notebook(parent)
        self._notebook.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=MUTED,
                        padding=[14, 6], font=FONT_SM, borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", BG2)],
                  foreground=[("selected", FG)])

        log_frame = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(log_frame, text="")
        self.log = scrolledtext.ScrolledText(
            log_frame, font=FONT_MONO, bg=BG, fg=FG,
            insertbackground=FG, selectbackground=BG3,
            bd=0, highlightthickness=0, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True)
        for tag, color in [("vuln", RED), ("ok", GREEN), ("info", BLUE),
                           ("warn", YELLOW), ("muted", MUTED)]:
            self.log.tag_config(tag, foreground=color)

        vuln_frame = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(vuln_frame, text="")
        self._build_vuln_table(vuln_frame)

        pl_frame = tk.Frame(self._notebook, bg=BG)
        self._notebook.add(pl_frame, text="")
        pl_text = scrolledtext.ScrolledText(pl_frame, font=FONT_MONO, bg=BG,
                                            fg=MUTED, bd=0, highlightthickness=0,
                                            wrap="none")
        pl_text.pack(fill="both", expand=True)
        for i, p in enumerate(XSS_PAYLOADS, 1):
            pl_text.insert("end", f"{i:2}. {p}\n")
        pl_text.config(state="disabled")

    def _build_vuln_table(self, parent):
        cols = ("URL", "Type", "Parameter", "Payload", "Severity")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")

        style = ttk.Style()
        style.configure("Treeview", background=BG2, foreground=FG,
                        fieldbackground=BG2, rowheight=24, font=FONT_SM, borderwidth=0)
        style.configure("Treeview.Heading", background=BG3, foreground=MUTED,
                        font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", BG3)])

        for col, w in zip(cols, [320, 80, 100, 260, 80]):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=60)

        self.tree.tag_configure("high",   foreground=RED)
        self.tree.tag_configure("medium", foreground=YELLOW)

        sy = ttk.Scrollbar(parent, orient="vertical",   command=self.tree.yview)
        sx = ttk.Scrollbar(parent, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        sy.pack(side="right",  fill="y")
        sx.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        detail_frame = tk.Frame(parent, bg=BG2)
        detail_frame.pack(fill="x")
        dl = tk.Label(detail_frame, font=FONT_SM, bg=BG2, fg=MUTED)
        dl.pack(anchor="w", padx=8, pady=(4, 0))
        self._register(dl, "detail_label")
        self.detail_text = tk.Text(detail_frame, height=4, font=FONT_MONO,
                                   bg=BG2, fg=FG, bd=0, highlightthickness=0,
                                   wrap="word", state="disabled")
        self.detail_text.pack(fill="x", padx=8, pady=(0, 8))
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

    def _stat(self, parent, label_key, value, color):
        frame = tk.Frame(parent, bg=BG2)
        frame.pack(side="left", expand=True, fill="both", padx=1, pady=1)
        val_lbl = tk.Label(frame, text=value,
                           font=("Courier New", 20, "bold"), bg=BG2, fg=color)
        val_lbl.pack(pady=(8, 0))
        lbl = tk.Label(frame, font=("Segoe UI", 8), bg=BG2, fg=MUTED)
        lbl.pack(pady=(0, 8))
        self._register(lbl, label_key)
        return val_lbl


    def _log(self, msg, tag=""):
        def _do():
            self.log.config(state="normal")
            ts = datetime.now().strftime("%H:%M:%S")
            self.log.insert("end", f"[{ts}] {msg}\n", tag)
            self.log.see("end")
            self.log.config(state="disabled")
        self.root.after(0, _do)

    def _set_status(self, text, color=MUTED):
        self.root.after(0, lambda: self.status_dot.config(
            text=f"● {text}", fg=color))

    def _update_stats(self):
        self.root.after(0, lambda: [
            self.stat_tested.config(text=str(self._tested)),
            self.stat_vulns.config( text=str(len(self.results))),
            self.stat_forms.config( text=str(self._forms_found)),
            self.stat_pages.config( text=str(self._pages_crawled)),
        ])

    def _show_detail(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        v = self.tree.item(sel[0], "values")
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", self.i18n.t(
            "detail_text", url=v[0], type=v[1], param=v[2],
            severity=v[4], payload=v[3]))
        self.detail_text.config(state="disabled")


    def _start_scan(self):
        url = self.url_var.get().strip()
        if not url or url == "https://":
            messagebox.showwarning(
                self.i18n.t("warn_no_url_title"),
                self.i18n.t("warn_no_url_msg"))
            return
        if not url.startswith("http"):
            url = "https://" + url
            self.url_var.set(url)

        if self.scan_mode.get() == "playwright" and not PLAYWRIGHT_AVAILABLE:
            messagebox.showerror(
                self.i18n.t("pw_error_title"),
                self.i18n.t("pw_error_msg"))
            return

        if not messagebox.askyesno(
                self.i18n.t("confirm_title"),
                self.i18n.t("confirm_msg", url=url)):
            return

        self.results.clear()
        self._stored_markers.clear()
        self._tested = self._forms_found = self._pages_crawled = 0
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        for item in self.tree.get_children():
            self.tree.delete(item)

        cookie = self.cookie_entry.get().strip()
        auth   = self.auth_entry.get().strip()
        if cookie: self.session.headers.update({"Cookie": cookie})
        if auth:   self.session.headers.update({"Authorization": auth})

        self.stop_flag = False
        self.scanning  = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        if self.scan_mode.get() == "playwright":
            self._set_status(
                self.i18n.t("status_scanning_browser",
                             browser=self.browser_var.get()), PURPLE)
            threading.Thread(target=self._scan_thread_playwright,
                             args=(url,), daemon=True).start()
        else:
            self._set_status(self.i18n.t("status_scanning"), GREEN)
            threading.Thread(target=self._scan_thread,
                             args=(url,), daemon=True).start()

    def _stop_scan(self):
        self.stop_flag = True
        self._log(self.i18n.t("log_stopped"), "warn")

    def _finish_scan(self):
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        count = len(self.results)
        if count > 0:
            self._set_status(self.i18n.t("status_done_vulns", count=count), RED)
            self._log(self.i18n.t("log_done_vulns", count=count), "vuln")
        else:
            self._set_status(self.i18n.t("status_done_clean"), GREEN)
            self._log(self.i18n.t("log_done_clean"), "ok")


    def _scan_thread(self, base_url):
        try:
            self._log(self.i18n.t("log_start", url=base_url), "info")
            urls_to_test = [base_url]

            if self.opt_crawl.get():
                self._log(self.i18n.t("log_crawling"), "info")
                crawled = self._crawl(base_url)
                urls_to_test = list(set(urls_to_test + crawled))
                self._log(self.i18n.t("log_crawled", count=len(urls_to_test)), "muted")

            for url in urls_to_test:
                if self.stop_flag:
                    break
                self._test_url(url)

            if self.opt_stored.get() and self._stored_markers and not self.stop_flag:
                self._check_stored_xss(urls_to_test)

            self.root.after(0, self._finish_scan)
        except Exception as e:
            self._log(self.i18n.t("log_error", error=e), "warn")
            self.root.after(0, self._finish_scan)

    def _crawl(self, base_url):
        """Requests-based crawl — statické HTML."""
        visited, to_visit, found = set(), [base_url], []
        domain = urlparse(base_url).netloc
        max_p  = self.maxpages_var.get()

        while to_visit and len(visited) < max_p and not self.stop_flag:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                resp = self.session.get(url, timeout=8, allow_redirects=True)
                self._pages_crawled += 1
                self._update_stats()
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all("a", href=True):
                    href = urljoin(url, tag["href"])
                    if urlparse(href).netloc == domain and href not in visited:
                        to_visit.append(href)
                        if href not in found:
                            found.append(href)
            except Exception:
                pass
            time.sleep(self.delay_var.get() / 1000)

        return found

    def _test_url(self, url):
        self._log(self.i18n.t("log_testing", url=url), "muted")
        parsed = urlparse(url)

        if self.opt_params.get():
            params = parse_qs(parsed.query)
            if params:
                self._log(self.i18n.t("log_params", params=list(params.keys())), "muted")
                for param in params:
                    for payload in XSS_PAYLOADS:
                        if self.stop_flag: return
                        self._test_param(url, param, payload)
                        self._tested += 1
                        self._update_stats()
                        time.sleep(self.delay_var.get() / 1000)

        if self.opt_forms.get():
            try:
                resp = self.session.get(url, timeout=8)
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form")
                if forms:
                    self._log(self.i18n.t("log_forms", count=len(forms)), "muted")
                    self._forms_found += len(forms)
                    self._update_stats()
                for form in forms:
                    if self.stop_flag: return
                    self._test_form(url, form)
            except Exception as e:
                self._log(self.i18n.t("log_page_error", error=e), "warn")

        if self.opt_headers.get():
            for payload in XSS_PAYLOADS[:5]:
                if self.stop_flag: return
                self._test_header(url, "User-Agent", payload)
                self._test_header(url, "Referer",    payload)
                self._tested += 2
                self._update_stats()
                time.sleep(self.delay_var.get() / 1000)

    def _test_param(self, url, param, payload):
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(params, doseq=True)))
            resp = self.session.get(test_url, timeout=8)
            if self._detect_xss(resp.text, payload):
                sev = "HIGH" if "<script>" in payload.lower() else "MEDIUM"
                self._report_vuln(url, "URL param", param, payload, sev)
            elif self.opt_stored.get():
                marker = self._make_stored_marker(
                    url, "URL param", param, payload)
                params[param] = [marker]
                marker_url = urlunparse(
                    parsed._replace(query=urlencode(params, doseq=True)))
                self.session.get(marker_url, timeout=8)
        except Exception:
            pass

    def _test_form(self, page_url, form):
        try:
            action = urljoin(page_url, form.get("action", page_url))
            method = form.get("method", "get").lower()
            fields = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name  = inp.get("name", "")
                if not name: continue
                itype = inp.get("type", "text").lower()
                if itype in ("submit", "button", "image", "reset"):
                    fields[name] = inp.get("value", "submit")
                elif itype == "checkbox":
                    fields[name] = "on"
                else:
                    fields[name] = inp.get("value", "test")

            testable = [f for f in fields if fields[f] in ("test", "")
                        or not any(v in fields[f] for v in ("submit", "on"))]

            for field_name in testable:
                for payload in XSS_PAYLOADS:
                    if self.stop_flag: return
                    test_fields = {**fields, field_name: payload}
                    try:
                        if method == "post":
                            resp = self.session.post(action, data=test_fields, timeout=8)
                        else:
                            resp = self.session.get(action, params=test_fields, timeout=8)
                        self._tested += 1
                        self._update_stats()
                        if self._detect_xss(resp.text, payload):
                            sev = "HIGH" if "<script>" in payload.lower() else "MEDIUM"
                            self._report_vuln(action, f"Form ({method.upper()})",
                                              field_name, payload, sev)
                        elif self.opt_stored.get():
                            # Odešli marker pro stored XSS
                            marker = self._make_stored_marker(
                                action, f"Form ({method.upper()})",
                                field_name, payload)
                            mf = {**fields, field_name: marker}
                            if method == "post":
                                self.session.post(action, data=mf, timeout=8)
                            else:
                                self.session.get(action, params=mf, timeout=8)
                    except Exception:
                        pass
                    time.sleep(self.delay_var.get() / 1000)
        except Exception as e:
            self._log(self.i18n.t("log_form_error", error=e), "warn")

    def _test_header(self, url, header, payload):
        try:
            resp = self.session.get(url, headers={header: payload}, timeout=8)
            if self._detect_xss(resp.text, payload):
                self._report_vuln(url, "Header", header, payload, "MEDIUM")
        except Exception:
            pass

    def _detect_xss(self, response_text, payload):
        if payload in response_text:
            return True
        for pattern in DETECTION_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False


    def _make_stored_marker(self, url, vuln_type, param, payload):
        """
        Vytvoří unikátní textový marker a uloží ho do _stored_markers.
        Marker se odešle místo payloadu — po scanu se hledá na všech stránkách.
        """
        marker_id = uuid.uuid4().hex[:12]
        marker    = f"{STORED_MARKER_PREFIX}{marker_id}"
        self._stored_markers[marker] = {
            "url": url, "type": vuln_type,
            "param": param, "payload": payload,
        }
        return marker

    def _check_stored_xss(self, urls_to_check):
        """
        Fáze 2: projde všechny crawlované stránky a hledá markery v HTML.
        Pokud marker najde → stored XSS nalezeno.
        """
        self._log(self.i18n.t("log_stored_check",
                               count=len(self._stored_markers)), "info")
        for url in urls_to_check:
            if self.stop_flag:
                break
            try:
                resp = self.session.get(url, timeout=8)
                for marker, info in list(self._stored_markers.items()):
                    if marker in resp.text:
                        self._log(
                            self.i18n.t("log_stored_found", url=url,
                                        param=info["param"]), "vuln")
                        self._report_vuln(
                            url,
                            info["type"] + " [Stored]",
                            info["param"],
                            info["payload"],
                            "HIGH")
                        # Odstraň marker aby se nereportoval víckrát
                        del self._stored_markers[marker]
            except Exception:
                pass
            time.sleep(self.delay_var.get() / 1000)

        remaining = len(self._stored_markers)
        if remaining == 0:
            self._log(self.i18n.t("log_stored_none"), "muted")


    def _scan_thread_playwright(self, base_url):
        try:
            self._log(self.i18n.t("log_pw_start",
                                   browser=self.browser_var.get()), "info")

            with sync_playwright() as pw:
                browser_type = getattr(pw, self.browser_var.get())
                browser = browser_type.launch(headless=self.opt_headless.get())
                context = browser.new_context()

                cookie_str = self.cookie_entry.get().strip()
                if cookie_str:
                    for pair in cookie_str.split(";"):
                        pair = pair.strip()
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            context.add_cookies([{
                                "name": k.strip(), "value": v.strip(),
                                "url": base_url
                            }])

                if self.opt_crawl.get():
                    self._log(self.i18n.t("log_crawling"), "info")
                    if self.opt_jscrawl.get():
                        crawled = self._pw_crawl(context, base_url)
                    else:
                        crawled = self._crawl(base_url)
                    urls_to_test = list(set([base_url] + crawled))
                    self._log(self.i18n.t("log_crawled",
                                          count=len(urls_to_test)), "muted")
                else:
                    urls_to_test = [base_url]

                for url in urls_to_test:
                    if self.stop_flag:
                        break
                    self._pw_test_url(context, url)

                if self.opt_stored.get() and self._stored_markers and not self.stop_flag:
                    self._pw_check_stored_xss(context, urls_to_test)

                browser.close()

            self.root.after(0, self._finish_scan)
        except Exception as e:
            self._log(self.i18n.t("log_error", error=e), "warn")
            self.root.after(0, self._finish_scan)

    def _pw_crawl(self, context, base_url):
        """
        JS crawling přes Playwright — načte každou stránku v prohlížeči,
        počká na JS rendering a sbírá href z DOM (včetně SPA odkazů).
        Zachytí URL přidané JavaScriptem, které requests crawler nevidí.
        """
        self._log(self.i18n.t("log_pw_jscrawl"), "info")
        visited, to_visit, found = set(), [base_url], []
        domain = urlparse(base_url).netloc
        max_p  = self.maxpages_var.get()

        while to_visit and len(visited) < max_p and not self.stop_flag:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            page = context.new_page()
            try:
                page.goto(url, timeout=15000, wait_until="networkidle")
                self._pages_crawled += 1
                self._update_stats()

                hrefs = page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(e => e.href)"
                )
                for href in hrefs:
                    href = href.split("#")[0]  
                    if not href:
                        continue
                    if urlparse(href).netloc == domain and href not in visited:
                        to_visit.append(href)
                        if href not in found:
                            found.append(href)
                            self._log(
                                self.i18n.t("log_pw_jscrawl_found", url=href),
                                "muted")
            except Exception:
                pass
            finally:
                page.close()
            time.sleep(self.delay_var.get() / 1000)

        return found

    def _pw_test_url(self, context, url):
        self._log(self.i18n.t("log_pw_testing", url=url), "muted")

        if self.opt_params.get():
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                self._log(self.i18n.t("log_params",
                                       params=list(params.keys())), "muted")
                for param in params:
                    for payload in XSS_PAYLOADS:
                        if self.stop_flag: return
                        test_p = dict(params)
                        test_p[param] = [payload]
                        test_url = urlunparse(
                            parsed._replace(query=urlencode(test_p, doseq=True)))
                        fired = self._pw_navigate_and_check(
                            context, test_url, "URL param", param, payload)
                        if not fired and self.opt_stored.get():
                            marker = self._make_stored_marker(
                                url, "URL param", param, payload)
                            test_p[param] = [marker]
                            m_url = urlunparse(
                                parsed._replace(
                                    query=urlencode(test_p, doseq=True)))
                            self._pw_navigate_silent(context, m_url)
                        self._tested += 1
                        self._update_stats()
                        time.sleep(self.delay_var.get() / 1000)

        if self.opt_forms.get():
            try:
                page = context.new_page()
                page.goto(url, timeout=15000, wait_until="domcontentloaded")
                html = page.content()
                soup = BeautifulSoup(html, "html.parser")
                forms = soup.find_all("form")
                page.close()

                if forms:
                    self._log(self.i18n.t("log_forms", count=len(forms)), "muted")
                    self._forms_found += len(forms)
                    self._update_stats()

                for form in forms:
                    if self.stop_flag: return
                    self._pw_test_form(context, url, form)
            except Exception as e:
                self._log(self.i18n.t("log_page_error", error=e), "warn")

    def _pw_navigate_and_check(self, context, url, vuln_type, param, payload):
        """Naviguj a detekuj alert(). Vrátí True pokud alert vyskočil."""
        alert_fired = {"value": False}

        def _on_dialog(dialog):
            alert_fired["value"] = True
            dialog.dismiss()

        page = context.new_page()
        try:
            page.on("dialog", _on_dialog)
            page.goto(url, timeout=12000, wait_until="domcontentloaded")
            page.wait_for_timeout(600)
            if alert_fired["value"]:
                sev = "HIGH" if "<script>" in payload.lower() else "MEDIUM"
                self._report_vuln(url, vuln_type + " [Browser]", param, payload, sev)
                self._log(self.i18n.t("log_pw_alert_fired", param=param), "vuln")
        except Exception:
            pass
        finally:
            page.close()
        return alert_fired["value"]

    def _pw_navigate_silent(self, context, url):
        """Naviguj bez detekce alertu — pro odeslání stored markeru."""
        page = context.new_page()
        try:
            page.on("dialog", lambda d: d.dismiss())
            page.goto(url, timeout=10000, wait_until="domcontentloaded")
        except Exception:
            pass
        finally:
            page.close()

    def _pw_test_form(self, context, page_url, form):
        try:
            action = urljoin(page_url, form.get("action", page_url))
            method = form.get("method", "get").lower()

            text_fields = []
            for inp in form.find_all(["input", "textarea"]):
                name  = inp.get("name", "")
                itype = inp.get("type", "text").lower()
                if not name:
                    continue
                if itype in ("text", "search", "email", "url", "tel",
                             "password", "textarea", ""):
                    text_fields.append(name)

            for field_name in text_fields:
                for payload in XSS_PAYLOADS:
                    if self.stop_flag: return
                    alert_fired = {"value": False}

                    def _on_dialog(dialog, _af=alert_fired):
                        _af["value"] = True
                        dialog.dismiss()

                    page = context.new_page()
                    try:
                        page.on("dialog", _on_dialog)
                        page.goto(page_url, timeout=12000,
                                  wait_until="domcontentloaded")
                        locator = page.locator(f'[name="{field_name}"]').first
                        locator.fill(payload)
                        submit = page.locator(
                            'input[type="submit"], button[type="submit"], '
                            'button:not([type])'
                        ).first
                        try:
                            submit.click(timeout=3000)
                        except Exception:
                            locator.press("Enter")
                        self._tested += 1
                        self._update_stats()
                        page.wait_for_timeout(800)

                        if alert_fired["value"]:
                            sev = "HIGH" if "<script>" in payload.lower() else "MEDIUM"
                            self._report_vuln(
                                action,
                                f"Form-Browser ({method.upper()})",
                                field_name, payload, sev)
                            self._log(
                                self.i18n.t("log_pw_alert_fired",
                                            param=field_name), "vuln")
                        elif self.opt_stored.get():
                            # Odešli stored marker formulářem
                            marker = self._make_stored_marker(
                                action, f"Form ({method.upper()})",
                                field_name, payload)
                            try:
                                locator.fill(marker)
                                submit.click(timeout=3000)
                                page.wait_for_timeout(400)
                            except Exception:
                                pass
                    except Exception:
                        self._tested += 1
                        self._update_stats()
                    finally:
                        page.close()

                    time.sleep(self.delay_var.get() / 1000)
        except Exception as e:
            self._log(self.i18n.t("log_form_error", error=e), "warn")

    def _pw_check_stored_xss(self, context, urls_to_check):
        """
        Playwright verze stored XSS kontroly — načte stránky v prohlížeči
        a hledá markery v DOM (zachytí i dynamicky vložený obsah).
        """
        self._log(self.i18n.t("log_stored_check",
                               count=len(self._stored_markers)), "info")
        for url in urls_to_check:
            if self.stop_flag:
                break
            page = context.new_page()
            try:
                page.on("dialog", lambda d: d.dismiss())
                page.goto(url, timeout=12000, wait_until="domcontentloaded")
                page.wait_for_timeout(500)
                content = page.content()
                for marker, info in list(self._stored_markers.items()):
                    if marker in content:
                        self._log(
                            self.i18n.t("log_stored_found", url=url,
                                        param=info["param"]), "vuln")
                        self._report_vuln(
                            url,
                            info["type"] + " [Stored-Browser]",
                            info["param"],
                            info["payload"],
                            "HIGH")
                        del self._stored_markers[marker]
            except Exception:
                pass
            finally:
                page.close()
            time.sleep(self.delay_var.get() / 1000)


    def _report_vuln(self, url, vuln_type, param, payload, severity):
        self.results.append({
            "url": url, "type": vuln_type, "param": param,
            "payload": payload, "severity": severity,
            "time": datetime.now().isoformat()
        })
        self._log(self.i18n.t("log_vuln_found",  severity=severity), "vuln")
        self._log(self.i18n.t("log_vuln_url",     url=url),          "vuln")
        self._log(self.i18n.t("log_vuln_detail",  type=vuln_type, param=param), "vuln")
        self._log(self.i18n.t("log_vuln_payload", payload=payload),  "vuln")

        tag = "high" if severity == "HIGH" else "medium"
        su  = url     if len(url)     <= 50 else url[:47]     + "..."
        sp  = payload if len(payload) <= 50 else payload[:47] + "..."
        self.root.after(0, lambda: self.tree.insert(
            "", "end",
            values=(su, vuln_type, param, sp, severity),
            tags=(tag,)))


    def _export(self):
        if not self.results:
            messagebox.showinfo(
                self.i18n.t("export_title"),
                self.i18n.t("export_empty"))
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = self.i18n.t("export_default_name", timestamp=ts)
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Text", "*.txt"), ("All", "*.*")],
            initialfile=name)
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump({
                "scan_time": datetime.now().isoformat(),
                "target":    self.url_var.get(),
                "total_vulnerabilities": len(self.results),
                "vulnerabilities": self.results,
            }, f, indent=2, ensure_ascii=False)
        messagebox.showinfo(
            self.i18n.t("export_title"),
            self.i18n.t("export_saved", path=path))


    def _load_custom_payloads(self):
        path = filedialog.askopenfilename(
            title=self.i18n.t("load_pl_dialog_title"),
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            if not lines:
                messagebox.showwarning(
                    self.i18n.t("load_pl_empty_title"),
                    self.i18n.t("load_pl_empty_msg"))
                return
            self.custom_payloads = lines
            global XSS_PAYLOADS
            XSS_PAYLOADS = list(DEFAULT_PAYLOADS)
            for p in lines:
                if p not in XSS_PAYLOADS:
                    XSS_PAYLOADS.append(p)
            self.custom_pl_lbl.config(
                text=self.i18n.t("load_pl_loaded",
                                  count=len(lines), total=len(XSS_PAYLOADS)),
                fg=GREEN)
            self._apply_translations()
        except Exception as e:
            messagebox.showerror(
                self.i18n.t("load_pl_error_title"),
                self.i18n.t("load_pl_error_msg", error=e))

    def _show_payload_help(self):
        win = tk.Toplevel(self.root)
        win.title(self.i18n.t("help_title"))
        win.configure(bg=BG)
        win.geometry("520x380")
        win.resizable(False, False)

        tk.Label(win, text=self.i18n.t("help_title"),
                 font=("Segoe UI", 11, "bold"), bg=BG, fg=BLUE).pack(pady=(16, 4))

        txt = scrolledtext.ScrolledText(
            win, font=FONT_MONO, bg=BG2, fg=FG, bd=0,
            highlightthickness=0, wrap="word", state="normal")
        txt.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        txt.insert("end", self.i18n.t("help_body"))
        txt.config(state="disabled")

        tk.Button(win, text="OK", font=FONT_SM, bg=BG3, fg=FG,
                  bd=0, cursor="hand2", activebackground=BORDER,
                  command=win.destroy).pack(pady=(0, 12), ipadx=16, ipady=4)


if __name__ == "__main__":
    root = tk.Tk()
    app  = XSSScanner(root)
    root.mainloop()