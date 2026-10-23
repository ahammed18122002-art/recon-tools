#!/usr/bin/env python3
"""MH Security Tool Installer — Kali/Debian Linux, Tkinter GUI.
Installs and verifies DNSRecon, Subfinder, ProjectDiscovery httpx, Nmap,
Katana, Arjun, Photon, dnsx, naabu, and Nuclei. Uses official Go downloads with SHA-256 verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import queue
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "MH Security Tool Installer"
BASE_DIR = Path.home() / ".local" / "share" / "mh-tool-installer"
LOCAL_BIN = Path.home() / ".local" / "bin"
GO_SDK_DIR = BASE_DIR / "go-sdk"
REPORT_PATH = BASE_DIR / "install_report.txt"
PHOTON_REPO = "https://github.com/s0md3v/Photon.git"
PHOTON_DIR = BASE_DIR / "photon"
PHOTON_VENV = BASE_DIR / "photon-venv"

# Individual APT package rows allow the GUI to distinguish packages that were
# already present from packages added by this installer.
SYSTEM_DEPENDENCIES = {
    "Git": {"package": "git", "binary": "git", "version_cmd": ["git", "--version"], "purpose": "Source downloads and repository access"},
    "Curl": {"package": "curl", "binary": "curl", "version_cmd": ["curl", "--version"], "purpose": "HTTPS downloads and API requests"},
    "Wget": {"package": "wget", "binary": "wget", "version_cmd": ["wget", "--version"], "purpose": "File downloads"},
    "CA certificates": {"package": "ca-certificates", "binary": None, "version_cmd": None, "purpose": "TLS certificate trust store"},
    "Python 3": {"package": "python3", "binary": "python3", "version_cmd": ["python3", "--version"], "purpose": "Runs this installer and Python tools"},
    "Python pip": {"package": "python3-pip", "binary": "pip3", "version_cmd": ["pip3", "--version"], "purpose": "Python package installation support"},
    "Python venv": {"package": "python3-venv", "binary": None, "version_cmd": None, "purpose": "Isolated Python environments"},
    "pipx": {"package": "pipx", "binary": "pipx", "version_cmd": ["pipx", "--version"], "purpose": "Isolated installation of Python CLI tools"},
    "libpcap-dev": {"package": "libpcap-dev", "binary": None, "version_cmd": None, "purpose": "Packet-capture development headers"},
    "build-essential": {"package": "build-essential", "binary": None, "version_cmd": None, "purpose": "Compiler and build toolchain"},
    "jq": {"package": "jq", "binary": "jq", "version_cmd": ["jq", "--version"], "purpose": "JSON parsing in shell workflows"},
    "Tkinter": {"package": "python3-tk", "binary": "python3", "version_cmd": ["python3", "-c", "import tkinter; print('Tkinter available')"], "purpose": "Graphical user interface dependency"},
}

GO_TOOLS = {
    "Subfinder": ("subfinder", ["go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"], ["subfinder", "-version"], {}),
    "httpx": ("httpx", ["go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], ["httpx", "-version"], {}),
    "Katana": ("katana", ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"], ["katana", "-version"], {"CGO_ENABLED": "1"}),
    "dnsx": ("dnsx", ["go", "install", "-v", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"], ["dnsx", "-version"], {}),
    "naabu": ("naabu", ["go", "install", "-v", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], ["naabu", "-version"], {}),
    "Nuclei": ("nuclei", ["go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"], ["nuclei", "-version"], {"CGO_ENABLED": "0"}),
}
CHECKS = {
    "DNSRecon": ("dnsrecon", ["dnsrecon", "--help"]),
    "Subfinder": ("subfinder", ["subfinder", "-version"]),
    "httpx": ("httpx", ["httpx", "-version"]),
    "Nmap": ("nmap", ["nmap", "--version"]),
    "Katana": ("katana", ["katana", "-version"]),
    "Arjun": ("arjun", ["arjun", "--help"]),
    "Photon": ("photon", ["photon", "--help"]),
    "dnsx": ("dnsx", ["dnsx", "-version"]),
    "naabu": ("naabu", ["naabu", "-version"]),
    "Nuclei": ("nuclei", ["nuclei", "-version"]),
}
VERSION_COMMANDS = {
    "DNSRecon": [["dnsrecon", "--version"], ["dnsrecon", "-V"]],
    "Subfinder": [["subfinder", "-version"]],
    "httpx": [["httpx", "-version"]],
    "Nmap": [["nmap", "--version"]],
    "Katana": [["katana", "-version"]],
    "Arjun": [["arjun", "--version"], ["arjun", "-V"]],
    "Photon": [],  # Photon has no version flag; the git commit is reported instead.
    "dnsx": [["dnsx", "-version"]],
    "naabu": [["naabu", "-version"]],
    "Nuclei": [["nuclei", "-version"]],
    "Go runtime": [["go", "version"]],
}
TOOL_ROWS = list(CHECKS)
ROWS = ["System dependencies", *SYSTEM_DEPENDENCIES.keys(), "Go runtime", *TOOL_ROWS]


def safe_text(value: object) -> str:
    return str(value).replace("\x00", "")


class InstallerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_NAME)
        self.root.geometry("1280x900")
        self.root.minsize(1000, 720)
        self.root.configure(bg="#0c111b")
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        self.env = os.environ.copy()
        self.env["PATH"] = str(LOCAL_BIN) + os.pathsep + self.env.get("PATH", "")
        self.go_bin: Path | None = None
        self.session_lines: list[str] = []
        self.started_at: float | None = None
        self.row_data: dict[str, dict[str, str]] = {
            name: {"setup": "Not checked", "check": "Not checked", "notes": "Waiting for initial check", "version": "—"}
            for name in ROWS
        }

        self._styles()
        self._build_ui()
        self._poll_events()
        self._initial_check()

    def _styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#0c111b")
        style.configure("Panel.TFrame", background="#121a28")
        style.configure("TLabel", background="#0c111b", foreground="#e6edf7", font=("DejaVu Sans", 10))
        style.configure("Title.TLabel", font=("DejaVu Sans", 19, "bold"), foreground="#eff6ff", background="#0c111b")
        style.configure("Sub.TLabel", font=("DejaVu Sans", 10), foreground="#9aadc5", background="#0c111b")
        style.configure("TButton", font=("DejaVu Sans", 10, "bold"), padding=(12, 8))
        style.configure("Accent.TButton", background="#27b3a7", foreground="#061414")
        style.map("Accent.TButton", background=[("disabled", "#53616e"), ("active", "#45d4c6")])
        style.configure("Treeview", background="#0f1724", foreground="#e6edf7", fieldbackground="#0f1724", rowheight=28, bordercolor="#263448")
        style.configure("Treeview.Heading", background="#1b283a", foreground="#dce8f7", font=("DejaVu Sans", 9, "bold"))
        style.map("Treeview", background=[("selected", "#174a56")])
        style.configure("Horizontal.TProgressbar", troughcolor="#1a2635", background="#27b3a7", bordercolor="#1a2635", lightcolor="#27b3a7", darkcolor="#27b3a7")

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        top = ttk.Frame(outer)
        top.pack(fill="x")
        ttk.Label(top, text="MH SECURITY TOOL INSTALLER", style="Title.TLabel").pack(anchor="w")
        ttk.Label(top, text="Kali / Debian • Per-component install status • Final verification • Version inventory", style="Sub.TLabel").pack(anchor="w", pady=(4, 10))

        cards = ttk.Frame(outer)
        cards.pack(fill="x", pady=(0, 10))
        self.summary_var = tk.StringVar(value="Checking packages and tool versions…")
        summary = tk.Label(cards, textvariable=self.summary_var, bg="#121a28", fg="#c8d7e8", font=("DejaVu Sans", 10), anchor="w", padx=14, pady=10)
        summary.pack(fill="x")

        table_wrap = ttk.Frame(outer, style="Panel.TFrame", padding=7)
        table_wrap.pack(fill="both", expand=False, pady=(0, 8))
        columns = ("setup", "check", "notes", "version")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="tree headings", height=13)
        self.tree.heading("#0", text="Component")
        self.tree.heading("setup", text="Install status")
        self.tree.heading("check", text="Final check")
        self.tree.heading("notes", text="Details")
        self.tree.heading("version", text="Version")
        self.tree.column("#0", width=175, minwidth=145, stretch=False)
        self.tree.column("setup", width=135, minwidth=120, stretch=False)
        self.tree.column("check", width=100, minwidth=90, stretch=False)
        self.tree.column("notes", width=500, minwidth=300, stretch=True)
        self.tree.column("version", width=210, minwidth=150, stretch=False)

        # Show APT dependencies as expandable child rows under one summary row.
        self.tree.insert("", "end", iid="System dependencies", text="System dependencies", values=("Checking…", "Not checked", "Package-by-package verification", "—"))
        for name in SYSTEM_DEPENDENCIES:
            self.tree.insert("System dependencies", "end", iid=name, text=name, values=("Checking…", "Not checked", "—", "—"))
        self.tree.item("System dependencies", open=True)
        self.tree.insert("", "end", iid="Go runtime", text="Go runtime", values=("Checking…", "Not checked", "—", "—"))
        for name in TOOL_ROWS:
            self.tree.insert("", "end", iid=name, text=name, values=("Checking…", "Not checked", "—", "—"))

        self.tree.tag_configure("ok", foreground="#63e6a5")
        self.tree.tag_configure("fail", foreground="#ff7b86")
        self.tree.tag_configure("run", foreground="#ffd166")
        self.tree.tag_configure("idle", foreground="#b9c8da")
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._show_selected_detail)

        control = ttk.Frame(outer)
        control.pack(fill="x", pady=(0, 7))
        self.install_btn = ttk.Button(control, text="⬇ Download & Install All", style="Accent.TButton", command=self.start_install)
        self.install_btn.pack(side="left")
        self.check_btn = ttk.Button(control, text="↻ Re-check Tools", command=self.start_recheck)
        self.check_btn.pack(side="left", padx=(8, 0))
        self.open_report_btn = ttk.Button(control, text="Open Report Folder", command=self.open_report_folder)
        self.open_report_btn.pack(side="left", padx=(8, 0))
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(control, textvariable=self.progress_var, style="Sub.TLabel").pack(side="right")
        self.progress = ttk.Progressbar(outer, mode="determinate", maximum=100, value=0)
        self.progress.pack(fill="x", pady=(0, 8))

        detail_frame = ttk.Frame(outer, style="Panel.TFrame", padding=(9, 6))
        detail_frame.pack(fill="x", pady=(0, 8))
        ttk.Label(detail_frame, text="SELECTED COMPONENT DETAILS", font=("DejaVu Sans", 9, "bold"), background="#121a28", foreground="#9aadc5").pack(anchor="w")
        self.detail_var = tk.StringVar(value="Select a component row to see its package path, verification method, result and version.")
        self.detail_label = tk.Label(detail_frame, textvariable=self.detail_var, bg="#121a28", fg="#c8d7e8", font=("DejaVu Sans Mono", 9), anchor="w", justify="left", wraplength=1180, padx=4, pady=5)
        self.detail_label.pack(fill="x")

        log_frame = ttk.Frame(outer)
        log_frame.pack(fill="both", expand=True)
        ttk.Label(log_frame, text="LIVE LOG", font=("DejaVu Sans", 9, "bold")).pack(anchor="w", pady=(0, 4))
        log_holder = ttk.Frame(log_frame)
        log_holder.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_holder, bg="#080d15", fg="#c5d5e8", insertbackground="#ffffff", relief="flat", wrap="word", font=("DejaVu Sans Mono", 9), padx=10, pady=8, height=7)
        scroll = ttk.Scrollbar(log_holder, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.log_text.tag_configure("good", foreground="#63e6a5")
        self.log_text.tag_configure("bad", foreground="#ff7b86")
        self.log_text.tag_configure("info", foreground="#7dd3fc")
        self.log_text.tag_configure("warn", foreground="#ffd166")
        self.log_text.configure(state="disabled")

        foot = ttk.Label(outer, text="Use only on systems you own or are explicitly authorized to audit. This installer downloads tools; it does not scan targets.", style="Sub.TLabel")
        foot.pack(anchor="w", pady=(7, 0))

    def log(self, msg: str, kind: str = "normal"):
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {safe_text(msg)}"
        self.session_lines.append(line)
        tag = kind if kind in {"good", "bad", "info", "warn"} else None
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def post_log(self, message: str, kind: str = "normal"):
        self.events.put(("log", message, kind))

    def set_row(self, component: str, setup: str | None = None, check: str | None = None,
                notes: str | None = None, version: str | None = None):
        if component not in self.row_data:
            return
        row = self.row_data[component]
        if setup is not None:
            row["setup"] = setup
        if check is not None:
            row["check"] = check
        if notes is not None:
            row["notes"] = notes
        if version is not None:
            row["version"] = version
        tag = "idle"
        test = row["check"].strip().lower()
        inst = row["setup"].strip().lower()
        if test in {"missing", "failed", "fail", "not ok"} or "failed" in inst or "not installed" in inst:
            tag = "fail"
        elif "running" in inst or "installing" in inst or "checking" in inst:
            tag = "run"
        elif test == "ok" or inst in {"installed", "already installed", "ready"}:
            tag = "ok"
        if component in self.tree.get_children("") or component in self.tree.get_children("System dependencies"):
            try:
                self.tree.item(component, values=(row["setup"], row["check"], row["notes"], row["version"]), tags=(tag,))
            except tk.TclError:
                pass

    def _show_selected_detail(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        name = selected[0]
        row = self.row_data.get(name, {})
        if name == "System dependencies":
            detail = row.get("notes", "System package summary")
        elif name in SYSTEM_DEPENDENCIES:
            cfg = SYSTEM_DEPENDENCIES[name]
            detail = f"Package: {cfg['package']} | Purpose: {cfg['purpose']} | {row.get('notes', 'No additional details')} | Version: {row.get('version', '—')}"
        elif name == "Go runtime":
            detail = f"Go runtime | {row.get('notes', 'No additional details')} | Version: {row.get('version', '—')}"
        else:
            entry = CHECKS.get(name)
            command = " ".join(entry[1]) if entry else "—"
            detail = f"Verification command: {command} | {row.get('notes', 'No additional details')} | Version: {row.get('version', '—')}"
        self.detail_var.set(detail)

    def _package_info(self, package: str) -> tuple[bool, str, str]:
        """Return installed state, package version and dpkg detail for an APT package."""
        try:
            status = subprocess.run(
                ["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                timeout=8, env=self.env, check=False,
            )
            state = (status.stdout or "").strip()
            installed = status.returncode == 0 and state == "installed"
            version = "—"
            if installed:
                ver = subprocess.run(
                    ["dpkg-query", "-W", "-f=${Version}", package],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                    timeout=8, env=self.env, check=False,
                )
                version = (ver.stdout or "").strip() or "Unknown"
            details = f"APT package: {package}; dpkg state: {state or 'not found'}"
            return installed, version if installed else "Not installed", details
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "Unknown", f"Could not inspect package {package}: {exc}"

    def _inspect_dependency(self, name: str) -> tuple[bool, str, str]:
        cfg = SYSTEM_DEPENDENCIES[name]
        installed, version, details = self._package_info(cfg["package"])
        binary = cfg.get("binary")
        if binary:
            executable = shutil.which(binary, path=self.env.get("PATH", ""))
            details += f"; executable: {executable or 'not found in PATH'}"
            if name == "Tkinter" and executable:
                try:
                    probe = subprocess.run([executable, "-c", "import tkinter; print('Tkinter import OK')"],
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                           timeout=8, env=self.env, check=False)
                    installed = installed and probe.returncode == 0
                    details += f"; GUI import test: {(probe.stdout or '').strip() or ('passed' if probe.returncode == 0 else 'failed')}"
                except (OSError, subprocess.TimeoutExpired) as exc:
                    installed = False
                    details += f"; GUI import test failed: {exc}"
            elif executable and cfg.get("version_cmd"):
                try:
                    probe = subprocess.run(cfg["version_cmd"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, timeout=8, env=self.env, check=False)
                    output = (probe.stdout or "").strip().splitlines()
                    if probe.returncode == 0 and output:
                        details += f"; command version: {output[0][:100]}"
                except (OSError, subprocess.TimeoutExpired):
                    pass
            else:
                installed = False
        return installed, version, details + f"; purpose: {cfg['purpose']}"

    def _tool_version(self, name: str, env: dict[str, str] | None = None) -> str:
        run_env = env or self.env
        path = run_env.get("PATH", os.environ.get("PATH", ""))
        if name == "Go runtime":
            commands = VERSION_COMMANDS["Go runtime"]
        else:
            binary = CHECKS.get(name, (None, None))[0]
            if not binary or not shutil.which(binary, path=path):
                return "Not installed"
            commands = VERSION_COMMANDS.get(name, [])
        if name == "Photon":
            git = shutil.which("git", path=path)
            if git and (PHOTON_DIR / ".git").is_dir():
                try:
                    res = subprocess.run([git, "-C", str(PHOTON_DIR), "log", "-1", "--format=git %h (%cs)"],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, timeout=10, env=run_env, check=False)
                    out = (res.stdout or "").strip()
                    if res.returncode == 0 and out:
                        return out[:180]
                except (OSError, subprocess.TimeoutExpired):
                    pass
            return "Installed (git commit unavailable)"
        for command in commands:
            try:
                res = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, timeout=12, env=run_env, check=False)
                lines = [line.strip() for line in (res.stdout or "").splitlines() if line.strip()]
                if res.returncode == 0 and lines:
                    return lines[0][:180]
            except (OSError, subprocess.TimeoutExpired):
                continue
        # Python tools installed through pipx can report their package metadata.
        if name in {"Arjun", "DNSRecon"}:
            pipx = shutil.which("pipx", path=path)
            package = "arjun" if name == "Arjun" else "dnsrecon"
            if pipx:
                try:
                    res = subprocess.run([pipx, "runpip", package, "show", package],
                                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, timeout=15, env=run_env, check=False)
                    for line in (res.stdout or "").splitlines():
                        if line.lower().startswith("version:"):
                            return line.split(":", 1)[1].strip()
                except (OSError, subprocess.TimeoutExpired):
                    pass
        # APT metadata is a final fallback for packaged tools.
        pkg_map = {"DNSRecon": "dnsrecon", "Nmap": "nmap"}
        if name in pkg_map:
            installed, version, _ = self._package_info(pkg_map[name])
            if installed:
                return version
        return "Unknown (tool responded, version flag unsupported)"

    def _tool_details(self, name: str, ok: bool, note: str, env: dict[str, str] | None = None) -> str:
        run_env = env or self.env
        entry = CHECKS.get(name)
        if not entry:
            return note
        binary, command = entry
        executable = shutil.which(binary, path=run_env.get("PATH", ""))
        state = "verification passed" if ok else "verification failed"
        return f"Binary: {executable or 'not found'}; check: {' '.join(command)}; {state}; output: {note[:180]}"

    def _initial_check(self):
        def worker():
            dep_ok_count = 0
            for name in SYSTEM_DEPENDENCIES:
                installed, version, detail = self._inspect_dependency(name)
                setup = "Already installed" if installed else "Not installed"
                check = "OK" if installed else "Missing"
                self.events.put(("status", name, setup, check, detail, version))
                dep_ok_count += int(installed)
            dep_all = dep_ok_count == len(SYSTEM_DEPENDENCIES)
            dep_setup = "Already installed" if dep_all else ("Partially installed" if dep_ok_count else "Not installed")
            dep_detail = f"{dep_ok_count}/{len(SYSTEM_DEPENDENCIES)} required APT packages and command checks passed"
            self.events.put(("status", "System dependencies", dep_setup, "OK" if dep_all else "Missing", dep_detail, "—"))

            found = 0
            for name in TOOL_ROWS:
                ok, note = self.verify(name, self.env, silent=True)
                setup = "Already installed" if ok else "Not installed"
                version = self._tool_version(name, self.env) if ok else "Not installed"
                detail = self._tool_details(name, ok, note, self.env)
                self.events.put(("status", name, setup, "OK" if ok else "Missing", detail, version))
                found += int(ok)

            go_cmd = shutil.which("go", path=self.env.get("PATH", ""))
            go_ok = bool(go_cmd)
            go_version = self._tool_version("Go runtime", self.env) if go_ok else "Not installed"
            go_details = f"Executable: {go_cmd or 'not found in PATH'}; source: existing PATH installation or MH cache"
            self.events.put(("status", "Go runtime", "Already installed" if go_ok else "Not installed",
                             "OK" if go_ok else "Missing", go_details, go_version))
            self.events.put(("summary", f"Initial check: {found}/{len(TOOL_ROWS)} tools OK • {dep_ok_count}/{len(SYSTEM_DEPENDENCIES)} dependencies OK • Go: {'OK' if go_ok else 'Missing'}"))
        threading.Thread(target=worker, daemon=True).start()

    def start_install(self):
        if self.busy:
            return
        if platform.system() != "Linux":
            messagebox.showerror("Unsupported OS", "This installer is designed for Kali/Debian Linux.")
            return
        if os.geteuid() == 0:
            messagebox.showerror("Run as normal user", "Do not run the Python GUI with sudo. Start run_mh_installer.sh; it uses sudo only for apt packages and installs Go tools in your user account.")
            return
        self.busy = True
        self.install_btn.configure(state="disabled")
        self.check_btn.configure(state="disabled")
        self.progress.configure(value=0, maximum=100)
        self.started_at = time.time()
        self.post_log("Starting sequential download and installation…", "info")
        threading.Thread(target=self._install_worker_guarded, daemon=True).start()

    def start_recheck(self):
        if self.busy:
            return
        self.busy = True
        self.install_btn.configure(state="disabled")
        self.check_btn.configure(state="disabled")
        self.progress.configure(value=0, maximum=len(TOOL_ROWS) + len(SYSTEM_DEPENDENCIES) + 1)
        threading.Thread(target=self._recheck_worker, daemon=True).start()

    def _recheck_worker(self):
        total = len(TOOL_ROWS) + len(SYSTEM_DEPENDENCIES) + 1
        current = 0
        dep_count = 0
        for name in SYSTEM_DEPENDENCIES:
            installed, version, detail = self._inspect_dependency(name)
            old_setup = self.row_data.get(name, {}).get("setup", "")
            setup = old_setup if old_setup in {"Installed", "Already installed"} and installed else ("Already installed" if installed else "Not installed")
            self.events.put(("status", name, setup, "OK" if installed else "Missing", detail, version))
            dep_count += int(installed)
            current += 1
            self.events.put(("progress", current, total, f"Checking dependency: {name}"))
        dep_ok = dep_count == len(SYSTEM_DEPENDENCIES)
        self.events.put(("status", "System dependencies", "Already installed" if dep_ok else "Partially installed",
                         "OK" if dep_ok else "Missing", f"{dep_count}/{len(SYSTEM_DEPENDENCIES)} packages and command checks passed", "—"))

        tools_ok_count = 0
        for name in TOOL_ROWS:
            ok, note = self.verify(name, self.env)
            old_setup = self.row_data.get(name, {}).get("setup", "")
            setup = old_setup if old_setup in {"Installed", "Already installed"} and ok else ("Already installed" if ok else "Not installed")
            version = self._tool_version(name, self.env) if ok else "Not installed"
            self.events.put(("status", name, setup, "OK" if ok else "Missing", self._tool_details(name, ok, note), version))
            tools_ok_count += int(ok)
            current += 1
            self.events.put(("progress", current, total, f"Checking {name}"))

        go_cmd = shutil.which("go", path=self.env.get("PATH", ""))
        go_ok = False
        go_version = "Not installed"
        if go_cmd:
            try:
                result = subprocess.run([go_cmd, "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, timeout=15, env=self.env, check=False)
                go_ok = result.returncode == 0
                if go_ok:
                    go_version = (result.stdout or "").strip().splitlines()[0]
            except (OSError, subprocess.TimeoutExpired):
                go_ok = False
        self.events.put(("status", "Go runtime", "Already installed" if go_ok else "Not installed", "OK" if go_ok else "Missing",
                         f"Executable: {go_cmd or 'not found'}; version check {'passed' if go_ok else 'failed'}", go_version))
        current += 1
        self.events.put(("progress", current, total, "Checking Go runtime"))
        all_ok = dep_ok and tools_ok_count == len(TOOL_ROWS) and go_ok
        self.events.put(("summary", f"Final check: {tools_ok_count}/{len(TOOL_ROWS)} tools OK • {dep_count}/{len(SYSTEM_DEPENDENCIES)} dependencies OK • Go {'OK' if go_ok else 'MISSING'}"))
        self.events.put(("progress", total, total, "Re-check complete"))
        self.events.put(("finished", all_ok, f"Final check: {tools_ok_count}/{len(TOOL_ROWS)} tools; dependencies {dep_count}/{len(SYSTEM_DEPENDENCIES)}; Go {'OK' if go_ok else 'MISSING'}"))

    def _install_worker_guarded(self):
        try:
            self._install_worker()
        except Exception as exc:
            self.post_log(f"Unexpected installer error: {type(exc).__name__}: {exc}", "bad")
            self.events.put(("finished", False, f"Installer stopped unexpectedly: {exc}"))

    def _install_worker(self):
        failures: list[str] = []
        setup_states: dict[str, str] = {}
        total = 2 + 1 + 1 + 1 + 1 + len(GO_TOOLS) + len(SYSTEM_DEPENDENCIES) + len(TOOL_ROWS) + 1
        done = 0

        def step(label: str):
            nonlocal done
            done += 1
            self.events.put(("progress", min(done, total), total, label))

        BASE_DIR.mkdir(parents=True, exist_ok=True)
        LOCAL_BIN.mkdir(parents=True, exist_ok=True)
        self.env = os.environ.copy()
        self.env["PATH"] = str(LOCAL_BIN) + os.pathsep + self.env.get("PATH", "")
        self.env["PIPX_BIN_DIR"] = str(LOCAL_BIN)
        self.env["GOBIN"] = str(LOCAL_BIN)
        self._ensure_bash_path()

        # Snapshot package state first so pre-existing packages remain labelled
        # "Already installed" after the installer finishes.
        preinstalled: dict[str, bool] = {}
        nmap_preinstalled = self._package_info("nmap")[0] and bool(shutil.which("nmap", path=self.env.get("PATH", "")))
        for name in SYSTEM_DEPENDENCIES:
            present, version, details = self._inspect_dependency(name)
            preinstalled[name] = present
            self.events.put(("status", name, "Already installed" if present else "Not installed",
                             "OK" if present else "Missing", details, version))
        dep_pre_count = sum(preinstalled.values())
        self.events.put(("status", "System dependencies", "Already installed" if dep_pre_count == len(preinstalled) else "Partially installed",
                         "OK" if dep_pre_count == len(preinstalled) else "Missing",
                         f"Before install: {dep_pre_count}/{len(preinstalled)} dependencies present", "—"))

        # Stage 1: update APT and install only what is missing (APT itself skips
        # already-current packages; the GUI still preserves the pre-install state).
        self.events.put(("status", "System dependencies", "Running", None, "Updating package indexes then checking every required package", "—"))
        self.post_log("Updating APT package metadata…", "info")
        apt_update = self.run_command(["sudo", "-n", "apt-get", "update"], timeout=900, env=self.env)
        step("APT update")
        packages = [cfg["package"] for cfg in SYSTEM_DEPENDENCIES.values()] + ["nmap"]
        packages = list(dict.fromkeys(packages))
        self.post_log("Installing system dependencies and Nmap…", "info")
        apt_install = self.run_command(["sudo", "-n", "apt-get", "install", "-y", *packages], timeout=1200, env=self.env)
        step("System dependency install")
        dep_count = 0
        for name in SYSTEM_DEPENDENCIES:
            present, version, details = self._inspect_dependency(name)
            setup = "Already installed" if preinstalled.get(name) and present else ("Installed" if present else "Failed")
            setup_states[name] = setup
            self.events.put(("status", name, setup, "OK" if present else "Missing", details, version))
            dep_count += int(present)
            if not present:
                failures.append(name)
        dep_ok = dep_count == len(SYSTEM_DEPENDENCIES) and apt_install == 0
        parent_setup = "Already installed" if dep_pre_count == len(preinstalled) and dep_ok else ("Installed" if dep_ok else "Failed")
        setup_states["System dependencies"] = parent_setup
        self.events.put(("status", "System dependencies", parent_setup, "OK" if dep_ok else "Missing",
                         f"APT exit code: {apt_install}; verified dependencies: {dep_count}/{len(SYSTEM_DEPENDENCIES)}", "—"))
        if not dep_ok:
            failures.append("System dependencies")
        if shutil.which("nmap", path=self.env.get("PATH")):
            self.events.put(("status", "Nmap", "Already installed" if nmap_preinstalled else "Installed", None,
                             "Nmap package is available; final version check follows", self._tool_version("Nmap", self.env)))
            setup_states["Nmap"] = "Already installed" if nmap_preinstalled else "Installed"
        else:
            self.events.put(("status", "Nmap", "Failed", None, "nmap binary was not found after APT step", "Not installed"))
            setup_states["Nmap"] = "Failed"
            failures.append("Nmap")

        # Stage 2: Reuse an existing Go runtime; otherwise obtain the latest
        # official Linux release with SHA-256 verification.
        existing_go = shutil.which("go", path=self.env.get("PATH", ""))
        self.events.put(("status", "Go runtime", "Running", None, "Checking existing Go runtime before download", "—"))
        try:
            if existing_go:
                go_test = subprocess.run([existing_go, "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                         text=True, timeout=15, env=self.env, check=False)
                if go_test.returncode != 0:
                    raise RuntimeError("Existing Go executable did not pass 'go version'")
                setup_states["Go runtime"] = "Already installed"
                go_version = (go_test.stdout or "").strip().splitlines()[0]
                self.events.put(("status", "Go runtime", "Already installed", None, f"Executable: {existing_go}", go_version))
                self.post_log(f"Reusing existing Go runtime: {go_version}", "good")
            else:
                self.go_bin = self.install_latest_go()
                self.env["PATH"] = str(LOCAL_BIN) + os.pathsep + str(self.go_bin / "bin") + os.pathsep + self.env.get("PATH", "")
                self.env["GOBIN"] = str(LOCAL_BIN)
                setup_states["Go runtime"] = "Installed"
                go_version = self._tool_version("Go runtime", self.env)
                self.events.put(("status", "Go runtime", "Installed", None, f"Installed to {self.go_bin / 'bin' / 'go'}", go_version))
        except Exception as exc:
            self.post_log(f"Go install/check failed: {exc}", "bad")
            self.events.put(("status", "Go runtime", "Failed", None, str(exc), "Unknown"))
            setup_states["Go runtime"] = "Failed"
            failures.append("Go runtime")
        step("Go runtime")

        # Stage 3: DNSRecon via APT first, pipx fallback if needed.
        self.events.put(("status", "DNSRecon", "Running", None, "Installing from APT; pipx fallback if APT fails", "—"))
        if self.verify("DNSRecon", self.env, silent=True)[0]:
            setup_states["DNSRecon"] = "Already installed"
            self.events.put(("status", "DNSRecon", "Already installed", None, self._tool_details("DNSRecon", True, "Existing command passed check"), self._tool_version("DNSRecon", self.env)))
        else:
            rc = self.run_command(["sudo", "-n", "apt-get", "install", "-y", "dnsrecon"], timeout=600, env=self.env)
            if rc == 0 and self.verify("DNSRecon", self.env, silent=True)[0]:
                setup_states["DNSRecon"] = "Installed"
                self.events.put(("status", "DNSRecon", "Installed", None, self._tool_details("DNSRecon", True, "Installed from APT"), self._tool_version("DNSRecon", self.env)))
            else:
                pipx = shutil.which("pipx", path=self.env.get("PATH"))
                rc2 = self.run_command([pipx, "install", "--force", "dnsrecon"], timeout=900, env=self.env) if pipx else 127
                ok, note = self.verify("DNSRecon", self.env, silent=True)
                if rc2 == 0 and ok:
                    setup_states["DNSRecon"] = "Installed"
                    self.events.put(("status", "DNSRecon", "Installed", None, self._tool_details("DNSRecon", True, "Installed through pipx fallback: " + note), self._tool_version("DNSRecon", self.env)))
                else:
                    setup_states["DNSRecon"] = "Failed"
                    self.events.put(("status", "DNSRecon", "Failed", None, "APT and pipx installation did not verify", "Unknown"))
                    failures.append("DNSRecon")
        step("DNSRecon")

        # Stage 4: Arjun through pipx.
        self.events.put(("status", "Arjun", "Running", None, "Installing in isolated pipx environment", "—"))
        if self.verify("Arjun", self.env, silent=True)[0]:
            setup_states["Arjun"] = "Already installed"
            self.events.put(("status", "Arjun", "Already installed", None, self._tool_details("Arjun", True, "Existing command passed check"), self._tool_version("Arjun", self.env)))
        else:
            pipx = shutil.which("pipx", path=self.env.get("PATH"))
            rc = self.run_command([pipx, "install", "--force", "arjun"], timeout=900, env=self.env) if pipx else 127
            ok, note = self.verify("Arjun", self.env, silent=True)
            if rc == 0 and ok:
                setup_states["Arjun"] = "Installed"
                self.events.put(("status", "Arjun", "Installed", None, self._tool_details("Arjun", True, note), self._tool_version("Arjun", self.env)))
            else:
                setup_states["Arjun"] = "Failed"
                self.events.put(("status", "Arjun", "Failed", None, "pipx install or verification failed", "Unknown"))
                failures.append("Arjun")
        step("Arjun")

        # Stage 4b: Photon (OSINT crawler) from GitHub into an isolated venv.
        self.events.put(("status", "Photon", "Running", None, "Cloning s0md3v/Photon and building an isolated virtualenv", "—"))
        if self.verify("Photon", self.env, silent=True)[0]:
            setup_states["Photon"] = "Already installed"
            self.events.put(("status", "Photon", "Already installed", None, self._tool_details("Photon", True, "Existing command passed check"), self._tool_version("Photon", self.env)))
        else:
            installed_ok = self.install_photon()
            ok, note = self.verify("Photon", self.env, silent=True)
            if installed_ok and ok:
                setup_states["Photon"] = "Installed"
                self.events.put(("status", "Photon", "Installed", None, self._tool_details("Photon", True, note), self._tool_version("Photon", self.env)))
            else:
                setup_states["Photon"] = "Failed"
                self.events.put(("status", "Photon", "Failed", None, "git clone, venv setup or verification failed: " + note, "Unknown"))
                failures.append("Photon")
        step("Photon")

        # Stage 5: Sequential ProjectDiscovery Go tools.
        for name, (binary, install_cmd, check_cmd, extra_env) in GO_TOOLS.items():
            self.events.put(("status", name, "Running", None, "Installing/verifying from upstream Go module", "—"))
            if not shutil.which("go", path=self.env.get("PATH", "")):
                setup_states[name] = "Failed"
                self.events.put(("status", name, "Failed", None, "Go executable unavailable", "Not installed"))
                failures.append(name)
                step(name)
                continue
            if self.verify(name, self.env, silent=True)[0]:
                setup_states[name] = "Already installed"
                ok, note = self.verify(name, self.env, silent=True)
                self.events.put(("status", name, "Already installed", None, self._tool_details(name, ok, note), self._tool_version(name, self.env)))
                step(name)
                continue
            install_env = self.env.copy()
            install_env.update(extra_env)
            install_env["GOBIN"] = str(LOCAL_BIN)
            rc = self.run_command(install_cmd, timeout=1800, env=install_env)
            ok, note = self.verify(name, install_env, silent=True) if rc == 0 else (False, f"go install exit code {rc}")
            if ok:
                setup_states[name] = "Installed"
                self.events.put(("status", name, "Installed", None, self._tool_details(name, True, note, install_env), self._tool_version(name, install_env)))
            else:
                setup_states[name] = "Failed"
                self.events.put(("status", name, "Failed", None, self._tool_details(name, False, note, install_env), "Unknown"))
                failures.append(name)
            step(name)

        # Stage 6: Final verification for every dependency, runtime, and tool.
        self.post_log("Installation stages finished; running final package, tool and version checks…", "info")
        verified: list[str] = []
        final_failed: list[str] = []
        final_inventory: dict[str, dict[str, str]] = {}
        dep_count = 0
        for name in SYSTEM_DEPENDENCIES:
            ok, version, details = self._inspect_dependency(name)
            install_status = setup_states.get(name, "Already installed" if ok else "Failed")
            check_status = "OK" if ok else "Missing"
            self.events.put(("status", name, install_status, check_status, details, version))
            final_inventory[name] = {"setup": install_status, "check": check_status, "notes": details, "version": version}
            dep_count += int(ok)
            step(f"Final check: {name}")
            if not ok:
                final_failed.append(f"Dependency: {name}")
        dep_ok = dep_count == len(SYSTEM_DEPENDENCIES)
        parent_setup = setup_states.get("System dependencies", "Installed" if dep_ok else "Failed")
        parent_check = "OK" if dep_ok else "Missing"
        parent_details = f"Final package checks: {dep_count}/{len(SYSTEM_DEPENDENCIES)}"
        self.events.put(("status", "System dependencies", parent_setup, parent_check, parent_details, "—"))
        final_inventory["System dependencies"] = {"setup": parent_setup, "check": parent_check, "notes": parent_details, "version": "—"}

        for name in TOOL_ROWS:
            ok, note = self.verify(name, self.env)
            install_status = setup_states.get(name, "Already installed" if ok else "Failed")
            check_status = "OK" if ok else "Missing"
            version = self._tool_version(name, self.env) if ok else "Not installed"
            details = self._tool_details(name, ok, note)
            self.events.put(("status", name, install_status, check_status, details, version))
            final_inventory[name] = {"setup": install_status, "check": check_status, "notes": details, "version": version}
            if ok:
                verified.append(name)
            else:
                final_failed.append(name)
            step(f"Final check: {name}")

        go_cmd = shutil.which("go", path=self.env.get("PATH", ""))
        go_ok = False
        go_version = "Not installed"
        go_details = f"Executable: {go_cmd or 'not found in PATH'}"
        if go_cmd:
            try:
                go_result = subprocess.run([go_cmd, "version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           text=True, timeout=15, env=self.env, check=False)
                go_ok = go_result.returncode == 0
                go_version = (go_result.stdout or "").strip().splitlines()[0] if go_ok and (go_result.stdout or "").strip() else "Unknown"
                go_details += "; go version check " + ("passed" if go_ok else f"failed with exit code {go_result.returncode}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                go_details += f"; check error: {exc}"
        go_setup = setup_states.get("Go runtime", "Already installed" if go_ok else "Failed")
        self.events.put(("status", "Go runtime", go_setup, "OK" if go_ok else "Missing", go_details, go_version))
        final_inventory["Go runtime"] = {"setup": go_setup, "check": "OK" if go_ok else "Missing", "notes": go_details, "version": go_version}
        if not go_ok:
            final_failed.append("Go runtime")
        step("Final check: Go runtime")
        overall_ok = not final_failed
        report = self._save_report(verified, final_failed, go_ok, dep_ok, final_inventory)
        self.events.put(("progress", total, total, "Final verification complete"))
        self.events.put(("finished", overall_ok,
                         f"Verified {len(verified)}/{len(TOOL_ROWS)} tools; dependencies {dep_count}/{len(SYSTEM_DEPENDENCIES)}; Go {'OK' if go_ok else 'MISSING'}. Report: {report}"))

    def _ensure_bash_path(self):
        bashrc = Path.home() / ".bashrc"
        line = 'export PATH="$HOME/.local/bin:$PATH"'
        try:
            content = bashrc.read_text(errors="ignore") if bashrc.exists() else ""
            if line not in content:
                with bashrc.open("a") as f:
                    f.write("\n# Added by MH Security Tool Installer\n" + line + "\n")
                self.post_log("Added ~/.local/bin to ~/.bashrc PATH.", "good")
        except OSError as exc:
            self.post_log(f"Could not update ~/.bashrc PATH automatically: {exc}", "warn")

    def install_latest_go(self) -> Path:
        system = platform.system().lower()
        machine_map = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64", "i386": "386", "i686": "386", "armv6l": "armv6l"}
        arch = machine_map.get(platform.machine().lower())
        if system != "linux" or not arch:
            raise RuntimeError(f"Unsupported Go archive platform: {system}/{platform.machine()}")
        self.post_log("Reading the official Go release manifest (go.dev)…", "info")
        req = urllib.request.Request("https://go.dev/dl/?mode=json", headers={"User-Agent": "MH-Tool-Installer/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            versions = json.loads(response.read().decode("utf-8"))
        stable = [item for item in versions if item.get("stable") is True]
        if not stable:
            raise RuntimeError("Official Go manifest did not return a stable release")
        # API normally returns newest first; still sort by numeric version for robustness.
        def version_key(item):
            return tuple(int(x) for x in item["version"].removeprefix("go").split(".") if x.isdigit())
        release = sorted(stable, key=version_key, reverse=True)[0]
        version = release["version"]
        file_info = next((f for f in release.get("files", []) if f.get("os") == "linux" and f.get("arch") == arch and f.get("kind") == "archive"), None)
        if not file_info:
            raise RuntimeError(f"No official Linux {arch} archive found for {version}")
        filename = file_info["filename"]
        expected_hash = file_info["sha256"].lower()
        GO_SDK_DIR.mkdir(parents=True, exist_ok=True)
        target = GO_SDK_DIR / version
        target_go = target / "bin" / "go"
        if target_go.is_file():
            self.post_log(f"Go {version} is already cached; reusing it.", "good")
            return target

        url = "https://go.dev/dl/" + filename
        with tempfile.TemporaryDirectory(prefix="go-download-", dir=str(GO_SDK_DIR)) as tmpdir:
            archive = Path(tmpdir) / filename
            self.post_log(f"Downloading official {version} ({arch}); checksum will be verified…", "info")
            req = urllib.request.Request(url, headers={"User-Agent": "MH-Tool-Installer/1.0"})
            hasher = hashlib.sha256()
            downloaded = 0
            last_pct = -1
            with urllib.request.urlopen(req, timeout=45) as response, archive.open("wb") as out:
                total_size = int(response.headers.get("Content-Length", "0") or 0)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    hasher.update(chunk)
                    downloaded += len(chunk)
                    if total_size:
                        pct = int(downloaded * 100 / total_size)
                        if pct >= last_pct + 10:
                            last_pct = pct
                            self.events.put(("download_progress", pct, f"Downloading Go: {pct}%"))
            actual_hash = hasher.hexdigest().lower()
            if actual_hash != expected_hash:
                raise RuntimeError(f"Go SHA-256 mismatch. Expected {expected_hash}, got {actual_hash}")
            self.post_log("Go archive SHA-256 verified successfully.", "good")
            extract_dir = Path(tmpdir) / "extract"
            extract_dir.mkdir()
            with tarfile.open(archive, "r:gz") as tf:
                members = tf.getmembers()
                for member in members:
                    p = Path(member.name)
                    if p.is_absolute() or ".." in p.parts or not (p.parts and p.parts[0] == "go"):
                        raise RuntimeError("Unexpected path found inside the Go archive")
                # This archive is from the official Go site and verified above.
                tf.extractall(extract_dir)
            extracted = extract_dir / "go"
            if not (extracted / "bin" / "go").is_file():
                raise RuntimeError("Downloaded archive did not contain go/bin/go")
            if target.exists():
                shutil.rmtree(target)
            shutil.move(str(extracted), str(target))
        self.post_log(f"Installed Go {version} under {target}", "good")
        return target

    def install_photon(self) -> bool:
        """Clone Photon, create a private venv, install requirements, add a launcher in ~/.local/bin."""
        path = self.env.get("PATH", "")
        git = shutil.which("git", path=path)
        python = shutil.which("python3", path=path)
        if not git or not python:
            self.post_log("Photon needs git and python3 on PATH.", "bad")
            return False
        if (PHOTON_DIR / ".git").is_dir():
            self.run_command([git, "-C", str(PHOTON_DIR), "pull", "--ff-only"], timeout=300, env=self.env)
        else:
            if PHOTON_DIR.exists():
                shutil.rmtree(PHOTON_DIR)
            if self.run_command([git, "clone", "--depth", "1", PHOTON_REPO, str(PHOTON_DIR)], timeout=600, env=self.env) != 0:
                return False
        if not (PHOTON_VENV / "bin" / "python").is_file():
            if self.run_command([python, "-m", "venv", str(PHOTON_VENV)], timeout=300, env=self.env) != 0:
                return False
        venv_python = str(PHOTON_VENV / "bin" / "python")
        requirements = PHOTON_DIR / "requirements.txt"
        if requirements.is_file():
            if self.run_command([venv_python, "-m", "pip", "install", "-r", str(requirements)], timeout=900, env=self.env) != 0:
                return False
        launcher = LOCAL_BIN / "photon"
        launcher.write_text(
            "#!/usr/bin/env bash\n"
            "# Launcher created by MH Security Tool Installer\n"
            f'exec "{venv_python}" "{PHOTON_DIR / "photon.py"}" "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        return True

    def run_command(self, command: list[str], timeout: int, env: dict[str, str] | None = None) -> int:
        command = [str(x) for x in command]
        self.post_log("$ " + " ".join(command), "info")
        try:
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env or self.env)
        except FileNotFoundError:
            self.post_log(f"Command not found: {command[0]}", "bad")
            return 127
        except OSError as exc:
            self.post_log(f"Could not start command: {exc}", "bad")
            return 126

        def reader():
            assert proc.stdout is not None
            for line in proc.stdout:
                self.events.put(("log", line.rstrip("\n"), "normal"))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            self.post_log(f"Timed out after {timeout}s: {' '.join(command)}", "bad")
            rc = 124
        thread.join(timeout=2)
        if rc == 0:
            self.post_log(f"Completed: {command[0]}", "good")
        else:
            self.post_log(f"Command returned exit code {rc}: {command[0]}", "bad")
        return rc

    def verify(self, name: str, env: dict[str, str] | None = None, silent: bool = False) -> tuple[bool, str]:
        entry = CHECKS.get(name)
        if not entry:
            return False, "No verification rule defined"
        binary, check_cmd = entry
        run_env = env or self.env
        path = run_env.get("PATH", os.environ.get("PATH", ""))
        executable = shutil.which(binary, path=path)
        if not executable:
            return False, f"{binary} not found in PATH"
        try:
            result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=20, env=run_env, check=False)
            lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
            note = (lines[0][:180] if lines else f"{binary} exited with code {result.returncode}")
            # Some CLIs return a non-zero code for a help screen. Treat them as
            # available only when their own executable responds with useful output.
            ok = result.returncode == 0 or (name in {"DNSRecon", "Arjun", "Photon"} and bool(lines))
            if not silent:
                self.post_log(f"{'PASS' if ok else 'FAIL'} {name}: {note}", "good" if ok else "bad")
            return ok, note
        except subprocess.TimeoutExpired:
            return False, f"{binary} verification timed out"
        except OSError as exc:
            return False, f"Could not execute {binary}: {exc}"

    def _save_report(self, verified: list[str], failed: list[str], go_ok: bool, dep_ok: bool,
                     inventory: dict[str, dict[str, str]] | None = None) -> str:
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            APP_NAME,
            f"Finished: {end_time}",
            f"OS: {platform.platform()}",
            f"Go runtime check: {'PASS' if go_ok else 'FAIL'}",
            f"System dependency check: {'PASS' if dep_ok else 'FAIL'}",
            f"Tools verified ({len(verified)}/{len(TOOL_ROWS)}): {', '.join(verified) or 'none'}",
            f"Tools missing/failed verification: {', '.join(failed) or 'none'}",
            "", "Component inventory (status | final check | version | details):"
        ]
        inventory = inventory or {}
        for name in ROWS:
            row = inventory.get(name, self.row_data.get(name, {}))
            lines.append(f"{name} | {row.get('setup', '—')} | {row.get('check', '—')} | {row.get('version', '—')} | {row.get('notes', '—')}")
        lines.extend(["", "Detailed session log:", *self.session_lines])
        REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.post_log(f"Saved installation report: {REPORT_PATH}", "good")
        return str(REPORT_PATH)

    def open_report_folder(self):
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["xdg-open", str(BASE_DIR)])
        except OSError as exc:
            messagebox.showerror("Could not open folder", str(exc))

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self.log(event[1], event[2])
                elif kind == "status":
                    _, component, setup, check, notes, *version = event
                    self.set_row(component, setup, check, notes, version[0] if version else None)
                elif kind == "progress":
                    _, current, total, label = event
                    self.progress.configure(maximum=max(total, 1), value=current)
                    self.progress_var.set(label)
                elif kind == "download_progress":
                    _, pct, label = event
                    self.progress_var.set(label)
                elif kind == "summary":
                    self.summary_var.set(event[1])
                elif kind == "finished":
                    _, ok, note = event
                    self.busy = False
                    self.install_btn.configure(state="normal")
                    self.check_btn.configure(state="normal")
                    self.summary_var.set(("✅ COMPLETE — " if ok else "⚠ ATTENTION REQUIRED — ") + note)
                    self.log(note, "good" if ok else "warn")
                    if ok:
                        messagebox.showinfo("Installation complete", note)
                    else:
                        messagebox.showwarning("Installation needs attention", note + "\n\nOpen the live log and report file to see failed steps.")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)


def main():
    if platform.system() != "Linux":
        print("This installer is designed for Kali/Debian Linux.", file=sys.stderr)
        return 2
    try:
        import tkinter  # noqa: F401
    except Exception:
        print("Tkinter is missing. Run ./run_mh_installer.sh so it can install python3-tk first.", file=sys.stderr)
        return 2
    root = tk.Tk()
    InstallerApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
