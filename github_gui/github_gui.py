import os
import json
import base64
import threading
import subprocess
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import requests

# --- THEME COLORS ---
GH_BG = "#0d1117"
GH_SIDEBAR = "#161b22"
GH_TEXT = "#c9d1d9"
GH_GREEN = "#238636"
GH_BLUE = "#1f6feb"
GH_BORDER = "#30363d"
GH_RED = "#da3633"
GH_GRAY = "#8b949e"

CONFIG_FILE = Path.home() / '.github_cli_config.json'

class GitHubProV8(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("GIT-TOOL PRO V8.5 - PRODUCTION")
        self.geometry("1300x950")
        self.configure(fg_color=GH_BG)

        # State Management
        self.config = self._load_config()
        self.token = self.config.get('github_token', '')
        self.username = None
        self.all_repos = []
        self.staged_files = [] 
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._init_ui()
        
        if self.token:
            self.verify_auth()
            self.show_frame("home")
        else:
            self.show_frame("settings")

    def _load_config(self):
        if CONFIG_FILE.exists():
            try: return json.loads(CONFIG_FILE.read_text())
            except: return {}
        return {}

    def _save_config(self):
        CONFIG_FILE.write_text(json.dumps({'github_token': self.token}, indent=4))

    def _init_ui(self):
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=GH_SIDEBAR, border_color=GH_BORDER, border_width=1)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="GIT-PRO V8.5", font=ctk.CTkFont(size=22, weight="bold")).pack(pady=30)
        
        self._nav_btn("📊 Dashboard", "home")
        self._nav_btn("📦 Repositories", "list")
        self._nav_btn("⚡ Ultra Sync", "sync")
        self._nav_btn("📥 Clone Utility", "clone")
        self._nav_btn("⚙️ Settings", "settings")
        
        self.status_ball = ctk.CTkLabel(self.sidebar, text="● Offline", text_color=GH_RED)
        self.status_ball.pack(side="bottom", pady=10)
        self.user_lbl = ctk.CTkLabel(self.sidebar, text="Unauthorized", text_color=GH_GRAY)
        self.user_lbl.pack(side="bottom", pady=(0, 20))

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)
        self.frames = {}

        self._build_home()
        self._build_repo_list()
        self._build_sync_engine()
        self._build_clone_tool()
        self._build_settings()
        self._build_log_console()

    def _nav_btn(self, text, frame_name):
        btn = ctk.CTkButton(self.sidebar, text=text, fg_color="transparent", anchor="w", 
                            hover_color=GH_BORDER, height=50, text_color=GH_TEXT, 
                            command=lambda: self.show_frame(frame_name))
        btn.pack(fill="x", padx=15, pady=2)

    # --- UI FRAMES ---
    def _build_home(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        ctk.CTkLabel(f, text="GIT-TOOL PRO V8.5", font=("Arial", 28, "bold"), text_color=GH_BLUE).pack(pady=40)
        ctk.CTkLabel(f, text="Production-ready GitHub management system.", font=("Arial", 16)).pack()
        self.frames["home"] = f

    def _build_repo_list(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        header = ctk.CTkFrame(f, fg_color="transparent")
        header.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(header, text="Your Repositories", font=("Arial", 22, "bold")).pack(side="left")
        ctk.CTkButton(header, text="🔄 Refresh List", width=120, fg_color=GH_BLUE, command=self.fetch_repos).pack(side="right")
        
        self.repo_scroll = ctk.CTkScrollableFrame(f, fg_color=GH_SIDEBAR, height=600, border_color=GH_BORDER, border_width=1)
        self.repo_scroll.pack(fill="both", expand=True)
        self.frames["list"] = f

    def _build_sync_engine(self):
        f = ctk.CTkScrollableFrame(self.container, fg_color="transparent", label_text="ULTRA SYNC ENGINE")
        
        config_box = ctk.CTkFrame(f, fg_color=GH_SIDEBAR, border_color=GH_BORDER, border_width=1)
        config_box.pack(fill="x", pady=10)

        self.up_name = ctk.CTkEntry(config_box, placeholder_text="Repo Name", width=250)
        self.up_name.grid(row=0, column=0, padx=15, pady=15)
        
        self.sync_private_var = ctk.BooleanVar(value=True)
        self.sync_private_sw = ctk.CTkSwitch(config_box, text="Private Repo", variable=self.sync_private_var, progress_color=GH_BLUE)
        self.sync_private_sw.grid(row=0, column=1, padx=20)

        ctk.CTkLabel(config_box, text="Threads:", text_color=GH_GRAY).grid(row=0, column=2, padx=5)
        self.worker_slider = ctk.CTkSlider(config_box, from_=1, to=20, width=150)
        self.worker_slider.set(8)
        self.worker_slider.grid(row=0, column=3, padx=5)
        self.worker_val = ctk.CTkLabel(config_box, text="8", text_color=GH_BLUE)
        self.worker_val.grid(row=0, column=4, padx=5)
        self.worker_slider.configure(command=lambda v: self.worker_val.configure(text=str(int(v))))

        path_row = ctk.CTkFrame(f, fg_color="transparent")
        path_row.pack(fill="x", pady=5)
        self.up_path = ctk.CTkEntry(path_row, placeholder_text="Source Path", width=500)
        self.up_path.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkButton(path_row, text="Browse", fg_color=GH_BORDER, width=100, command=self.analyze_folder).pack(side="right")

        self.ignore_input = ctk.CTkEntry(f, placeholder_text="Ignore list...")
        self.ignore_input.pack(fill="x", pady=10)
        self.ignore_input.insert(0, ".git, node_modules, __pycache__, venv, .github_cli, dist, build")

        self.staging_area = ctk.CTkTextbox(f, height=300, font=("Consolas", 11), fg_color="#010409", text_color="#d1d5da")
        self.staging_area.pack(fill="x", pady=5)

        self.progress_lbl = ctk.CTkLabel(f, text="Sync Progress: 0%", font=("Arial", 12))
        self.progress_lbl.pack()
        self.progress_bar = ctk.CTkProgressBar(f, height=15, progress_color=GH_GREEN)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=10)

        self.sync_btn = ctk.CTkButton(f, text="START CLOUD SYNC", fg_color=GH_GREEN, height=50, font=("Arial", 16, "bold"), command=self.start_sync)
        self.sync_btn.pack(pady=10, fill="x")
        self.frames["sync"] = f

    def _build_clone_tool(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        ctk.CTkLabel(f, text="Clone Repository", font=("Arial", 22, "bold")).pack(pady=30)
        self.cl_url = ctk.CTkEntry(f, placeholder_text="GitHub URL", width=600, height=40)
        self.cl_url.pack(pady=10)
        self.cl_dest = ctk.CTkEntry(f, placeholder_text="Destination Path", width=600, height=40)
        self.cl_dest.pack(pady=10)
        ctk.CTkButton(f, text="Select Path", fg_color=GH_BORDER, command=lambda: self.browse_folder(self.cl_dest)).pack()
        ctk.CTkButton(f, text="Clone Now", fg_color=GH_BLUE, width=200, height=45, command=self.clone_repo).pack(pady=30)
        self.frames["clone"] = f

    def _build_settings(self):
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        ctk.CTkLabel(f, text="Auth Settings", font=("Arial", 22, "bold")).pack(pady=30)
        self.token_in = ctk.CTkEntry(f, placeholder_text="GitHub Personal Access Token", width=600, height=40, show="*")
        self.token_in.pack(pady=10)
        if self.token: self.token_in.insert(0, self.token)
        ctk.CTkButton(f, text="Save & Connect", fg_color=GH_BLUE, width=200, height=45, command=self.save_settings).pack(pady=20)
        self.frames["settings"] = f

    def _build_log_console(self):
        self.log_box = ctk.CTkTextbox(self, height=130, fg_color="#010409", text_color="#7ee787", font=("Consolas", 12))
        self.log_box.grid(row=1, column=1, sticky="nsew", padx=30, pady=(0, 30))

    # --- FUNCTIONALITY ---

    def log(self, msg):
        self.log_box.insert("end", f"> {msg}\n")
        self.log_box.see("end")

    def show_frame(self, name):
        for f in self.frames.values(): f.pack_forget()
        self.frames[name].pack(fill="both", expand=True)

    def verify_auth(self):
        headers = {'Authorization': f'token {self.token}'}
        def task():
            try:
                r = requests.get('https://api.github.com/user', headers=headers)
                if r.status_code == 200:
                    self.username = r.json()['login']
                    self.after(0, lambda: self.status_ball.configure(text="● Online", text_color=GH_GREEN))
                    self.after(0, lambda: self.user_lbl.configure(text=f"User: {self.username}"))
                    self.fetch_repos()
                else: self.log("✗ Auth Failed.")
            except: pass
        threading.Thread(target=task, daemon=True).start()

    def fetch_repos(self):
        headers = {'Authorization': f'token {self.token}'}
        def task():
            try:
                r = requests.get(f'https://api.github.com/user/repos?per_page=100&sort=updated', headers=headers)
                self.all_repos = r.json()
                self.after(0, self.render_repo_list)
            except: self.log("✗ Failed to fetch repositories.")
        threading.Thread(target=task, daemon=True).start()

    def render_repo_list(self):
        for w in self.repo_scroll.winfo_children(): w.destroy()
        for repo in self.all_repos:
            frame = ctk.CTkFrame(self.repo_scroll, fg_color=GH_BORDER, height=50)
            frame.pack(fill="x", pady=2, padx=5)
            name = repo['name']
            is_p = repo['private']
            
            ctk.CTkLabel(frame, text=name, font=("Arial", 13, "bold"), width=250, anchor="w").pack(side="left", padx=15)
            
            # Visibility Button
            vis_text = "🔒 Private" if is_p else "🌐 Public"
            vis_color = GH_BLUE if is_p else GH_GREEN
            ctk.CTkButton(frame, text=vis_text, width=100, height=28, fg_color=vis_color, 
                          command=lambda n=name, p=is_p: self.toggle_privacy(n, p)).pack(side="left", padx=10)
            
            ctk.CTkButton(frame, text="Delete", fg_color=GH_RED, width=70, height=28, command=lambda n=name: self.delete_repo(n)).pack(side="right", padx=10)
            ctk.CTkButton(frame, text="Sync", fg_color=GH_BLUE, width=70, height=28, command=lambda n=name: self.load_sync(n)).pack(side="right")

    def toggle_privacy(self, repo_name, current_private):
        new_private = not current_private
        headers = {'Authorization': f'token {self.token}'}
        def task():
            url = f'https://api.github.com/repos/{self.username}/{repo_name}'
            res = requests.patch(url, headers=headers, json={'private': new_private})
            if res.status_code == 200:
                self.log(f"✓ {repo_name} is now {'Private' if new_private else 'Public'}")
                self.fetch_repos()
            else: self.log(f"✗ Failed to change visibility: {res.status_code}")
        threading.Thread(target=task, daemon=True).start()

    def analyze_folder(self):
        p = filedialog.askdirectory()
        if not p: return
        self.up_path.delete(0, "end"); self.up_path.insert(0, p)
        root = Path(p)
        if not self.up_name.get(): self.up_name.insert(0, root.name)
        
        ignores = [x.strip() for x in self.ignore_input.get().split(',') if x.strip()]
        self.staged_files = []
        self.staging_area.delete("1.0", "end")
        for f in root.rglob('*'):
            if f.is_file():
                rel = f.relative_to(root).as_posix()
                if not any(pat in rel for pat in ignores):
                    self.staged_files.append((f, rel))
                    self.staging_area.insert("end", f"[READY] {rel}\n")

    def start_sync(self):
        repo_name = self.up_name.get()
        local_dir = self.up_path.get()
        is_priv = self.sync_private_var.get()
        workers = int(self.worker_slider.get())
        
        if not repo_name or not self.staged_files: return
        self.sync_btn.configure(state="disabled")

        def task():
            headers = {'Authorization': f'token {self.token}'}
            # 1. Ensure Repo exists and Visibility is correct
            self.log(f"Setting up {repo_name}...")
            r_check = requests.get(f'https://api.github.com/repos/{self.username}/{repo_name}', headers=headers)
            
            if r_check.status_code == 404:
                requests.post('https://api.github.com/user/repos', headers=headers, json={'name': repo_name, 'private': is_priv, 'auto_init': True})
            else:
                requests.patch(f'https://api.github.com/repos/{self.username}/{repo_name}', headers=headers, json={'private': is_priv})

            # 2. Get SHAs
            shas = {}
            r = requests.get(f'https://api.github.com/repos/{self.username}/{repo_name}/git/trees/main?recursive=1', headers=headers)
            if r.status_code == 200:
                for item in r.json().get('tree', []):
                    if item['type'] == 'blob': shas[item['path']] = item['sha']

            done = 0
            total = len(self.staged_files)

            def upload_file(f_info):
                abs_p, rel_p = f_info
                sha = shas.get(rel_p)
                for _ in range(3):
                    try:
                        self.after(0, lambda: self._update_console(rel_p, "SYNCING"))
                        with open(abs_p, 'rb') as f: content = base64.b64encode(f.read()).decode()
                        d = {"message": "Sync V8.5", "content": content}
                        if sha: d["sha"] = sha
                        
                        res = requests.put(f'https://api.github.com/repos/{self.username}/{repo_name}/contents/{rel_p}', headers=headers, json=d)
                        if res.status_code in [200, 201]:
                            self.after(0, lambda: self._update_console(rel_p, "DONE"))
                            return True
                        elif res.status_code == 409:
                            ref = requests.get(f'https://api.github.com/repos/{self.username}/{repo_name}/contents/{rel_p}', headers=headers)
                            if ref.status_code == 200: sha = ref.json().get('sha')
                    except: time.sleep(1)
                self.after(0, lambda: self._update_console(rel_p, "FAILED"))
                return False

            with ThreadPoolExecutor(max_workers=workers) as ex:
                for _ in ex.map(upload_file, self.staged_files):
                    done += 1
                    pct = done / total
                    self.after(0, lambda p=pct, d=done, t=total: self._up_progress(p, d, t))

            self.after(0, lambda: self.sync_btn.configure(state="normal"))
            self.log("✅ Sync Complete.")
            self.fetch_repos()

        threading.Thread(target=task, daemon=True).start()

    def _update_console(self, filename, status):
        try:
            raw = self.staging_area.get("1.0", "end").splitlines()
            for i, line in enumerate(raw):
                if filename in line:
                    self.staging_area.delete(f"{i+1}.0", f"{i+1}.end")
                    self.staging_area.insert(f"{i+1}.0", f"[{status}] {filename}")
                    break
        except: pass

    def _up_progress(self, p, d, t):
        self.progress_bar.set(p)
        self.progress_lbl.configure(text=f"Progress: {int(p*100)}% ({d}/{t})")

    def load_sync(self, name):
        self.show_frame("sync"); self.up_name.delete(0, "end"); self.up_name.insert(0, name)

    def delete_repo(self, name):
        if messagebox.askyesno("Delete", f"Delete {name}?"):
            headers = {'Authorization': f'token {self.token}'}
            threading.Thread(target=lambda: [requests.delete(f'https://api.github.com/repos/{self.username}/{name}', headers=headers), self.fetch_repos()], daemon=True).start()

    def clone_repo(self):
        url, dest = self.cl_url.get(), self.cl_dest.get()
        def task():
            r = subprocess.run(['git', 'clone', url, dest], capture_output=True, text=True)
            self.log("✓ Cloned" if r.returncode == 0 else f"✗ Error: {r.stderr}")
        threading.Thread(target=task, daemon=True).start()

    def save_settings(self):
        self.token = self.token_in.get().strip(); self._save_config(); self.verify_auth(); self.log("Settings Saved.")

    def browse_folder(self, w):
        p = filedialog.askdirectory()
        if p: w.delete(0, "end"); w.insert(0, p)

if __name__ == "__main__":
    app = GitHubProV8()
    app.mainloop()