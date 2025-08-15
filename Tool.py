"""
MULTITOOL OSINT - INTERFACE PREMIUM AVEC COPIE DE SITE ET LATENCE
Version: 4.1 - Design Premium
Author: Anonymous Rebel
"""

import os
import re
import sys
import socket
import requests
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import ipaddress
import concurrent.futures
from datetime import datetime
from bs4 import BeautifulSoup
import dns.resolver
import whois
import time
import shutil
from urllib.parse import urlparse
from PIL import Image, ImageTk
import sv_ttk

THREADS = 50
TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def osint_gather(target: str) -> dict:
    """Comprehensive OSINT data collection"""
    data = {"domain": target, "ip": "", "whois": {}, "dns": {}, "social": {}}
    
    try:
        data["ip"] = socket.gethostbyname(target)
    except socket.gaierror:
        data["ip"] = "Resolution failed"

    try:
        w = whois.whois(target)
        data["whois"] = {
            "registrar": w.registrar,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers
        }
    except Exception:
        pass

    try:
        resolver = dns.resolver.Resolver()
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                data["dns"][rtype] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                continue
    except Exception:
        pass

    platforms = {
        "twitter": f"https://twitter.com/{target}",
        "instagram": f"https://instagram.com/{target}",
        "github": f"https://github.com/{target}",
        "linkedin": f"https://linkedin.com/in/{target}"
    }
    for platform, url in platforms.items():
        try:
            resp = requests.head(url, timeout=TIMEOUT, allow_redirects=True)
            data["social"][platform] = "LIVE" if resp.status_code == 200 else "INVALID"
        except:
            data["social"][platform] = "ERROR"

    return data

def web_scanner(url: str) -> dict:
    """Advanced web vulnerability assessment"""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    results = {
        "url": url,
        "server": "N/A",
        "headers": {},
        "tech_stack": [],
        "vulnerabilities": []
    }

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        resp = session.get(url, timeout=TIMEOUT)
        results["headers"] = dict(resp.headers)
        results["server"] = resp.headers.get("Server", "N/A")

        tech_signatures = {
            "WordPress": re.compile(r"wp-content|wordpress", re.I),
            "Apache": re.compile(r"apache", re.I),
            "Nginx": re.compile(r"nginx", re.I),
            "PHP": re.compile(r"php|x-powered-by: php", re.I),
            "Cloudflare": re.compile(r"cloudflare", re.I),
            "React": re.compile(r"react|react-dom", re.I),
            "Vue.js": re.compile(r"vue\.js", re.I),
            "Django": re.compile(r"django", re.I)
        }
        for tech, pattern in tech_signatures.items():
            if pattern.search(resp.text) or pattern.search(str(resp.headers)):
                results["tech_stack"].append(tech)

        vuln_tests = [
            ("SQL Injection", f"{url}'", r"SQL syntax|mysql_fetch"),
            ("XSS", f"{url}<script>alert(1)</script>", r"<script>alert\(1\)</script>"),
            ("Path Traversal", f"{url}../../../../etc/passwd", r"root:[x*]:0:0"),
            ("LFI", f"{url}?file=../../../../etc/passwd", r"root:[x*]:0:0")
        ]
        for name, test_url, pattern in vuln_tests:
            try:
                vuln_resp = session.get(test_url, timeout=3)
                if re.search(pattern, vuln_resp.text, re.I):
                    results["vulnerabilities"].append(name)
            except:
                continue

        common_dirs = ["admin", "backup", "wp-admin", "test", "secret", "config", "database"]
        for directory in common_dirs:
            test_url = f"{url}/{directory}"
            try:
                dir_resp = session.head(test_url, timeout=2)
                if dir_resp.status_code == 200:
                    results["vulnerabilities"].append(f"Exposed directory: /{directory}")
            except:
                continue

    except requests.exceptions.RequestException as e:
        results["error"] = str(e)

    return results

def network_diagnostics(target: str, scan_type: str) -> dict:
    """Network analysis toolkit"""
    results = {"target": target, "type": scan_type, "data": []}

    if scan_type == "ping":
        try:
            cmd = ["ping", "-c", "4", target] if os.name != "nt" else ["ping", "-n", "4", target]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            results["data"] = output.splitlines()
        except subprocess.CalledProcessError as e:
            results["data"] = [f"Ping failed: {e.output.decode()}"]
        except Exception as e:
            results["data"] = [f"Error: {str(e)}"]

    elif scan_type == "ports":
        ports_to_scan = [21, 22, 80, 443, 8080, 3306, 3389, 5432, 5900, 6379]
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port, result == 0
            except Exception as e:
                return port, f"Error: {str(e)}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = [executor.submit(scan_port, port) for port in ports_to_scan]
            for future in concurrent.futures.as_completed(futures):
                port, status = future.result()
                if isinstance(status, bool):
                    results["data"].append(f"Port {port}: {'OPEN' if status else 'CLOSED'}")
                else:
                    results["data"].append(f"Port {port}: {status}")

    return results

def measure_latency(targets):
    """Measure server latency"""
    results = {}
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        try:
            if not target.startswith(("http://", "https://")):
                target = "http://" + target
                
            start_time = time.time()
            response = requests.head(target, timeout=5)
            latency = (time.time() - start_time) * 1000 
            results[target] = {
                "status": response.status_code,
                "latency": round(latency, 2),
                "success": True
            }
        except Exception as e:
            results[target] = {
                "status": "ERROR",
                "latency": "N/A",
                "error": str(e),
                "success": False
            }
            
    return results

def download_website(url, output_dir):
    """Download website to local directory"""
    try:
        domain = urlparse(url).netloc
        site_dir = os.path.join(output_dir, domain)
        os.makedirs(site_dir, exist_ok=True)
        
        response = requests.get(url, timeout=10)
        main_file = os.path.join(site_dir, "index.html")
        
        with open(main_file, "w", encoding="utf-8") as f:
            f.write(response.text)
            
        soup = BeautifulSoup(response.text, 'html.parser')
        resources = []
        
        for tag, attr in [('img', 'src'), ('link', 'href'), ('script', 'src'), ('a', 'href')]:
            for element in soup.find_all(tag):
                resource = element.get(attr)
                if resource and not resource.startswith(('http', '//')) and not resource.startswith('data:'):
                    resources.append(resource)
        
        for resource in set(resources):
            try:
                resource_url = url + resource if resource.startswith('/') else f"{url}/{resource}"
                resource_path = os.path.join(site_dir, resource.lstrip('/'))
                os.makedirs(os.path.dirname(resource_path), exist_ok=True)
                
                res_response = requests.get(resource_url, timeout=5)
                with open(resource_path, "wb") as f:
                    f.write(res_response.content)
            except Exception as e:
                print(f"Failed to download {resource}: {str(e)}")
        
        return site_dir, True
    except Exception as e:
        return str(e), False

def report_generator(data: dict, output_format: str = "txt"):
    """Multi-format reporting system"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}"

    if output_format == "txt":
        filename += ".txt"
        with open(filename, "w", encoding="utf-8") as f:
            for section, content in data.items():
                f.write(f"\n===== {section.upper()} =====\n")
                if isinstance(content, dict):
                    for k, v in content.items():
                        f.write(f"{k}: {v}\n")
                elif isinstance(content, list):
                    for item in content:
                        f.write(f"{item}\n")
                else:
                    f.write(str(content))
        return filename

    elif output_format == "html":
        filename += ".html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Security Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f8f9fa; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; margin-bottom: 30px; border-bottom: 2px solid #3498db; padding-bottom: 15px; }
        h2 { color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 8px; margin-top: 25px; }
        .result-section { margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .success { color: #27ae60; }
        .warning { color: #f39c12; }
        .error { color: #e74c3c; }
        .latency-good { color: #2ecc71; }
        .latency-medium { color: #f39c12; }
        .latency-bad { color: #e74c3c; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Scan Report</h1>""")
            
            for section, content in data.items():
                f.write(f"<div class='result-section'><h2>{section}</h2>")
                
                if isinstance(content, dict):
                    f.write("<table><tbody>")
                    for k, v in content.items():
                        if isinstance(v, dict):
                            f.write(f"<tr><th colspan='2'>{k}</th></tr>")
                            for sk, sv in v.items():
                                f.write(f"<tr><td>{sk}</td><td>{sv}</td></tr>")
                        else:
                            f.write(f"<tr><td><strong>{k}</strong></td><td>{v}</td></tr>")
                    f.write("</tbody></table>")
                
                elif isinstance(content, list):
                    f.write("<table><tbody>")
                    for item in content:
                        f.write(f"<tr><td>{item}</td></tr>")
                    f.write("</tbody></table>")
                else:
                    f.write(f"<p>{content}</p>")
                
                f.write("</div>")
            
            f.write("</div></body></html>")
        return filename

class PremiumMultitool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("422 Multitool ")
        self.geometry("1100x750")
        self.resizable(True, True)
        self.last_result = None
        self.scan_active = False
        self.download_dir = os.getcwd()
        self.create_widgets()
        self.center_window()
        
        sv_ttk.set_theme("dark")

    def center_window(self):
        self.update_idletasks()
        width = 1100
        height = 750
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def create_widgets(self):
        # Configuration de la grille principale
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header avec logo
        header_frame = ttk.Frame(self, padding=10)
        header_frame.grid(row=0, column=0, sticky="ew")
        
        logo_label = ttk.Label(
            header_frame, 
            text="🛰422 MULTITOOL ", 
            font=("Segoe UI", 16, "bold"),
            foreground="#4a86e8"
        )
        logo_label.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(
            header_frame, 
            text="Status: Prêt",
            font=("Segoe UI", 9)
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)

        main_container = ttk.Frame(self)
        main_container.grid(row=1, column=0, sticky="nsew", padx=10, pady=5)
        main_container.grid_columnconfigure(0, weight=3)
        main_container.grid_columnconfigure(1, weight=7)
        main_container.grid_rowconfigure(0, weight=1)

        control_frame = ttk.LabelFrame(main_container, text="Modules", padding=15)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=5)
        control_frame.grid_columnconfigure(0, weight=1)
        
        osint_frame = ttk.LabelFrame(control_frame, text="Recherche OSINT", padding=10)
        osint_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(osint_frame, text="Cible (domaine/utilisateur):").pack(anchor="w")
        self.osint_entry = ttk.Entry(osint_frame, width=30)
        self.osint_entry.pack(fill=tk.X, pady=(0, 10))
        self.osint_entry.insert(0, "example.com")
        
        ttk.Button(
            osint_frame, 
            text="Lancer la recherche", 
            command=self.run_osint,
            style="Accent.TButton"
        ).pack(fill=tk.X, pady=5)

       
        web_frame = ttk.LabelFrame(control_frame, text="Analyse Web", padding=10)
        web_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(web_frame, text="URL cible:").pack(anchor="w")
        self.web_entry = ttk.Entry(web_frame, width=30)
        self.web_entry.pack(fill=tk.X, pady=(0, 10))
        self.web_entry.insert(0, "http://PorHub.com")
        
        ttk.Button(
            web_frame, 
            text="Scanner le site", 
            command=self.run_web_scan,
            style="Accent.TButton"
        ).pack(fill=tk.X, pady=5)

       
        net_frame = ttk.LabelFrame(control_frame, text="Diagnostic Réseau", padding=10)
        net_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(net_frame, text="IP/Domaine cible:").pack(anchor="w")
        self.net_entry = ttk.Entry(net_frame, width=30)
        self.net_entry.pack(fill=tk.X, pady=(0, 10))
        self.net_entry.insert(0, "192.168.1.1")
        
        scan_frame = ttk.Frame(net_frame)
        scan_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            scan_frame, 
            text="Ping", 
            command=lambda: self.run_net_scan("ping"),
            width=10
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            scan_frame, 
            text="Scan Ports", 
            command=lambda: self.run_net_scan("ports"),
            width=10
        ).pack(side=tk.LEFT)


        site_frame = ttk.LabelFrame(control_frame, text="Outils Site Web", padding=10)
        site_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(site_frame, text="Copier un site:").pack(anchor="w")
        self.site_entry = ttk.Entry(site_frame, width=30)
        self.site_entry.pack(fill=tk.X, pady=(0, 5))
        self.site_entry.insert(0, "http://PorHub.com")
        
        download_frame = ttk.Frame(site_frame)
        download_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(
            download_frame, 
            command=self.select_download_dir,
            width=15
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            download_frame, 
            text="Télécharger", 
            command=self.download_site,
            width=15
        ).pack(side=tk.LEFT)
        

        ttk.Label(site_frame, text="Mesurer la latence (séparer par des virgules):").pack(anchor="w")
        self.latency_entry = ttk.Entry(site_frame, width=30)
        self.latency_entry.pack(fill=tk.X, pady=(0, 5))
        self.latency_entry.insert(0, "google.com, facebook.com, twitter.com")
        
        ttk.Button(
            site_frame, 
            text="Tester la latence", 
            command=self.test_latency,
            width=30
        ).pack(fill=tk.X, pady=5)

        action_frame = ttk.LabelFrame(control_frame, text="Rapports & Actions", padding=10)
        action_frame.pack(fill=tk.X, pady=5)
        
        report_frame = ttk.Frame(action_frame)
        report_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            report_frame, 
            text="Générer Rapport TXT", 
            command=lambda: self.save_report("txt"),
            width=14
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(
            report_frame, 
            text="Générer Rapport HTML", 
            command=lambda: self.save_report("html"),
            width=14
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            action_frame, 
            text="Effacer les résultats", 
            command=self.clear_console,
            width=30
        ).pack(fill=tk.X, pady=5)
        
        result_frame = ttk.LabelFrame(main_container, text="Résultats", padding=10)
        result_frame.grid(row=0, column=1, sticky="nsew", pady=5)
        result_frame.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(0, weight=1)
        
        self.result_notebook = ttk.Notebook(result_frame)
        self.result_notebook.pack(fill=tk.BOTH, expand=True)
        
        console_tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(console_tab, text="Console")
        console_tab.grid_columnconfigure(0, weight=1)
        console_tab.grid_rowconfigure(0, weight=1)
        
        self.output_area = scrolledtext.ScrolledText(
            console_tab, 
            wrap=tk.WORD, 
            bg="#1e1e1e", 
            fg="#e1e1e1",
            insertbackground='white',
            font=("Consolas", 10),
            padx=10,
            pady=10
        )
        self.output_area.grid(row=0, column=0, sticky="nsew")
        self.output_area.insert(tk.END, ">>> 422 MULTITOOL <<<\n")
        self.output_area.insert(tk.END, "-"*70 + "\n")
        self.output_area.insert(tk.END, "Sélectionnez un module et entrez une cible pour commencer\n")
        
        stats_tab = ttk.Frame(self.result_notebook)
        self.result_notebook.add(stats_tab, text="Statistiques")
        
        self.progress_frame = ttk.Frame(self, padding=5)
        self.progress_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        self.progress = ttk.Progressbar(
            self.progress_frame, 
            orient="horizontal", 
            mode="determinate",
            length=1060
        )
        self.progress.pack(fill=tk.X)
        self.progress["value"] = 0

        footer_frame = ttk.Frame(self, padding=5)
        footer_frame.grid(row=3, column=0, sticky="ew")
        
        ttk.Label(
            footer_frame, 
            text="© Multitool",
            font=("Segoe UI", 8)
        ).pack(side=tk.LEFT)
        
        ttk.Label(
            footer_frame, 
            text="En cours: Aucune opération",
            font=("Segoe UI", 8),
            foreground="#888"
        ).pack(side=tk.RIGHT)

        self.style = ttk.Style()
        self.style.configure("Accent.TButton", background="#4a86e8", foreground="white")
        self.style.map("Accent.TButton", background=[("active", "#3a76d8")])

    def update_status(self, message):
        self.status_label.config(text=f"Status: {message}")
        self.output_area.insert(tk.END, f"\n[STATUS] {message}\n")
        self.output_area.see(tk.END)

    def update_progress(self, value):
        self.progress["value"] = value
        self.update_idletasks()

    def animate_scan(self):
        if self.scan_active:
            current = self.progress["value"]
            if current < 100:
                self.progress["value"] = current + 1
                self.after(50, self.animate_scan)
            else:
                self.progress["value"] = 0
                self.after(50, self.animate_scan)

    def select_download_dir(self):
        self.download_dir = filedialog.askdirectory(title="Sélectionner le dossier de destination")
        if self.download_dir:
            self.output_area.insert(tk.END, f"\n[INFO] Dossier de téléchargement: {self.download_dir}\n")

    def download_site(self):
        if self.scan_active:
            return
            
        url = self.site_entry.get().strip()
        if not url:
            messagebox.showwarning("Erreur", "Veuillez entrer une URL valide")
            return
            
        self.scan_active = True
        self.animate_scan()
        self.update_status(f"Démarrage téléchargement: {url}")
        threading.Thread(target=self.execute_download, args=(url,), daemon=True).start()

    def execute_download(self, url):
        try:
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"TÉLÉCHARGEMENT DU SITE: {url}\n")
            self.output_area.insert(tk.END, f"Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'-'*70}\n")
            
            self.update_status("Téléchargement...")
            self.update_progress(20)
            
            site_dir, success = download_website(url, self.download_dir)
            
            if success:
                self.output_area.insert(tk.END, f"\n[SUCCÈS] Site téléchargé dans: {site_dir}\n")
                self.output_area.insert(tk.END, f"Taille: {self.get_folder_size(site_dir)} MB\n")
                self.update_status("Téléchargement terminé avec succès")
                messagebox.showinfo("Succès", f"Site téléchargé dans:\n{site_dir}")
            else:
                self.output_area.insert(tk.END, f"\n[ERREUR] Échec du téléchargement: {site_dir}\n")
                self.update_status("Échec du téléchargement")
                messagebox.showerror("Erreur", f"Échec du téléchargement:\n{site_dir}")
                
            self.update_progress(100)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"OPÉRATION TERMINÉE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'='*70}\n")
            
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec du téléchargement:\n{str(e)}")
        finally:
            self.scan_active = False
            self.progress["value"] = 0

    def get_folder_size(self, folder_path):
        """Calculate folder size in MB"""
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(folder_path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                total_size += os.path.getsize(fp)
        return round(total_size / (1024 * 1024), 2) 

    def test_latency(self):
        if self.scan_active:
            return
            
        targets_str = self.latency_entry.get().strip()
        if not targets_str:
            messagebox.showwarning("Erreur", "Veuillez entrer au moins une URL ou adresse IP")
            return
            
        targets = [t.strip() for t in targets_str.split(",") if t.strip()]
        self.scan_active = True
        self.animate_scan()
        self.update_status(f"Démarrage test de latence pour {len(targets)} serveurs")
        threading.Thread(target=self.execute_latency_test, args=(targets,), daemon=True).start()

    def execute_latency_test(self, targets):
        try:
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"TEST DE LATENCE: {len(targets)} serveurs\n")
            self.output_area.insert(tk.END, f"Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'-'*70}\n")
            
            self.update_status("Mesure de la latence en cours...")
            results = measure_latency(targets)
            
            self.output_area.insert(tk.END, "\nRÉSULTATS DE LATENCE:\n")
            self.output_area.insert(tk.END, "-"*70 + "\n")
            self.output_area.insert(tk.END, "Serveur".ljust(40) + "Statut".ljust(10) + "Latence (ms)\n")
            self.output_area.insert(tk.END, "-"*70 + "\n")
            
            for target, data in results.items():
                if data["success"]:
                    latency = data["latency"]
                    if latency < 100:
                        latency_color = "#2ecc71"
                        latency_status = "Excellent"
                    elif latency < 300:
                        latency_color = "#f39c12"  
                        latency_status = "Bon"
                    else:
                        latency_color = "#e74c3c"  
                        latency_status = "Médiocre"
                    
                    self.output_area.insert(tk.END, 
                        f"{target.ljust(40)} {str(data['status']).ljust(10)} ", 
                        "normal"
                    )
                    self.output_area.insert(tk.END, 
                        f"{latency} ms ({latency_status})\n", 
                        f"latency_{'good' if latency < 100 else 'medium' if latency < 300 else 'bad'}"
                    )
                else:
                    self.output_area.insert(tk.END, 
                        f"{target.ljust(40)} ERROR     ", 
                        "normal"
                    )
                    self.output_area.insert(tk.END, 
                        f"Erreur: {data.get('error', 'Inconnue')}\n", 
                        "error"
                    )
            
            self.output_area.tag_configure("latency_good", foreground="#2ecc71")
            self.output_area.tag_configure("latency_medium", foreground="#f39c12")
            self.output_area.tag_configure("latency_bad", foreground="#e74c3c")
            self.output_area.tag_configure("error", foreground="#e74c3c")
            
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"TEST TERMINÉ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'='*70}\n")
            
            self.update_status("Test de latence terminé")
            messagebox.showinfo("Succès", "Test de latence terminé avec succès!")
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec du test de latence:\n{str(e)}")
        finally:
            self.scan_active = False
            self.progress["value"] = 0
    
    def run_osint(self):
        if self.scan_active:
            return
            
        target = self.osint_entry.get().strip()
        if not target:
            messagebox.showwarning("Erreur", "Veuillez entrer une cible OSINT")
            return
            
        self.scan_active = True
        self.animate_scan()
        self.update_status(f"Démarrage scan OSINT: {target}")
        threading.Thread(target=self.execute_osint, args=(target,), daemon=True).start()

    def execute_osint(self, target):
        try:
            self.update_progress(10)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN OSINT: {target}\n")
            self.output_area.insert(tk.END, f"Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'-'*70}\n")
            
            self.update_status("Résolution DNS...")
            result = osint_gather(target)
            self.last_result = result
            
            self.update_progress(40)
            self.output_area.insert(tk.END, "\n[DOMAINE]\n")
            self.output_area.insert(tk.END, f"Nom: {result.get('domain', 'N/A')}\n")
            self.output_area.insert(tk.END, f"IP: {result.get('ip', 'N/A')}\n")
            
            self.update_status("Analyse WHOIS...")
            self.update_progress(60)
            self.output_area.insert(tk.END, "\n[WHOIS]\n")
            whois_data = result.get('whois', {})
            for k, v in whois_data.items():
                self.output_area.insert(tk.END, f"{k}: {v}\n")
            
            self.update_status("Vérification DNS...")
            self.update_progress(80)
            self.output_area.insert(tk.END, "\n[DNS]\n")
            dns_data = result.get('dns', {})
            for rtype, records in dns_data.items():
                self.output_area.insert(tk.END, f"{rtype}: {', '.join(records)}\n")
            
            self.update_status("Vérification réseaux sociaux...")
            self.update_progress(90)
            self.output_area.insert(tk.END, "\n[RÉSEAUX SOCIAUX]\n")
            social_data = result.get('social', {})
            for platform, status in social_data.items():
                self.output_area.insert(tk.END, f"{platform.capitalize()}: {status}\n")
            
            self.update_progress(100)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN TERMINÉ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'='*70}\n")
            
            self.update_status("Scan OSINT terminé")
            messagebox.showinfo("Succès", "Scan OSINT terminé avec succès!")
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec du scan OSINT:\n{str(e)}")
        finally:
            self.scan_active = False
            self.progress["value"] = 0

    def run_web_scan(self):
        if self.scan_active:
            return
            
        url = self.web_entry.get().strip()
        if not url:
            messagebox.showwarning("Erreur", "Veuillez entrer une URL valide")
            return
            
        self.scan_active = True
        self.animate_scan()
        self.update_status(f"Démarrage scan web: {url}")
        threading.Thread(target=self.execute_web_scan, args=(url,), daemon=True).start()

    def execute_web_scan(self, url):
        try:
            self.update_progress(10)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN WEB: {url}\n")
            self.output_area.insert(tk.END, f"Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'-'*70}\n")
            
            self.update_status("Connexion au serveur...")
            result = web_scanner(url)
            self.last_result = result
            
            self.update_progress(30)
            self.output_area.insert(tk.END, "\n[INFO SERVEUR]\n")
            self.output_area.insert(tk.END, f"URL: {result['url']}\n")
            self.output_area.insert(tk.END, f"Server: {result['server']}\n")
            
            self.update_status("Analyse technologies...")
            self.update_progress(50)
            self.output_area.insert(tk.END, "\n[TECHNOLOGIES]\n")
            for tech in result.get('tech_stack', []):
                self.output_area.insert(tk.END, f"- {tech}\n")
                
            self.update_status("Recherche de vulnérabilités...")
            self.update_progress(70)
            self.output_area.insert(tk.END, "\n[VULNÉRABILITÉS]\n")
            if result.get('vulnerabilities'):
                for vuln in result['vulnerabilities']:
                    self.output_area.insert(tk.END, f"- {vuln}\n")
            else:
                self.output_area.insert(tk.END, "Aucune vulnérabilité critique détectée\n")
            
            self.update_progress(100)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN TERMINÉ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'='*70}\n")
            
            self.update_status("Scan web terminé")
            messagebox.showinfo("Succès", "Scan web terminé avec succès!")
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec du scan web:\n{str(e)}")
        finally:
            self.scan_active = False
            self.progress["value"] = 0

    def run_net_scan(self, scan_type):
        if self.scan_active:
            return
                                                                                                                                                                                                                                                                                                                                               
        target = self.net_entry.get().strip()
        if not target:
            messagebox.showwarning("Erreur", "Veuillez entrer une cible réseau")
            return
            
        self.scan_active = True
        self.animate_scan()
        self.update_status(f"Démarrage {scan_type}: {target}")
        threading.Thread(target=self.execute_net_scan, args=(target, scan_type), daemon=True).start()

    def execute_net_scan(self, target, scan_type):
        try:
            self.update_progress(10)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN RÉSEAU: {scan_type.upper()} {target}\n")
            self.output_area.insert(tk.END, f"Début: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'-'*70}\n")
            
            self.update_status(f"Exécution {scan_type}...")
            result = network_diagnostics(target, scan_type)
            self.last_result = result
            
            self.update_progress(70)
            self.output_area.insert(tk.END, f"\nRÉSULTATS {scan_type.upper()}:\n")
            for line in result.get('data', []):
                self.output_area.insert(tk.END, f"{line}\n")
            
            self.update_progress(100)
            self.output_area.insert(tk.END, f"\n{'='*70}\n")
            self.output_area.insert(tk.END, f"SCAN TERMINÉ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.output_area.insert(tk.END, f"{'='*70}\n")
            
            self.update_status(f"{scan_type.capitalize()} terminé")
            messagebox.showinfo("Succès", f"Scan {scan_type} terminé avec succès!")
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec du scan {scan_type}:\n{str(e)}")
        finally:
            self.scan_active = False
            self.progress["value"] = 0

    def save_report(self, fmt):
        if not self.last_result:
            messagebox.showwarning("Erreur", "Aucun résultat à exporter")
            return
            
        try:
            filename = report_generator(self.last_result, fmt)
            self.output_area.insert(tk.END, f"\n[REPORT] Rapport sauvegardé: {filename}\n")
            messagebox.showinfo("Succès", f"Rapport généré:\n{os.path.abspath(filename)}")
        except Exception as e:
            self.output_area.insert(tk.END, f"\n[ERREUR] Échec génération rapport: {str(e)}\n")
            messagebox.showerror("Erreur", f"Échec génération rapport:\n{str(e)}")

    def clear_console(self):
        self.output_area.delete(1.0, tk.END)
        self.output_area.insert(tk.END, ">>> CONSOLE VIDÉE - PRÊT POUR NOUVELLE OPÉRATION <<<\n")
if __name__ == "__main__":
    app = PremiumMultitool()
    app.mainloop()
