"""
Modern Professional GUI for OWASPGuard with beautiful design and comprehensive features.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
from pathlib import Path
from datetime import datetime
import sys
import queue
import webbrowser

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.orchestrator import ScanOrchestrator
from reporting.json_report import JSONReportGenerator
from reporting.pdf_report import PDFReportGenerator


class ModernOWASPGuardGUI:
    """Modern professional GUI with beautiful design."""
    
    # Color scheme
    COLORS = {
        'bg': '#1e1e1e',
        'fg': '#d4d4d4',
        'accent': '#007acc',
        'accent_hover': '#005a9e',
        'success': '#4ec9b0',
        'warning': '#ffa500',
        'error': '#f48771',
        'critical': '#ff4444',
        'high': '#ff8800',
        'medium': '#ffbb00',
        'low': '#88cc00',
        'info': '#88aaff',
        'card_bg': '#252526',
        'border': '#3e3e42',
    }
    
    def __init__(self, root):
        """Initialize the modern GUI."""
        self.root = root
        self.root.title("OWASPGuard - Professional Security Analyzer")
        self.root.geometry("1800x1000")
        self.root.configure(bg=self.COLORS['bg'])
        
        # Variables
        self.scan_running = False
        self.scan_results = None
        self.project_path = tk.StringVar()
        self.progress_queue = queue.Queue()
        self.all_findings = []
        
        # Filter variables
        self.filter_severity = tk.StringVar(value="ALL")
        self.filter_owasp = tk.StringVar(value="ALL")
        self.search_text = tk.StringVar()
        
        # Setup UI
        self.setup_ui()
        self.center_window()
        
        # Start progress update loop
        self.update_progress()
    
    def center_window(self):
        """Center window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Setup the modern user interface."""
        # Main container with dark theme
        main_container = tk.Frame(self.root, bg=self.COLORS['bg'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Header bar
        header = tk.Frame(main_container, bg=self.COLORS['card_bg'], height=80)
        header.pack(fill=tk.X, padx=0, pady=0)
        header.pack_propagate(False)
        
        # Title
        title_frame = tk.Frame(header, bg=self.COLORS['card_bg'])
        title_frame.pack(side=tk.LEFT, padx=20, pady=15)
        
        title = tk.Label(
            title_frame,
            text="🛡️ OWASPGuard",
            font=("Segoe UI", 24, "bold"),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['accent']
        )
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(
            title_frame,
            text="Professional Static Application Security Analyzer",
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg']
        )
        subtitle.pack(anchor=tk.W)
        
        # Main content area
        content_frame = tk.Frame(main_container, bg=self.COLORS['bg'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Left sidebar - Configuration
        sidebar = tk.Frame(content_frame, bg=self.COLORS['card_bg'], width=350)
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 15))
        sidebar.pack_propagate(False)
        
        # Configuration section
        config_title = tk.Label(
            sidebar,
            text="⚙️ Configuration",
            font=("Segoe UI", 14, "bold"),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            anchor=tk.W
        )
        config_title.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        # Project path
        path_frame = tk.Frame(sidebar, bg=self.COLORS['card_bg'])
        path_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            path_frame,
            text="Project Path:",
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 5))
        
        path_entry_frame = tk.Frame(path_frame, bg=self.COLORS['card_bg'])
        path_entry_frame.pack(fill=tk.X)
        
        path_entry = tk.Entry(
            path_entry_frame,
            textvariable=self.project_path,
            font=("Segoe UI", 10),
            bg=self.COLORS['bg'],
            fg=self.COLORS['fg'],
            insertbackground=self.COLORS['fg'],
            relief=tk.FLAT,
            bd=2,
            highlightthickness=1,
            highlightbackground=self.COLORS['border'],
            highlightcolor=self.COLORS['accent']
        )
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        
        browse_btn = tk.Button(
            path_entry_frame,
            text="Browse",
            command=self.browse_project,
            font=("Segoe UI", 9),
            bg=self.COLORS['accent'],
            fg='white',
            activebackground=self.COLORS['accent_hover'],
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            padx=15,
            pady=5
        )
        browse_btn.pack(side=tk.RIGHT, padx=(5, 0))
        
        # Languages
        lang_frame = tk.Frame(sidebar, bg=self.COLORS['card_bg'])
        lang_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            lang_frame,
            text="Languages:",
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 5))
        
        self.python_var = tk.BooleanVar(value=True)
        self.js_var = tk.BooleanVar(value=True)
        
        tk.Checkbutton(
            lang_frame,
            text="Python",
            variable=self.python_var,
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            selectcolor=self.COLORS['bg'],
            activebackground=self.COLORS['card_bg'],
            activeforeground=self.COLORS['fg']
        ).pack(anchor=tk.W)
        
        tk.Checkbutton(
            lang_frame,
            text="JavaScript",
            variable=self.js_var,
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            selectcolor=self.COLORS['bg'],
            activebackground=self.COLORS['card_bg'],
            activeforeground=self.COLORS['fg']
        ).pack(anchor=tk.W)
        
        # Scan button
        scan_btn = tk.Button(
            sidebar,
            text="🚀 Start Scan",
            command=self.start_scan,
            font=("Segoe UI", 12, "bold"),
            bg=self.COLORS['success'],
            fg='white',
            activebackground='#3da895',
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            pady=12
        )
        scan_btn.pack(fill=tk.X, padx=20, pady=20)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            sidebar,
            variable=self.progress_var,
            maximum=100,
            mode='determinate',
            length=300
        )
        self.progress_bar.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        self.progress_label = tk.Label(
            sidebar,
            text="Ready to scan",
            font=("Segoe UI", 9),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg']
        )
        self.progress_label.pack(padx=20, pady=(0, 20))
        
        # Statistics
        stats_frame = tk.Frame(sidebar, bg=self.COLORS['card_bg'])
        stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            stats_frame,
            text="📊 Statistics",
            font=("Segoe UI", 12, "bold"),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            anchor=tk.W
        ).pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.Label(
            stats_frame,
            text="Findings: 0\nFiles: 0\nDuration: 0s",
            font=("Segoe UI", 10),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            justify=tk.LEFT,
            anchor=tk.W
        )
        self.stats_text.pack(fill=tk.X)
        
        # Right panel - Results
        results_frame = tk.Frame(content_frame, bg=self.COLORS['bg'])
        results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Filters
        filter_frame = tk.Frame(results_frame, bg=self.COLORS['card_bg'])
        filter_frame.pack(fill=tk.X, pady=(0, 15))
        
        tk.Label(
            filter_frame,
            text="🔍 Filters",
            font=("Segoe UI", 12, "bold"),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg']
        ).pack(side=tk.LEFT, padx=15, pady=10)
        
        # Severity filter
        severity_frame = tk.Frame(filter_frame, bg=self.COLORS['card_bg'])
        severity_frame.pack(side=tk.LEFT, padx=10)
        
        tk.Label(
            severity_frame,
            text="Severity:",
            font=("Segoe UI", 9),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg']
        ).pack(side=tk.LEFT, padx=(0, 5))
        
        severity_combo = ttk.Combobox(
            severity_frame,
            textvariable=self.filter_severity,
            values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            state="readonly",
            width=12,
            font=("Segoe UI", 9)
        )
        severity_combo.pack(side=tk.LEFT)
        severity_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Search
        search_frame = tk.Frame(filter_frame, bg=self.COLORS['card_bg'])
        search_frame.pack(side=tk.RIGHT, padx=15, pady=10)
        
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_text,
            font=("Segoe UI", 10),
            bg=self.COLORS['bg'],
            fg=self.COLORS['fg'],
            insertbackground=self.COLORS['fg'],
            relief=tk.FLAT,
            bd=2,
            highlightthickness=1,
            highlightbackground=self.COLORS['border'],
            highlightcolor=self.COLORS['accent'],
            width=30
        )
        search_entry.pack(side=tk.LEFT, ipady=3)
        search_entry.bind('<KeyRelease>', lambda e: self.apply_filters())
        
        # Findings tree
        tree_frame = tk.Frame(results_frame, bg=self.COLORS['bg'])
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        # Treeview with style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview",
                       background=self.COLORS['card_bg'],
                       foreground=self.COLORS['fg'],
                       fieldbackground=self.COLORS['card_bg'],
                       borderwidth=0)
        style.configure("Treeview.Heading",
                       background=self.COLORS['border'],
                       foreground=self.COLORS['fg'],
                       relief=tk.FLAT)
        style.map("Treeview", background=[('selected', self.COLORS['accent'])])
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        
        self.findings_tree = ttk.Treeview(
            tree_frame,
            columns=("Severity", "Score", "OWASP", "File", "Line", "Description"),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set,
            selectmode=tk.BROWSE
        )
        
        # Configure columns
        self.findings_tree.heading("Severity", text="Severity")
        self.findings_tree.heading("Score", text="Score")
        self.findings_tree.heading("OWASP", text="OWASP")
        self.findings_tree.heading("File", text="File")
        self.findings_tree.heading("Line", text="Line")
        self.findings_tree.heading("Description", text="Description")
        
        self.findings_tree.column("Severity", width=100)
        self.findings_tree.column("Score", width=80)
        self.findings_tree.column("OWASP", width=80)
        self.findings_tree.column("File", width=200)
        self.findings_tree.column("Line", width=60)
        self.findings_tree.column("Description", width=400)
        
        tree_scroll_y.config(command=self.findings_tree.yview)
        tree_scroll_x.config(command=self.findings_tree.xview)
        
        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.findings_tree.bind('<<TreeviewSelect>>', self.on_finding_select)
        
        # Details panel
        details_frame = tk.Frame(results_frame, bg=self.COLORS['card_bg'], height=250)
        details_frame.pack(fill=tk.X)
        details_frame.pack_propagate(False)
        
        tk.Label(
            details_frame,
            text="📋 Finding Details",
            font=("Segoe UI", 12, "bold"),
            bg=self.COLORS['card_bg'],
            fg=self.COLORS['fg'],
            anchor=tk.W
        ).pack(fill=tk.X, padx=15, pady=(15, 10))
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            font=("Consolas", 10),
            bg=self.COLORS['bg'],
            fg=self.COLORS['fg'],
            insertbackground=self.COLORS['fg'],
            relief=tk.FLAT,
            bd=0,
            wrap=tk.WORD,
            padx=15,
            pady=10
        )
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        # Log area (collapsible)
        self.log_visible = False
        log_toggle_btn = tk.Button(
            sidebar,
            text="📝 Show Log",
            command=self.toggle_log,
            font=("Segoe UI", 9),
            bg=self.COLORS['border'],
            fg=self.COLORS['fg'],
            activebackground=self.COLORS['accent'],
            activeforeground='white',
            relief=tk.FLAT,
            cursor='hand2',
            pady=5
        )
        log_toggle_btn.pack(fill=tk.X, padx=20, pady=10)
        
        self.log_frame = tk.Frame(sidebar, bg=self.COLORS['card_bg'])
        self.log_text = scrolledtext.ScrolledText(
            self.log_frame,
            font=("Consolas", 9),
            bg=self.COLORS['bg'],
            fg=self.COLORS['fg'],
            height=8,
            relief=tk.FLAT,
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def browse_project(self):
        """Browse for project directory."""
        path = filedialog.askdirectory(title="Select Project Directory")
        if path:
            self.project_path.set(path)
            self.log(f"Selected project: {path}")
    
    def toggle_log(self):
        """Toggle log visibility."""
        if self.log_visible:
            self.log_frame.pack_forget()
            self.log_visible = False
        else:
            self.log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
            self.log_visible = True
    
    def log(self, message, level="INFO"):
        """Add message to log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": self.COLORS['fg'],
            "WARNING": self.COLORS['warning'],
            "ERROR": self.COLORS['error'],
            "SUCCESS": self.COLORS['success']
        }
        color = colors.get(level, self.COLORS['fg'])
        
        formatted = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, formatted)
        self.log_text.tag_add(level, f"end-{len(formatted)}c", "end-1c")
        self.log_text.tag_config(level, foreground=color)
        self.log_text.see(tk.END)
    
    def update_progress(self):
        """Update progress from queue."""
        try:
            while True:
                message = self.progress_queue.get_nowait()
                if isinstance(message, dict):
                    if 'progress' in message:
                        self.progress_var.set(message['progress'])
                    if 'status' in message:
                        self.progress_label.config(text=message['status'])
                    if 'log' in message:
                        self.log(message['log'], message.get('level', 'INFO'))
        except queue.Empty:
            pass
        
        self.root.after(100, self.update_progress)
    
    def start_scan(self):
        """Start security scan."""
        if self.scan_running:
            messagebox.showwarning("Scan Running", "A scan is already in progress.")
            return
        
        project_path = self.project_path.get()
        if not project_path or not Path(project_path).exists():
            messagebox.showerror("Error", "Please select a valid project directory.")
            return
        
        # Get selected languages
        languages = []
        if self.python_var.get():
            languages.append('python')
        if self.js_var.get():
            languages.append('javascript')
        
        if not languages:
            messagebox.showerror("Error", "Please select at least one language.")
            return
        
        self.scan_running = True
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.all_findings = []
        self.progress_var.set(0)
        
        self.log("=" * 70, "INFO")
        self.log("OWASPGuard Scan Started", "INFO")
        self.log(f"Project: {project_path}", "INFO")
        self.log(f"Languages: {', '.join(languages)}", "INFO")
        self.log("Online CVE: Enabled", "INFO")
        
        # Run scan in thread
        thread = threading.Thread(target=self.run_scan, args=(project_path, languages), daemon=True)
        thread.start()
    
    def run_scan(self, project_path, languages):
        """Run scan in background thread."""
        try:
            orchestrator = ScanOrchestrator(
                project_path=project_path,
                languages=languages,
                use_online_cve=True
            )
            
            self.progress_queue.put({'status': 'Scanning...', 'progress': 10})
            
            results = orchestrator.scan()
            
            self.scan_results = results
            self.all_findings = results.get('findings', [])
            
            self.progress_queue.put({'status': 'Processing results...', 'progress': 90})
            
            # Update statistics
            stats = results.get('stats', {})
            stats_text = f"Findings: {len(self.all_findings)}\n"
            stats_text += f"Files: {stats.get('files_scanned', 0)}\n"
            stats_text += f"Duration: {stats.get('scan_duration', 0):.1f}s"
            self.stats_text.config(text=stats_text)
            
            # Populate findings
            self.populate_findings(self.all_findings)
            
            self.progress_queue.put({'status': 'Scan complete!', 'progress': 100})
            self.progress_queue.put({'log': f"Scan complete: {len(self.all_findings)} findings", 'level': 'SUCCESS'})
            
        except Exception as e:
            self.progress_queue.put({'log': f"Error: {str(e)}", 'level': 'ERROR'})
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        finally:
            self.scan_running = False
    
    def populate_findings(self, findings):
        """Populate findings tree."""
        self.findings_tree.delete(*self.findings_tree.get_children())
        
        severity_colors = {
            'CRITICAL': self.COLORS['critical'],
            'HIGH': self.COLORS['high'],
            'MEDIUM': self.COLORS['medium'],
            'LOW': self.COLORS['low'],
            'INFO': self.COLORS['info']
        }
        
        for idx, finding in enumerate(findings):
            severity = finding.get('severity', 'UNKNOWN')
            severity_score = finding.get('severity_score', 0)
            owasp = finding.get('owasp_category', 'N/A')
            file_path = Path(finding.get('file_path', '')).name
            line = finding.get('line_number', 'N/A')
            desc = finding.get('description', '')[:80] + '...' if len(finding.get('description', '')) > 80 else finding.get('description', '')
            
            unique_id = f"{finding.get('rule_id', 'rule')}_{file_path}_{line}_{idx}"
            
            item = self.findings_tree.insert('', tk.END, values=(
                severity, severity_score, owasp, file_path, line, desc
            ), tags=(severity,), iid=unique_id)
            
            # Color code by severity
            color = severity_colors.get(severity, self.COLORS['fg'])
            self.findings_tree.set(item, "Severity", severity)
    
    def apply_filters(self):
        """Apply filters to findings."""
        filtered = self.all_findings.copy()
        
        # Severity filter
        severity = self.filter_severity.get()
        if severity != "ALL":
            filtered = [f for f in filtered if f.get('severity') == severity]
        
        # Search filter
        search = self.search_text.get().lower()
        if search:
            filtered = [f for f in filtered if search in f.get('description', '').lower() or 
                       search in f.get('file_path', '').lower()]
        
        self.populate_findings(filtered)
    
    def on_finding_select(self, event):
        """Handle finding selection."""
        selection = self.findings_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        item_values = self.findings_tree.item(item_id)['values']
        
        if len(item_values) >= 5:
            file_name = item_values[3]
            line_num = item_values[4]
            
            finding = next(
                (f for f in self.all_findings 
                 if Path(f.get('file_path', '')).name == file_name 
                 and str(f.get('line_number', '')) == str(line_num)),
                None
            )
            
            if finding:
                self.show_finding_details(finding)
    
    def show_finding_details(self, finding):
        """Show detailed finding information."""
        self.details_text.delete(1.0, tk.END)
        
        details = f"🔍 Finding Details\n"
        details += "=" * 80 + "\n\n"
        
        details += f"📋 Description:\n{finding.get('description', 'N/A')}\n\n"
        details += f"⚠️  Severity: {finding.get('severity', 'N/A')} (Score: {finding.get('severity_score', 0)}/100)\n"
        
        ml_conf = finding.get('ml_confidence')
        # Safely format ML confidence (handle None / strings / invalid types)
        if ml_conf is not None:
            try:
                ml_value = float(ml_conf)
                # Expecting 0.0–1.0; clamp to sensible range
                if ml_value < 0:
                    ml_value = 0.0
                if ml_value > 1:
                    ml_value = 1.0
                details += f"🤖 ML Confidence: {ml_value:.1%}\n"
            except (TypeError, ValueError):
                # If it can't be parsed as float, just show raw value
                details += f"🤖 ML Confidence: {ml_conf}\n"
        
        details += f"🏷️  OWASP Category: {finding.get('owasp_category_full', finding.get('owasp_category', 'N/A'))}\n"
        details += f"📁 File: {finding.get('file_path', 'N/A')}\n"
        details += f"📍 Line: {finding.get('line_number', 'N/A')}\n"
        details += f"🆔 Rule ID: {finding.get('rule_id', 'N/A')}\n"
        details += f"🔧 Scan Type: {finding.get('scan_type', 'SAST')}\n\n"
        
        # Prefer a multi-line code snippet if available, otherwise fall back to a single line
        code_snippet = finding.get('code_snippet') or finding.get('line_content')
        if code_snippet:
            details += "💻 Code:\n"
            details += f"{code_snippet}\n\n"
        
        if finding.get('cve_id'):
            details += f"🔗 CVE ID: {finding.get('cve_id')}\n"
            details += f"📦 Package: {finding.get('package', 'N/A')}\n"
            details += f"📌 Version: {finding.get('version', 'N/A')}\n\n"
        
        if finding.get('remediation'):
            details += f"✅ Remediation:\n{finding.get('remediation')}\n\n"
        elif finding.get('recommendation'):
            details += f"✅ Recommendation:\n{finding.get('recommendation')}\n\n"
        
        if finding.get('confidence'):
            details += f"📊 Confidence: {finding.get('confidence', 'N/A')}\n"
        if finding.get('exploitability'):
            details += f"⚡ Exploitability: {finding.get('exploitability', 'N/A')}\n"
        
        self.details_text.insert(1.0, details)


def main():
    """Main entry point."""
    root = tk.Tk()
    app = ModernOWASPGuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

