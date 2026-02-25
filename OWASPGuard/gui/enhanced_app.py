"""
Enhanced Professional GUI for OWASPGuard with progress tracking and filtering.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
from pathlib import Path
from datetime import datetime
import sys
import queue

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.orchestrator import ScanOrchestrator
from reporting.json_report import JSONReportGenerator
from reporting.pdf_report import PDFReportGenerator


class EnhancedOWASPGuardGUI:
    """Enhanced GUI with progress tracking and advanced features."""
    
    def __init__(self, root):
        """Initialize the enhanced GUI."""
        self.root = root
        self.root.title("OWASPGuard - Advanced Static Security Analyzer")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#f5f5f5')
        
        # Variables
        self.scan_running = False
        self.scan_results = None
        self.project_path = tk.StringVar()
        self.progress_queue = queue.Queue()
        
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
        """Setup the enhanced user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        header_frame.columnconfigure(1, weight=1)
        
        title_label = tk.Label(
            header_frame,
            text="🛡️ OWASPGuard",
            font=("Helvetica", 28, "bold"),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.grid(row=0, column=0, padx=(0, 10))
        
        subtitle = tk.Label(
            header_frame,
            text="Advanced Static Application Security Analyzer | OWASP Top 10 Compliance",
            font=("Helvetica", 11),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        subtitle.grid(row=0, column=1, sticky=tk.W)
        
        # Left panel - Configuration
        config_frame = ttk.LabelFrame(main_frame, text="⚙️ Scan Configuration", padding="15")
        config_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Project path
        ttk.Label(config_frame, text="📁 Project Path:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=8)
        path_frame = ttk.Frame(config_frame)
        path_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=8, padx=(5, 0))
        path_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.project_path, width=40, font=("Helvetica", 10))
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="Browse...", command=self.browse_project)
        browse_btn.grid(row=0, column=1)
        
        # Languages
        ttk.Label(config_frame, text="🔤 Languages:", font=("Helvetica", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=8)
        lang_frame = ttk.Frame(config_frame)
        lang_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=8, padx=(5, 0))
        
        self.python_var = tk.BooleanVar(value=True)
        self.js_var = tk.BooleanVar(value=True)
        self.java_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(lang_frame, text="Python", variable=self.python_var).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(lang_frame, text="JavaScript", variable=self.js_var).pack(side=tk.LEFT, padx=8)
        ttk.Checkbutton(lang_frame, text="Java", variable=self.java_var).pack(side=tk.LEFT, padx=8)
        
        # Online CVE fetching
        ttk.Label(config_frame, text="🌐 Online CVE Check:", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=8)
        self.online_cve_var = tk.BooleanVar(value=True)
        online_frame = ttk.Frame(config_frame)
        online_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=8, padx=(5, 0))
        ttk.Checkbutton(online_frame, text="Fetch real-time CVE data (takes 2-3 min)", variable=self.online_cve_var).pack(side=tk.LEFT)
        
        # Workers
        ttk.Label(config_frame, text="⚡ Worker Threads:", font=("Helvetica", 10, "bold")).grid(row=3, column=0, sticky=tk.W, pady=8)
        self.workers_var = tk.IntVar(value=4)
        workers_spin = ttk.Spinbox(config_frame, from_=1, to=16, textvariable=self.workers_var, width=37, font=("Helvetica", 10))
        workers_spin.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=8, padx=(5, 0))
        
        # Progress bar
        ttk.Label(config_frame, text="📊 Progress:", font=("Helvetica", 10, "bold")).grid(row=4, column=0, sticky=tk.W, pady=8)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(config_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=8, padx=(5, 0))
        
        self.progress_label = ttk.Label(config_frame, text="Ready", font=("Helvetica", 9))
        self.progress_label.grid(row=5, column=1, sticky=tk.W, padx=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=20)
        
        self.scan_btn = ttk.Button(
            button_frame,
            text="▶️ Start Scan",
            command=self.start_scan,
            width=28
        )
        self.scan_btn.pack(pady=5)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text="⏹️ Stop Scan",
            command=self.stop_scan,
            state=tk.DISABLED,
            width=28
        )
        self.stop_btn.pack(pady=5)
        
        self.export_btn = ttk.Button(
            button_frame,
            text="📄 Export Reports",
            command=self.export_reports,
            state=tk.DISABLED,
            width=28
        )
        self.export_btn.pack(pady=5)
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(main_frame, text="📋 Scan Results", padding="10")
        results_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Filter bar
        filter_frame = ttk.Frame(results_frame)
        filter_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        filter_frame.columnconfigure(2, weight=1)
        
        ttk.Label(filter_frame, text="Filter:", font=("Helvetica", 9, "bold")).grid(row=0, column=0, padx=5)
        
        ttk.Label(filter_frame, text="Severity:").grid(row=0, column=1, padx=5)
        severity_combo = ttk.Combobox(filter_frame, textvariable=self.filter_severity, 
                                      values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                                      width=12, state="readonly")
        severity_combo.grid(row=0, column=2, padx=5)
        severity_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
        
        ttk.Label(filter_frame, text="OWASP:").grid(row=0, column=3, padx=5)
        owasp_combo = ttk.Combobox(filter_frame, textvariable=self.filter_owasp,
                                   values=["ALL", "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
                                   width=12, state="readonly")
        owasp_combo.grid(row=0, column=4, padx=5)
        owasp_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())
        
        ttk.Label(filter_frame, text="Search:").grid(row=0, column=5, padx=5)
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_text, width=20)
        search_entry.grid(row=0, column=6, padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self.apply_filters())
        
        # Notebook for tabs
        notebook = ttk.Notebook(results_frame)
        notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Findings tab
        findings_frame = ttk.Frame(notebook)
        notebook.add(findings_frame, text="🔍 Findings")
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)
        
        # Treeview with scrollbars
        tree_frame = ttk.Frame(findings_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('Severity', 'Score', 'OWASP', 'File', 'Line', 'Description')
        self.findings_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=30)
        
        # Configure columns
        self.findings_tree.heading('Severity', text='Severity')
        self.findings_tree.heading('Score', text='Score')
        self.findings_tree.heading('OWASP', text='OWASP')
        self.findings_tree.heading('File', text='File')
        self.findings_tree.heading('Line', text='Line')
        self.findings_tree.heading('Description', text='Description')
        
        self.findings_tree.column('Severity', width=100, anchor=tk.CENTER)
        self.findings_tree.column('Score', width=60, anchor=tk.CENTER)
        self.findings_tree.column('OWASP', width=80, anchor=tk.CENTER)
        self.findings_tree.column('File', width=250)
        self.findings_tree.column('Line', width=60, anchor=tk.CENTER)
        self.findings_tree.column('Description', width=450)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.findings_tree.xview)
        self.findings_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.findings_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        self.findings_tree.bind('<<TreeviewSelect>>', self.on_finding_select)
        self.findings_tree.bind('<Double-1>', lambda e: self.show_finding_details())
        
        # Details frame
        details_frame = ttk.LabelFrame(findings_frame, text="📝 Finding Details", padding="10")
        details_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        details_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#ffffff',
            fg='#2c3e50',
            height=10
        )
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Summary tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="📊 Summary")
        summary_frame.columnconfigure(0, weight=1)
        summary_frame.rowconfigure(0, weight=1)
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            font=("Helvetica", 11),
            bg='#ffffff',
            fg='#2c3e50'
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="📜 Log")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#1e1e1e',
            fg='#d4d4d4',
            insertbackground='white'
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="✅ Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, font=("Helvetica", 9))
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Statistics display
        stats_frame = ttk.Frame(main_frame)
        stats_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        self.stats_label = tk.Label(
            stats_frame,
            text="Findings: 0 | Files: 0 | Duration: 0s",
            font=("Helvetica", 9),
            bg='#f5f5f5',
            fg='#34495e'
        )
        self.stats_label.pack()
    
    def browse_project(self):
        """Browse for project directory."""
        path = filedialog.askdirectory(title="Select Project Directory")
        if path:
            self.project_path.set(path)
            self.log(f"Selected project: {path}")
    
    def log(self, message, level="INFO"):
        """Add message to log with color coding."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        colors = {
            "INFO": "#d4d4d4",
            "WARNING": "#ffa500",
            "ERROR": "#f48771",
            "SUCCESS": "#4ec9b0"
        }
        color = colors.get(level, "#d4d4d4")
        
        formatted = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, formatted)
        self.log_text.tag_add(level, f"end-{len(formatted)}c", "end-1c")
        self.log_text.tag_config(level, foreground=color)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_progress(self):
        """Update progress from queue."""
        try:
            while True:
                message = self.progress_queue.get_nowait()
                if message['type'] == 'progress':
                    self.progress_var.set(message['value'])
                    self.progress_label.config(text=message['text'])
                elif message['type'] == 'log':
                    self.log(message['text'], message.get('level', 'INFO'))
        except queue.Empty:
            pass
        
        self.root.after(100, self.update_progress)
    
    def start_scan(self):
        """Start scan in background thread."""
        if self.scan_running:
            return
        
        project_path = self.project_path.get().strip()
        if not project_path:
            messagebox.showerror("Error", "Please select a project directory")
            return
        
        if not Path(project_path).exists():
            messagebox.showerror("Error", "Project path does not exist")
            return
        
        self.scan_running = True
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)
        self.findings_tree.delete(*self.findings_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        
        # Get selected languages
        languages = []
        if self.python_var.get():
            languages.append('python')
        if self.js_var.get():
            languages.append('javascript')
        if self.java_var.get():
            languages.append('java')
        
        if not languages:
            messagebox.showerror("Error", "Please select at least one language")
            self.scan_running = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            return
        
        # Start scan thread
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(project_path, languages, self.workers_var.get(), self.online_cve_var.get()),
            daemon=True
        )
        scan_thread.start()
    
    def stop_scan(self):
        """Stop running scan."""
        self.scan_running = False
        self.log("Scan stopped by user", "WARNING")
        self.status_var.set("⏹️ Scan stopped")
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def run_scan(self, project_path, languages, workers, use_online):
        """Run the scan with progress updates."""
        try:
            self.progress_queue.put({'type': 'log', 'text': "=" * 70, 'level': 'INFO'})
            self.progress_queue.put({'type': 'log', 'text': "OWASPGuard Scan Started", 'level': 'INFO'})
            self.progress_queue.put({'type': 'log', 'text': f"Project: {project_path}", 'level': 'INFO'})
            self.progress_queue.put({'type': 'log', 'text': f"Languages: {', '.join(languages)}", 'level': 'INFO'})
            self.progress_queue.put({'type': 'log', 'text': f"Online CVE: {'Enabled' if use_online else 'Disabled'}", 'level': 'INFO'})
            self.progress_queue.put({'type': 'progress', 'value': 10, 'text': 'Initializing scan...'})
            
            # Create orchestrator with online CVE option
            orchestrator = ScanOrchestrator(project_path, languages, workers, use_online_cve=use_online)
            
            self.progress_queue.put({'type': 'progress', 'value': 20, 'text': 'Loading files...'})
            results = orchestrator.scan()
            
            self.scan_results = results
            findings = results.get('findings', [])
            
            self.progress_queue.put({'type': 'progress', 'value': 90, 'text': 'Processing results...'})
            
            # Populate findings tree
            self.all_findings = findings
            self.populate_findings(findings)
            
            # Update summary
            self.update_summary(results)
            
            self.progress_queue.put({'type': 'progress', 'value': 100, 'text': 'Complete!'})
            self.progress_queue.put({'type': 'log', 'text': f"✅ Scan complete: {len(findings)} findings", 'level': 'SUCCESS'})
            self.status_var.set(f"✅ Scan complete - {len(findings)} findings")
            self.export_btn.config(state=tk.NORMAL)
            
            # Update stats
            stats = results.get('stats', {})
            self.stats_label.config(
                text=f"Findings: {len(findings)} | Files: {stats.get('files_scanned', 0)} | Duration: {stats.get('scan_duration', 0):.2f}s"
            )
            
        except Exception as e:
            self.progress_queue.put({'type': 'log', 'text': f"❌ Error: {str(e)}", 'level': 'ERROR'})
            messagebox.showerror("Scan Error", f"An error occurred:\n{str(e)}")
        finally:
            self.scan_running = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
    
    def populate_findings(self, findings):
        """Populate findings tree."""
        self.findings_tree.delete(*self.findings_tree.get_children())
        
        for idx, finding in enumerate(findings):
            severity = finding.get('severity', 'UNKNOWN')
            severity_score = finding.get('severity_score', 0)
            owasp = finding.get('owasp_code', 'N/A')
            file_path = Path(finding.get('file_path', '')).name
            line = finding.get('line_number', 'N/A')
            desc = finding.get('description', '')[:70] + '...' if len(finding.get('description', '')) > 70 else finding.get('description', '')
            
            # Generate unique ID to avoid duplicates
            unique_id = f"{finding.get('rule_id', 'rule')}_{file_path}_{line}_{idx}"
            
            item = self.findings_tree.insert('', tk.END, values=(severity, severity_score, owasp, file_path, line, desc),
                                            tags=(severity,), iid=unique_id)
            
            # Color code by severity
            if severity == 'CRITICAL':
                self.findings_tree.set(item, 'Severity', '🔴 CRITICAL')
            elif severity == 'HIGH':
                self.findings_tree.set(item, 'Severity', '🟠 HIGH')
            elif severity == 'MEDIUM':
                self.findings_tree.set(item, 'Severity', '🟡 MEDIUM')
            elif severity == 'LOW':
                self.findings_tree.set(item, 'Severity', '🔵 LOW')
            
            # Set score with color coding
            if severity_score >= 90:
                score_display = f"🔴 {severity_score}"
            elif severity_score >= 70:
                score_display = f"🟠 {severity_score}"
            elif severity_score >= 40:
                score_display = f"🟡 {severity_score}"
            elif severity_score >= 20:
                score_display = f"🔵 {severity_score}"
            else:
                score_display = f"⚪ {severity_score}"
            
            self.findings_tree.set(item, 'Score', score_display)
    
    def apply_filters(self):
        """Apply filters to findings."""
        if not hasattr(self, 'all_findings'):
            return
        
        filtered = self.all_findings
        
        # Filter by severity
        if self.filter_severity.get() != "ALL":
            filtered = [f for f in filtered if f.get('severity') == self.filter_severity.get()]
        
        # Filter by OWASP
        if self.filter_owasp.get() != "ALL":
            filtered = [f for f in filtered if f.get('owasp_code') == self.filter_owasp.get()]
        
        # Filter by search text
        search = self.search_text.get().lower()
        if search:
            filtered = [f for f in filtered if search in f.get('description', '').lower() or 
                       search in f.get('file_path', '').lower()]
        
        self.populate_findings(filtered)
    
    def on_finding_select(self, event):
        """Handle finding selection."""
        selection = self.findings_tree.selection()
        if not selection or not self.scan_results:
            return
        
        item_id = selection[0]
        
        # Get values from tree to find matching finding
        item_values = self.findings_tree.item(item_id)['values']
        if len(item_values) >= 5:
            file_name = item_values[2]  # File column
            line_num = item_values[4]    # Line column
            
            # Find finding by file and line
            finding = next(
                (f for f in self.all_findings 
                 if Path(f.get('file_path', '')).name == file_name 
                 and str(f.get('line_number', '')) == str(line_num)),
                None
            )
            
            if finding:
                self.show_finding_details(finding)
    
    def show_finding_details(self, finding=None):
        """Show detailed finding information."""
        if not finding:
            selection = self.findings_tree.selection()
            if not selection:
                return
            
            item_id = selection[0]
            item_values = self.findings_tree.item(item_id)['values']
            
            if len(item_values) >= 5:
                # Find by file and line (more reliable)
                file_name = item_values[2]
                line_num = item_values[4]
                
                finding = next(
                    (f for f in self.all_findings 
                     if Path(f.get('file_path', '')).name == file_name 
                     and str(f.get('line_number', '')) == str(line_num)),
                    None
                )
            
            if not finding:
                # Fallback to rule_id
                finding = next((f for f in self.all_findings if f.get('rule_id') == item_id), None)
        
        if not finding:
            return
        
        self.details_text.delete(1.0, tk.END)
        
        details = f"🔍 Finding Details\n"
        details += "=" * 70 + "\n\n"
        details += f"📋 Description:\n{finding.get('description', 'N/A')}\n\n"
        details += f"⚠️  Severity: {finding.get('severity', 'N/A')}\n"
        details += f"📊 Severity Score: {finding.get('severity_score', 'N/A')}/100\n"
        if finding.get('ml_confidence'):
            details += f"🤖 ML Confidence: {finding.get('ml_confidence', 0):.2%}\n"
        details += f"🏷️  OWASP Category: {finding.get('owasp_category_full', 'N/A')}\n"
        details += f"📁 File: {finding.get('file_path', 'N/A')}\n"
        details += f"📍 Line: {finding.get('line_number', 'N/A')}\n"
        details += f"🆔 Rule ID: {finding.get('rule_id', 'N/A')}\n\n"
        
        if finding.get('line_content'):
            details += f"💻 Code:\n{finding.get('line_content')}\n\n"
        
        # Show comprehensive remediation
        if finding.get('remediation'):
            details += f"{finding.get('remediation')}\n\n"
        elif finding.get('recommendation'):
            details += f"✅ Recommendation:\n{finding.get('recommendation')}\n\n"
        
        if finding.get('evidence'):
            details += f"🔎 Evidence:\n{finding.get('evidence')}\n\n"
        
        self.details_text.insert(tk.END, details)
    
    def update_summary(self, results):
        """Update summary tab."""
        self.summary_text.delete(1.0, tk.END)
        
        findings = results.get('findings', [])
        stats = results.get('stats', {})
        categorized = results.get('categorized', {})
        
        summary = "📊 OWASPGuard Scan Summary\n"
        summary += "=" * 70 + "\n\n"
        summary += f"📁 Files Scanned: {stats.get('files_scanned', 0)}\n"
        summary += f"🔍 Total Findings: {len(findings)}\n"
        summary += f"⏱️  Scan Duration: {stats.get('scan_duration', 0):.2f} seconds\n\n"
        
        # Severity breakdown
        severity_count = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        summary += "📈 Findings by Severity:\n"
        summary += "-" * 70 + "\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_count.get(severity, 0)
            if count > 0:
                bar = "█" * min(count, 50)
                summary += f"  {severity:10} {count:4} {bar}\n"
        
        summary += "\n🏷️  Findings by OWASP Category:\n"
        summary += "-" * 70 + "\n"
        for category, cat_findings in sorted(categorized.items(), key=lambda x: len(x[1]), reverse=True):
            summary += f"  {category}: {len(cat_findings)}\n"
        
        self.summary_text.insert(tk.END, summary)
    
    def export_reports(self):
        """Export reports."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export")
            return
        
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        try:
            self.log("Generating reports...", "INFO")
            
            json_gen = JSONReportGenerator()
            json_path = json_gen.generate(self.scan_results, output_dir)
            self.log(f"✅ JSON report: {json_path}", "SUCCESS")
            
            pdf_gen = PDFReportGenerator()
            pdf_path = pdf_gen.generate(self.scan_results, output_dir)
            self.log(f"✅ PDF report: {pdf_path}", "SUCCESS")
            
            messagebox.showinfo("Success", f"Reports exported to:\n{output_dir}")
            
        except Exception as e:
            self.log(f"❌ Export error: {str(e)}", "ERROR")
            messagebox.showerror("Export Error", f"Error exporting reports:\n{str(e)}")


def main():
    """Main function to run enhanced GUI."""
    root = tk.Tk()
    app = EnhancedOWASPGuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

