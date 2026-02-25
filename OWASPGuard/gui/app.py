"""
Professional GUI for OWASPGuard using tkinter.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
from pathlib import Path
from datetime import datetime
import sys

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.orchestrator import ScanOrchestrator
from reporting.json_report import JSONReportGenerator
from reporting.pdf_report import PDFReportGenerator


class OWASPGuardGUI:
    """Main GUI application class."""
    
    def __init__(self, root):
        """Initialize the GUI."""
        self.root = root
        self.root.title("OWASPGuard - Static Application Security Analyzer")
        self.root.geometry("1400x900")
        self.root.configure(bg='#f5f5f5')
        
        # Variables
        self.scan_running = False
        self.scan_results = None
        self.project_path = tk.StringVar()
        
        # Setup UI
        self.setup_ui()
        self.center_window()
    
    def center_window(self):
        """Center window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="OWASPGuard",
            font=("Helvetica", 24, "bold"),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        subtitle = tk.Label(
            main_frame,
            text="Offline Static Application Security Analyzer for OWASP Top 10 Compliance",
            font=("Helvetica", 10),
            bg='#f5f5f5',
            fg='#7f8c8d'
        )
        subtitle.grid(row=1, column=0, columnspan=2, pady=(0, 20))
        
        # Left panel - Configuration
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="15")
        config_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Project path
        ttk.Label(config_frame, text="Project Path:").grid(row=0, column=0, sticky=tk.W, pady=5)
        path_frame = ttk.Frame(config_frame)
        path_frame.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        path_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(path_frame, textvariable=self.project_path, width=40)
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse_project)
        browse_btn.grid(row=0, column=1)
        
        # Languages
        ttk.Label(config_frame, text="Languages:").grid(row=1, column=0, sticky=tk.W, pady=5)
        lang_frame = ttk.Frame(config_frame)
        lang_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        self.python_var = tk.BooleanVar(value=True)
        self.js_var = tk.BooleanVar(value=True)
        self.java_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(lang_frame, text="Python", variable=self.python_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(lang_frame, text="JavaScript", variable=self.js_var).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(lang_frame, text="Java", variable=self.java_var).pack(side=tk.LEFT, padx=5)
        
        # Workers
        ttk.Label(config_frame, text="Worker Threads:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.workers_var = tk.IntVar(value=4)
        workers_spin = ttk.Spinbox(config_frame, from_=1, to=16, textvariable=self.workers_var, width=37)
        workers_spin.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        self.scan_btn = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            width=25
        )
        self.scan_btn.pack(pady=5)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            state=tk.DISABLED,
            width=25
        )
        self.stop_btn.pack(pady=5)
        
        self.export_btn = ttk.Button(
            button_frame,
            text="Export Reports",
            command=self.export_reports,
            state=tk.DISABLED,
            width=25
        )
        self.export_btn.pack(pady=5)
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="10")
        results_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Notebook for tabs
        notebook = ttk.Notebook(results_frame)
        notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Log tab
        log_frame = ttk.Frame(notebook)
        notebook.add(log_frame, text="Log")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg='#ffffff',
            fg='#2c3e50'
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Findings tab
        findings_frame = ttk.Frame(notebook)
        notebook.add(findings_frame, text="Findings")
        findings_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(0, weight=1)
        
        # Treeview for findings
        tree_frame = ttk.Frame(findings_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('Severity', 'OWASP', 'File', 'Line', 'Description')
        self.findings_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.findings_tree.heading(col, text=col)
            self.findings_tree.column(col, width=150)
        
        self.findings_tree.column('Description', width=400)
        self.findings_tree.column('File', width=300)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=scrollbar.set)
        
        self.findings_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        self.findings_tree.bind('<<TreeviewSelect>>', self.on_finding_select)
        
        # Details frame
        details_frame = ttk.LabelFrame(findings_frame, text="Finding Details", padding="10")
        details_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        details_frame.columnconfigure(0, weight=1)
        findings_frame.rowconfigure(1, weight=1)
        
        self.details_text = scrolledtext.ScrolledText(
            details_frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg='#ffffff',
            fg='#2c3e50',
            height=8
        )
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Summary tab
        summary_frame = ttk.Frame(notebook)
        notebook.add(summary_frame, text="Summary")
        summary_frame.columnconfigure(0, weight=1)
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            font=("Helvetica", 11),
            bg='#ffffff',
            fg='#2c3e50'
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def browse_project(self):
        """Browse for project directory."""
        path = filedialog.askdirectory(title="Select Project Directory")
        if path:
            self.project_path.set(path)
    
    def log(self, message, level="INFO"):
        """Add message to log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, formatted)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
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
        self.log_text.delete(1.0, tk.END)
        
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
            args=(project_path, languages, self.workers_var.get()),
            daemon=True
        )
        scan_thread.start()
    
    def stop_scan(self):
        """Stop running scan."""
        self.scan_running = False
        self.log("Scan stopped by user", "WARNING")
        self.status_var.set("Scan stopped")
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def run_scan(self, project_path, languages, workers):
        """Run the scan."""
        try:
            self.log("=" * 70)
            self.log("OWASPGuard Scan Started")
            self.log("=" * 70)
            self.log(f"Project: {project_path}")
            self.log(f"Languages: {', '.join(languages)}")
            self.status_var.set("Scanning...")
            
            orchestrator = ScanOrchestrator(project_path, languages, workers)
            results = orchestrator.scan()
            
            self.scan_results = results
            findings = results.get('findings', [])
            
            # Populate findings tree
            for finding in findings:
                self.findings_tree.insert('', tk.END, values=(
                    finding.get('severity', 'UNKNOWN'),
                    finding.get('owasp_code', 'N/A'),
                    Path(finding.get('file_path', '')).name,
                    finding.get('line_number', 'N/A'),
                    finding.get('description', '')[:80] + '...' if len(finding.get('description', '')) > 80 else finding.get('description', '')
                ), tags=(finding.get('severity', 'UNKNOWN'),))
            
            # Update summary
            self.update_summary(results)
            
            self.log(f"\n[+] Scan complete: {len(findings)} findings")
            self.status_var.set(f"Scan complete - {len(findings)} findings")
            self.export_btn.config(state=tk.NORMAL)
            
        except Exception as e:
            self.log(f"Error: {str(e)}", "ERROR")
            messagebox.showerror("Scan Error", f"An error occurred:\n{str(e)}")
        finally:
            self.scan_running = False
            self.scan_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
    
    def update_summary(self, results):
        """Update summary tab."""
        self.summary_text.delete(1.0, tk.END)
        
        findings = results.get('findings', [])
        stats = results.get('stats', {})
        categorized = results.get('categorized', {})
        
        summary = "OWASPGuard Scan Summary\n"
        summary += "=" * 70 + "\n\n"
        summary += f"Files Scanned: {stats.get('files_scanned', 0)}\n"
        summary += f"Total Findings: {len(findings)}\n"
        summary += f"Scan Duration: {stats.get('scan_duration', 0):.2f} seconds\n\n"
        
        # Severity breakdown
        severity_count = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        summary += "Findings by Severity:\n"
        summary += "-" * 70 + "\n"
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_count.get(severity, 0)
            if count > 0:
                summary += f"  {severity}: {count}\n"
        
        summary += "\nFindings by OWASP Category:\n"
        summary += "-" * 70 + "\n"
        for category, cat_findings in sorted(categorized.items(), key=lambda x: len(x[1]), reverse=True):
            summary += f"  {category}: {len(cat_findings)}\n"
        
        self.summary_text.insert(tk.END, summary)
    
    def on_finding_select(self, event):
        """Handle finding selection."""
        selection = self.findings_tree.selection()
        if not selection or not self.scan_results:
            return
        
        item = self.findings_tree.item(selection[0])
        values = item['values']
        
        # Find corresponding finding
        findings = self.scan_results.get('findings', [])
        if not findings:
            return
        
        # Match by description (simplified)
        selected_desc = values[4] if len(values) > 4 else ''
        finding = next((f for f in findings if selected_desc in f.get('description', '')), None)
        
        if finding:
            self.details_text.delete(1.0, tk.END)
            details = f"Description: {finding.get('description', 'N/A')}\n"
            details += f"Severity: {finding.get('severity', 'N/A')}\n"
            details += f"OWASP Category: {finding.get('owasp_category_full', 'N/A')}\n"
            details += f"File: {finding.get('file_path', 'N/A')}\n"
            details += f"Line: {finding.get('line_number', 'N/A')}\n"
            if finding.get('line_content'):
                details += f"\nCode:\n{finding.get('line_content')}\n"
            if finding.get('recommendation'):
                details += f"\nRecommendation:\n{finding.get('recommendation')}\n"
            
            self.details_text.insert(tk.END, details)
    
    def export_reports(self):
        """Export reports."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export")
            return
        
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        try:
            self.log("Generating reports...")
            
            json_gen = JSONReportGenerator()
            json_path = json_gen.generate(self.scan_results, output_dir)
            self.log(f"JSON report: {json_path}")
            
            pdf_gen = PDFReportGenerator()
            pdf_path = pdf_gen.generate(self.scan_results, output_dir)
            self.log(f"PDF report: {pdf_path}")
            
            messagebox.showinfo("Success", f"Reports exported to:\n{output_dir}")
            
        except Exception as e:
            self.log(f"Export error: {str(e)}", "ERROR")
            messagebox.showerror("Export Error", f"Error exporting reports:\n{str(e)}")


def main():
    """Main function to run GUI."""
    root = tk.Tk()
    app = OWASPGuardGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

