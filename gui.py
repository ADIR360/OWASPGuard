"""
GUI application for Mini-ZAP vulnerability scanner.
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import time
from datetime import datetime
import os
from crawler import WebCrawler
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss import XSSScanner
from scanners.access_control import AccessControlScanner
from scanners.misconfiguration import MisconfigurationScanner
from scanners.ssrf import SSRFScanner
from reports.json_report import JSONReportGenerator
from reports.pdf_report import PDFReportGenerator
from utils.vulnerability import RiskLevel


class MiniZAPGUI:
    """Main GUI application class."""
    
    def __init__(self, root):
        """Initialize the GUI application."""
        self.root = root
        self.root.title("Mini-ZAP - OWASP Top 10 Vulnerability Scanner")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f5f5f5')
        
        # Variables
        self.scan_running = False
        self.vulnerabilities = []
        self.scan_info = {}
        
        # Setup UI
        self.setup_ui()
        
        # Center window
        self.center_window()
    
    def center_window(self):
        """Center the window on screen."""
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
            text="Mini-ZAP Vulnerability Scanner",
            font=("Helvetica", 20, "bold"),
            bg='#f5f5f5',
            fg='#2c3e50'
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Left panel - Configuration
        config_frame = ttk.LabelFrame(main_frame, text="Scan Configuration", padding="10")
        config_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        config_frame.columnconfigure(1, weight=1)
        
        # Target URL
        ttk.Label(config_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(config_frame, width=30)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        self.url_entry.insert(0, "https://example.com")
        
        # Crawl depth
        ttk.Label(config_frame, text="Crawl Depth:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.depth_var = tk.IntVar(value=2)
        depth_spinbox = ttk.Spinbox(config_frame, from_=1, to=5, textvariable=self.depth_var, width=27)
        depth_spinbox.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Delay
        ttk.Label(config_frame, text="Request Delay (s):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.delay_var = tk.DoubleVar(value=0.5)
        delay_spinbox = ttk.Spinbox(config_frame, from_=0.1, to=5.0, increment=0.1, 
                                    textvariable=self.delay_var, width=27)
        delay_spinbox.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Scanners selection
        ttk.Label(config_frame, text="Scanners:").grid(row=3, column=0, sticky=tk.W, pady=5)
        scanner_frame = ttk.Frame(config_frame)
        scanner_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.access_var = tk.BooleanVar(value=True)
        self.misconfig_var = tk.BooleanVar(value=True)
        self.ssrf_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(scanner_frame, text="SQL Injection", variable=self.sql_var).pack(anchor=tk.W)
        ttk.Checkbutton(scanner_frame, text="XSS", variable=self.xss_var).pack(anchor=tk.W)
        ttk.Checkbutton(scanner_frame, text="Access Control", variable=self.access_var).pack(anchor=tk.W)
        ttk.Checkbutton(scanner_frame, text="Misconfiguration", variable=self.misconfig_var).pack(anchor=tk.W)
        ttk.Checkbutton(scanner_frame, text="SSRF", variable=self.ssrf_var).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        self.start_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan,
            width=20
        )
        self.start_button.pack(pady=5)
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan,
            state=tk.DISABLED,
            width=20
        )
        self.stop_button.pack(pady=5)
        
        self.export_button = ttk.Button(
            button_frame,
            text="Export Reports",
            command=self.export_reports,
            width=20
        )
        self.export_button.pack(pady=5)
        
        # Right panel - Output
        output_frame = ttk.LabelFrame(main_frame, text="Scan Output", padding="10")
        output_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        # Notebook for tabs
        notebook = ttk.Notebook(output_frame)
        notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        output_frame.rowconfigure(0, weight=1)
        
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
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(notebook)
        notebook.add(vuln_frame, text="Vulnerabilities")
        vuln_frame.columnconfigure(0, weight=1)
        vuln_frame.rowconfigure(0, weight=1)
        
        # Treeview for vulnerabilities
        tree_frame = ttk.Frame(vuln_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        columns = ('ID', 'Title', 'Risk', 'Category', 'URL')
        self.vuln_tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=150)
        
        self.vuln_tree.column('Title', width=250)
        self.vuln_tree.column('URL', width=300)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Bind selection event
        self.vuln_tree.bind('<<TreeviewSelect>>', self.on_vuln_select)
        
        # Details frame
        details_frame = ttk.LabelFrame(vuln_frame, text="Vulnerability Details", padding="10")
        details_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        details_frame.columnconfigure(0, weight=1)
        vuln_frame.rowconfigure(1, weight=1)
        
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
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def log(self, message, level="INFO"):
        """Add message to log."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}\n"
        self.log_text.insert(tk.END, formatted_message)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def start_scan(self):
        """Start the vulnerability scan in a separate thread."""
        if self.scan_running:
            return
        
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, url)
        
        self.scan_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.vulnerabilities = []
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the running scan."""
        self.scan_running = False
        self.log("Scan stopped by user", "WARNING")
        self.status_var.set("Scan stopped")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
    
    def run_scan(self):
        """Run the vulnerability scan."""
        try:
            url = self.url_entry.get().strip()
            depth = self.depth_var.get()
            delay = self.delay_var.get()
            
            self.log("=" * 60)
            self.log("Mini-ZAP Vulnerability Scan Started")
            self.log("=" * 60)
            self.log(f"Target URL: {url}")
            self.log(f"Crawl Depth: {depth}")
            self.log(f"Request Delay: {delay}s")
            self.status_var.set("Scanning...")
            
            start_time = time.time()
            
            # Crawl
            self.log("\n[*] Starting web crawler...")
            crawler = WebCrawler(url, max_depth=depth, delay=delay)
            crawl_result = crawler.crawl()
            self.log(f"[+] Crawl complete: {crawl_result['total_endpoints']} endpoints, "
                    f"{crawl_result['total_input_points']} input points")
            
            if not self.scan_running:
                return
            
            # Run scanners
            scanners_to_run = []
            if self.sql_var.get():
                scanners_to_run.append(('SQL Injection', SQLInjectionScanner(delay=delay)))
            if self.xss_var.get():
                scanners_to_run.append(('XSS', XSSScanner(delay=delay)))
            if self.access_var.get():
                scanners_to_run.append(('Access Control', AccessControlScanner(delay=delay)))
            if self.misconfig_var.get():
                scanners_to_run.append(('Misconfiguration', MisconfigurationScanner(delay=delay)))
            if self.ssrf_var.get():
                scanners_to_run.append(('SSRF', SSRFScanner(delay=delay)))
            
            for scanner_name, scanner in scanners_to_run:
                if not self.scan_running:
                    break
                
                self.log(f"\n[*] Running {scanner_name} scanner...")
                self.status_var.set(f"Running {scanner_name} scanner...")
                
                if scanner_name == 'Access Control':
                    vulns = scanner.scan(crawl_result['endpoints'], crawl_result['base_url'])
                elif scanner_name == 'Misconfiguration':
                    vulns = scanner.scan(crawl_result['endpoints'])
                else:
                    vulns = scanner.scan(crawl_result['input_points'])
                
                self.vulnerabilities.extend(vulns)
                self.log(f"[+] {scanner_name} scan complete: {len(vulns)} vulnerabilities found")
                
                # Update treeview
                for vuln in vulns:
                    self.vuln_tree.insert('', tk.END, values=(
                        vuln.id,
                        vuln.title,
                        vuln.risk_level.value,
                        vuln.category.value,
                        vuln.url[:50] + '...' if len(vuln.url) > 50 else vuln.url
                    ))
            
            scan_duration = time.time() - start_time
            self.scan_info = {
                'target_url': url,
                'duration': scan_duration
            }
            
            # Update summary
            self.update_summary()
            
            self.log("\n" + "=" * 60)
            self.log("Scan Complete")
            self.log("=" * 60)
            self.log(f"Total Vulnerabilities: {len(self.vulnerabilities)}")
            self.log(f"Scan Duration: {scan_duration:.2f} seconds")
            
            self.status_var.set(f"Scan complete - {len(self.vulnerabilities)} vulnerabilities found")
            
        except Exception as e:
            self.log(f"Error during scan: {str(e)}", "ERROR")
            messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{str(e)}")
        finally:
            self.scan_running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def update_summary(self):
        """Update the summary tab."""
        self.summary_text.delete(1.0, tk.END)
        
        if not self.vulnerabilities:
            self.summary_text.insert(tk.END, "No vulnerabilities detected.\n")
            return
        
        summary = f"Scan Summary\n"
        summary += "=" * 60 + "\n\n"
        summary += f"Target URL: {self.scan_info.get('target_url', 'N/A')}\n"
        summary += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        summary += f"Total Vulnerabilities: {len(self.vulnerabilities)}\n"
        summary += f"Scan Duration: {self.scan_info.get('duration', 0):.2f} seconds\n\n"
        
        summary += "Risk Level Distribution:\n"
        summary += "-" * 60 + "\n"
        summary += f"Critical: {len([v for v in self.vulnerabilities if v.risk_level == RiskLevel.CRITICAL])}\n"
        summary += f"High: {len([v for v in self.vulnerabilities if v.risk_level == RiskLevel.HIGH])}\n"
        summary += f"Medium: {len([v for v in self.vulnerabilities if v.risk_level == RiskLevel.MEDIUM])}\n"
        summary += f"Low: {len([v for v in self.vulnerabilities if v.risk_level == RiskLevel.LOW])}\n"
        summary += f"Informational: {len([v for v in self.vulnerabilities if v.risk_level == RiskLevel.INFO])}\n\n"
        
        summary += "By Category:\n"
        summary += "-" * 60 + "\n"
        categories = {}
        for vuln in self.vulnerabilities:
            cat = vuln.category.value
            categories[cat] = categories.get(cat, 0) + 1
        
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            summary += f"{cat}: {count}\n"
        
        self.summary_text.insert(tk.END, summary)
    
    def on_vuln_select(self, event):
        """Handle vulnerability selection."""
        selection = self.vuln_tree.selection()
        if not selection:
            return
        
        item = self.vuln_tree.item(selection[0])
        vuln_id = item['values'][0]
        
        # Find vulnerability
        vuln = next((v for v in self.vulnerabilities if v.id == vuln_id), None)
        if not vuln:
            return
        
        # Display details
        self.details_text.delete(1.0, tk.END)
        details = f"Title: {vuln.title}\n"
        details += f"Risk Level: {vuln.risk_level.value}\n"
        details += f"Category: {vuln.category.value}\n"
        details += f"URL: {vuln.url}\n"
        details += f"Method: {vuln.method}\n"
        if vuln.parameter:
            details += f"Parameter: {vuln.parameter}\n"
        if vuln.payload:
            details += f"Payload: {vuln.payload}\n"
        details += f"\nDescription:\n{vuln.description}\n"
        if vuln.evidence:
            details += f"\nEvidence:\n{vuln.evidence}\n"
        if vuln.recommendation:
            details += f"\nRecommendation:\n{vuln.recommendation}\n"
        
        self.details_text.insert(tk.END, details)
    
    def export_reports(self):
        """Export vulnerability reports."""
        if not self.vulnerabilities:
            messagebox.showwarning("No Data", "No vulnerabilities to export. Please run a scan first.")
            return
        
        # Ask for directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        try:
            json_path = os.path.join(output_dir, "report.json")
            pdf_path = os.path.join(output_dir, "report.pdf")
            
            self.log(f"\n[*] Generating reports...")
            self.status_var.set("Generating reports...")
            
            # Generate JSON report
            json_gen = JSONReportGenerator()
            json_gen.generate(self.vulnerabilities, self.scan_info, json_path)
            self.log(f"[+] JSON report saved: {json_path}")
            
            # Generate PDF report
            pdf_gen = PDFReportGenerator()
            pdf_gen.generate(self.vulnerabilities, self.scan_info, pdf_path)
            self.log(f"[+] PDF report saved: {pdf_path}")
            
            messagebox.showinfo("Success", f"Reports exported successfully to:\n{output_dir}")
            self.status_var.set("Reports exported")
            
        except Exception as e:
            self.log(f"Error exporting reports: {str(e)}", "ERROR")
            messagebox.showerror("Export Error", f"An error occurred while exporting reports:\n{str(e)}")


def main():
    """Main function to run the GUI."""
    root = tk.Tk()
    app = MiniZAPGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

