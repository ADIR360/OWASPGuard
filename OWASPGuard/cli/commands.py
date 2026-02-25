"""
CLI commands implementation.
"""
import json
from pathlib import Path
from datetime import datetime
from core.orchestrator import ScanOrchestrator
from reporting.json_report import JSONReportGenerator
from reporting.pdf_report import PDFReportGenerator
try:
    from reporting.html_report import HTMLReportGenerator
    HTML_REPORT_AVAILABLE = True
except ImportError:
    HTML_REPORT_AVAILABLE = False


class ScanCommand:
    """Scan command handler."""
    
    def execute(self, project_path: str, languages: list, output_dir: str, workers: int):
        """
        Execute scan command.
        
        Args:
            project_path: Path to project
            languages: List of languages to scan
            output_dir: Output directory for reports
            workers: Number of worker threads
        """
        print("=" * 70)
        print("OWASPGuard - Offline Static Application Security Analyzer")
        print("=" * 70)
        print(f"\nProject: {project_path}")
        print(f"Languages: {', '.join(languages)}")
        print(f"Workers: {workers}\n")
        
        # Initialize orchestrator
        orchestrator = ScanOrchestrator(project_path, languages, workers)
        
        # Run scan
        results = orchestrator.scan()
        
        # Save results
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        results_file = output_path / "scan_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[+] Results saved to: {results_file}")
        
        # Generate reports
        print("\n[*] Generating reports...")
        
        json_report = JSONReportGenerator()
        json_report_path = json_report.generate(results, output_dir)
        print(f"[+] JSON report: {json_report_path}")
        
        pdf_report = PDFReportGenerator()
        pdf_report_path = pdf_report.generate(results, output_dir)
        print(f"[+] PDF report: {pdf_report_path}")
        
        # Generate HTML report
        if HTML_REPORT_AVAILABLE:
            try:
                metadata = {
                    'project_path': project_path,
                    'files_scanned': stats.get('files_scanned', 0),
                    'lines_scanned': 0,  # Could be calculated
                    'duration': stats.get('scan_duration', 0),
                    'scanners': ['SAST', 'SCA', 'Config']
                }
                html_report = HTMLReportGenerator(results.get('findings', []), metadata)
                html_path = Path(output_dir) / f"owaspguard_report_{Path(output_dir).name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                html_report.generate(str(html_path))
                print(f"[+] HTML report: {html_path}")
            except Exception as e:
                print(f"[!] Could not generate HTML report: {e}")
        
        # Print summary
        self._print_summary(results)
    
    def _print_summary(self, results: dict):
        """Print scan summary."""
        findings = results.get('findings', [])
        stats = results.get('stats', {})
        
        print("\n" + "=" * 70)
        print("Scan Summary")
        print("=" * 70)
        print(f"Files Scanned: {stats.get('files_scanned', 0)}")
        print(f"Total Findings: {len(findings)}")
        print(f"Scan Duration: {stats.get('scan_duration', 0):.2f} seconds")
        
        # Count by severity
        severity_count = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        print("\nFindings by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        # Count by OWASP category
        categorized = results.get('categorized', {})
        print("\nFindings by OWASP Category:")
        for category, cat_findings in sorted(categorized.items(), key=lambda x: len(x[1]), reverse=True):
            print(f"  {category}: {len(cat_findings)}")
        
        print("=" * 70)


class ReportCommand:
    """Report command handler."""
    
    def execute(self, args):
        """
        Execute report command.
        
        Args:
            args: Command arguments
        """
        # Load scan results
        if args.input:
            results_file = Path(args.input)
        else:
            # Look for default results file
            results_file = Path(args.output) / "scan_results.json"
        
        if not results_file.exists():
            print(f"[!] Error: Scan results file not found: {results_file}")
            return
        
        with open(results_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate requested reports
        if args.json or (not args.json and not args.pdf):
            json_report = JSONReportGenerator()
            json_path = json_report.generate(results, str(output_dir))
            print(f"[+] JSON report generated: {json_path}")
        
        if args.pdf or (not args.json and not args.pdf):
            pdf_report = PDFReportGenerator()
            pdf_path = pdf_report.generate(results, str(output_dir))
            print(f"[+] PDF report generated: {pdf_path}")

