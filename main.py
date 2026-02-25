"""
Main entry point for Mini-ZAP CLI.
"""
import argparse
import time
from crawler import WebCrawler
from scanners.sql_injection import SQLInjectionScanner
from scanners.xss import XSSScanner
from scanners.access_control import AccessControlScanner
from scanners.misconfiguration import MisconfigurationScanner
from scanners.ssrf import SSRFScanner
from reports.json_report import JSONReportGenerator
from reports.pdf_report import PDFReportGenerator


def main():
    """Main function for CLI execution."""
    parser = argparse.ArgumentParser(
        description='Mini-ZAP: OWASP Top 10 Automated Vulnerability Scanner'
    )
    parser.add_argument('--url', required=True, help='Target URL to scan')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5s)')
    parser.add_argument('--output-dir', default='.', help='Output directory for reports (default: current directory)')
    parser.add_argument('--skip-crawl', action='store_true', help='Skip crawling (use provided endpoints)')
    parser.add_argument('--scanners', nargs='+', 
                       choices=['sql', 'xss', 'access', 'misconfig', 'ssrf', 'all'],
                       default=['all'], help='Scanners to run')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Mini-ZAP: OWASP Top 10 Automated Vulnerability Scanner")
    print("=" * 60)
    print(f"\nTarget URL: {args.url}")
    print(f"Crawl Depth: {args.depth}")
    print(f"Delay: {args.delay}s\n")
    
    start_time = time.time()
    all_vulnerabilities = []
    
    # Crawl web application
    if not args.skip_crawl:
        print("[*] Starting web crawler...")
        crawler = WebCrawler(args.url, max_depth=args.depth, delay=args.delay)
        crawl_result = crawler.crawl()
        print(f"[+] Crawl complete: {crawl_result['total_endpoints']} endpoints, "
              f"{crawl_result['total_input_points']} input points\n")
    else:
        crawl_result = {
            'base_url': args.url,
            'endpoints': [],
            'input_points': []
        }
    
    # Determine which scanners to run
    scanners_to_run = []
    if 'all' in args.scanners:
        scanners_to_run = ['sql', 'xss', 'access', 'misconfig', 'ssrf']
    else:
        scanners_to_run = args.scanners
    
    # Run scanners
    if 'sql' in scanners_to_run:
        print("[*] Running SQL Injection scanner...")
        sql_scanner = SQLInjectionScanner(delay=args.delay)
        vulns = sql_scanner.scan(crawl_result['input_points'])
        all_vulnerabilities.extend(vulns)
        print(f"[+] SQL Injection scan complete: {len(vulns)} vulnerabilities found\n")
    
    if 'xss' in scanners_to_run:
        print("[*] Running XSS scanner...")
        xss_scanner = XSSScanner(delay=args.delay)
        vulns = xss_scanner.scan(crawl_result['input_points'])
        all_vulnerabilities.extend(vulns)
        print(f"[+] XSS scan complete: {len(vulns)} vulnerabilities found\n")
    
    if 'access' in scanners_to_run:
        print("[*] Running Access Control scanner...")
        access_scanner = AccessControlScanner(delay=args.delay)
        vulns = access_scanner.scan(crawl_result['endpoints'], crawl_result['base_url'])
        all_vulnerabilities.extend(vulns)
        print(f"[+] Access Control scan complete: {len(vulns)} vulnerabilities found\n")
    
    if 'misconfig' in scanners_to_run:
        print("[*] Running Security Misconfiguration scanner...")
        misconfig_scanner = MisconfigurationScanner(delay=args.delay)
        vulns = misconfig_scanner.scan(crawl_result['endpoints'])
        all_vulnerabilities.extend(vulns)
        print(f"[+] Security Misconfiguration scan complete: {len(vulns)} vulnerabilities found\n")
    
    if 'ssrf' in scanners_to_run:
        print("[*] Running SSRF scanner...")
        ssrf_scanner = SSRFScanner(delay=args.delay)
        vulns = ssrf_scanner.scan(crawl_result['input_points'])
        all_vulnerabilities.extend(vulns)
        print(f"[+] SSRF scan complete: {len(vulns)} vulnerabilities found\n")
    
    scan_duration = time.time() - start_time
    
    # Generate reports
    print("[*] Generating reports...")
    scan_info = {
        'target_url': args.url,
        'duration': scan_duration
    }
    
    json_report_path = f"{args.output_dir}/report.json"
    pdf_report_path = f"{args.output_dir}/report.pdf"
    
    json_gen = JSONReportGenerator()
    json_gen.generate(all_vulnerabilities, scan_info, json_report_path)
    print(f"[+] JSON report saved: {json_report_path}")
    
    pdf_gen = PDFReportGenerator()
    pdf_gen.generate(all_vulnerabilities, scan_info, pdf_report_path)
    print(f"[+] PDF report saved: {pdf_report_path}")
    
    # Print summary
    print("\n" + "=" * 60)
    print("Scan Summary")
    print("=" * 60)
    print(f"Total Vulnerabilities: {len(all_vulnerabilities)}")
    print(f"  - Critical: {len([v for v in all_vulnerabilities if v.risk_level.value == 'Critical'])}")
    print(f"  - High: {len([v for v in all_vulnerabilities if v.risk_level.value == 'High'])}")
    print(f"  - Medium: {len([v for v in all_vulnerabilities if v.risk_level.value == 'Medium'])}")
    print(f"  - Low: {len([v for v in all_vulnerabilities if v.risk_level.value == 'Low'])}")
    print(f"  - Informational: {len([v for v in all_vulnerabilities if v.risk_level.value == 'Informational'])}")
    print(f"\nScan Duration: {scan_duration:.2f} seconds")
    print("=" * 60)


if __name__ == "__main__":
    main()

