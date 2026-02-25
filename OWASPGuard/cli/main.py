"""
CLI entry point for OWASPGuard.
"""
import argparse
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from cli.commands import ScanCommand, ReportCommand


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='OWASPGuard - Offline Static Application Security Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan ./project
  %(prog)s scan --lang python,javascript ./repo
  %(prog)s report --pdf
  %(prog)s report --json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan a project for vulnerabilities')
    scan_parser.add_argument('path', help='Path to project directory or file')
    scan_parser.add_argument('--lang', '--languages', 
                            help='Comma-separated list of languages (python,javascript,java)',
                            default='python,javascript')
    scan_parser.add_argument('--output', '-o', 
                            help='Output directory for reports',
                            default='.')
    scan_parser.add_argument('--workers', '-w',
                            type=int,
                            help='Number of worker threads',
                            default=4)
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports from scan results')
    report_parser.add_argument('--json', action='store_true', help='Generate JSON report')
    report_parser.add_argument('--pdf', action='store_true', help='Generate PDF report')
    report_parser.add_argument('--input', '-i', help='Input scan results JSON file')
    report_parser.add_argument('--output', '-o', help='Output directory', default='.')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == 'scan':
            languages = [l.strip() for l in args.lang.split(',')]
            cmd = ScanCommand()
            cmd.execute(args.path, languages, args.output, args.workers)
        
        elif args.command == 'report':
            cmd = ReportCommand()
            cmd.execute(args)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

