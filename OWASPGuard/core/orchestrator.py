"""
Scan orchestrator - coordinates all scanners and manages scan workflow.
This is the main controller for the entire scanning process.
"""
import time
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.file_loader import FileLoader
from core.rule_engine import RuleEngine
from core.owasp_mapper import OWASPMapper
from core.risk_engine import RiskEngine
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher
from core.incremental_scanner import IncrementalScanner
from core.parallel_scanner import ParallelScanner

# Try to import taint analysis
try:
    from scanners.taint_analysis import run_taint_analysis
    TAINT_AVAILABLE = True
except ImportError:
    TAINT_AVAILABLE = False
    run_taint_analysis = None

# Try to import entropy scanner
try:
    from scanners.entropy_scanner import EntropyScanner
    ENTROPY_AVAILABLE = True
except ImportError:
    ENTROPY_AVAILABLE = False
    EntropyScanner = None

# Try to import context-aware scanner
try:
    from scanners.context_patterns import run_context_analysis
    CONTEXT_AVAILABLE = True
except ImportError:
    CONTEXT_AVAILABLE = False
    run_context_analysis = None
import sys
from pathlib import Path

# Add project root to path for imports
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from scanners.sast.python_scanner import PythonScanner
    from scanners.sast.js_scanner import JavaScriptScanner
    from scanners.comprehensive_scanner import ComprehensiveScanner
    from scanners.sca.dependency_parser import DependencyParser
    from scanners.sca.cve_matcher import CVEMatcher
    from scanners.config_scan.secrets_scanner import SecretsScanner
    from scanners.config_scan.env_scanner import EnvScanner
    # OWASP Top 10 scanners
    from scanners.owasp import (
        AccessControlScanner, CryptoScanner, InjectionScanner,
        InsecureDesignScanner, SecurityMisconfigurationScanner,
        AuthenticationFailuresScanner, DataIntegrityScanner,
        LoggingFailuresScanner, SSRFScanner
    )
    OWASP_SCANNERS_AVAILABLE = True
except ImportError as e:
    print(f"[!] Warning: Could not import scanners: {e}")
    PythonScanner = None
    JavaScriptScanner = None
    ComprehensiveScanner = None
    DependencyParser = None
    CVEMatcher = None
    SecretsScanner = None
    EnvScanner = None
    OWASP_SCANNERS_AVAILABLE = False
    AccessControlScanner = None
    CryptoScanner = None
    InjectionScanner = None
    InsecureDesignScanner = None
    SecurityMisconfigurationScanner = None
    AuthenticationFailuresScanner = None
    DataIntegrityScanner = None
    LoggingFailuresScanner = None
    SSRFScanner = None


class ScanOrchestrator:
    """Orchestrates the entire scanning process."""
    
    def __init__(self, project_path: str, languages: List[str] = None, max_workers: int = 4, use_online_cve: bool = True):
        """
        Initialize scan orchestrator.
        
        Args:
            project_path: Path to project to scan
            languages: List of languages to scan
            max_workers: Maximum number of worker threads
            use_online_cve: Whether to fetch CVE data from online sources
        """
        self.project_path = project_path
        self.languages = languages or ['python', 'javascript']
        self.max_workers = max_workers
        self.use_online_cve = use_online_cve
        
        # Initialize components
        self.file_loader = FileLoader(project_path, languages)
        self.rule_engine = RuleEngine()
        self.owasp_mapper = OWASPMapper()
        self.risk_engine = RiskEngine()
        
        # Initialize scanners
        if PythonScanner:
            self.python_scanner = PythonScanner(self.rule_engine) if 'python' in self.languages else None
        else:
            self.python_scanner = None
        
        if JavaScriptScanner:
            self.js_scanner = JavaScriptScanner(self.rule_engine) if 'javascript' in self.languages else None
        else:
            self.js_scanner = None
        
        # Comprehensive scanner for maximum coverage
        if ComprehensiveScanner:
            try:
                self.comprehensive_scanner = ComprehensiveScanner(self.rule_engine)
            except:
                self.comprehensive_scanner = None
        else:
            self.comprehensive_scanner = None
        
        if DependencyParser:
            self.dependency_parser = DependencyParser()
        else:
            self.dependency_parser = None
        
        if CVEMatcher:
            self.cve_matcher = CVEMatcher(use_online=self.use_online_cve)
        else:
            self.cve_matcher = None
        
        if SecretsScanner:
            self.secrets_scanner = SecretsScanner(self.rule_engine)
        else:
            self.secrets_scanner = None
        
        if EnvScanner:
            self.env_scanner = EnvScanner(self.rule_engine)
        else:
            self.env_scanner = None
        
        # Results storage
        self.findings: List[Dict] = []
        self.scan_stats = {
            'files_scanned': 0,
            'findings_count': 0,
            'scan_duration': 0.0
        }
        
        # Incremental scanning (disabled by default to ensure full coverage)
        self.incremental_scanner = IncrementalScanner()
        self.use_incremental = False
        
        # Parallel scanning
        self.parallel_scanner = ParallelScanner(max_workers=self.max_workers)
        
        # Entropy scanner
        if ENTROPY_AVAILABLE and EntropyScanner:
            self.entropy_scanner = EntropyScanner()
        else:
            self.entropy_scanner = None
        
        # Severity scorer and remediation fetcher
        from core.severity_scorer import SeverityScorer
        from core.remediation_fetcher import RemediationFetcher
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
        
        # Initialize OWASP Top 10 scanners
        if OWASP_SCANNERS_AVAILABLE:
            self.owasp_scanners = {
                'A01': AccessControlScanner() if AccessControlScanner else None,
                'A02': CryptoScanner() if CryptoScanner else None,
                'A03': InjectionScanner() if InjectionScanner else None,
                'A04': InsecureDesignScanner() if InsecureDesignScanner else None,
                'A05': SecurityMisconfigurationScanner() if SecurityMisconfigurationScanner else None,
                'A07': AuthenticationFailuresScanner() if AuthenticationFailuresScanner else None,
                'A08': DataIntegrityScanner() if DataIntegrityScanner else None,
                'A09': LoggingFailuresScanner() if LoggingFailuresScanner else None,
                'A10': SSRFScanner() if SSRFScanner else None,
            }
        else:
            self.owasp_scanners = {}
        
        # ML Classifier
        try:
            from core.ml_classifier import VulnerabilityClassifier
            self.ml_classifier = VulnerabilityClassifier()
        except:
            self.ml_classifier = None
    
    def scan(self) -> Dict:
        """
        Execute full scan of the project.
        
        Returns:
            Dictionary containing scan results and statistics
        """
        start_time = time.time()
        
        print(f"[*] Starting scan of {self.project_path}")
        print(f"[*] Languages: {', '.join(self.languages)}")
        
        # Phase 1: SAST Scanning
        print("\n[*] Phase 1: Static Code Analysis (SAST)")
        self._run_sast_scan()
        
        # Phase 2: SCA Scanning
        print("\n[*] Phase 2: Software Composition Analysis (SCA)")
        self._run_sca_scan()
        
        # Phase 3: Configuration Scanning
        print("\n[*] Phase 3: Configuration & Secrets Scanning")
        self._run_config_scan()
        
        # Phase 4: Post-processing
        print("\n[*] Phase 4: Post-processing findings")
        self._post_process_findings()
        
        scan_duration = time.time() - start_time
        self.scan_stats['scan_duration'] = scan_duration
        self.scan_stats['findings_count'] = len(self.findings)
        
        print(f"\n[+] Scan complete: {len(self.findings)} findings in {scan_duration:.2f}s")
        
        return {
            'findings': self.findings,
            'stats': self.scan_stats,
            'categorized': self.owasp_mapper.categorize_findings(self.findings)
        }
    
    def _run_sast_scan(self):
        """Run SAST scanners on source code files."""
        all_files = list(self.file_loader.get_files())
        
        # Use incremental scanning if enabled
        if self.use_incremental:
            file_extensions = {'.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go'}
            changed_files = self.incremental_scanner.get_changed_files(
                Path(self.project_path),
                file_extensions
            )
            
            if changed_files:
                files = list(changed_files)
                cache_stats = self.incremental_scanner.get_cache_stats()
                print(f"[*] Incremental scan: {len(files)} changed files (cached: {cache_stats['cached_files']})")
            else:
                files = []
                print("[*] No changed files detected - skipping SAST scan")
        else:
            files = all_files
        
        self.scan_stats['files_scanned'] = len(files)
        
        if not files:
            return
        
        print(f"[*] Scanning {len(files)} files...")
        
        # Use parallel scanner for faster processing
        def scan_single_file(file_path: Path) -> List[Dict]:
            """Scan a single file with all available scanners"""
            findings = []
            
            # Comprehensive scanner (primary)
            if self.comprehensive_scanner and file_path.suffix in ['.py', '.js', '.jsx', '.ts', '.tsx']:
                try:
                    file_findings = self.comprehensive_scanner.scan_file(file_path)
                    findings.extend(file_findings)
                except:
                    pass
            
            # Language-specific scanners (fallback)
            if file_path.suffix == '.py' and self.python_scanner:
                try:
                    file_findings = self.python_scanner.scan_file(file_path)
                    findings.extend(file_findings)
                except:
                    pass
            elif file_path.suffix in ['.js', '.jsx', '.ts', '.tsx'] and self.js_scanner:
                try:
                    file_findings = self.js_scanner.scan_file(file_path)
                    findings.extend(file_findings)
                except:
                    pass
            
            # Taint analysis for Python files
            if TAINT_AVAILABLE and run_taint_analysis and file_path.suffix == '.py':
                try:
                    taint_findings = run_taint_analysis(file_path)
                    findings.extend(taint_findings)
                except:
                    pass
            
            # Context-aware analysis for Python files
            if CONTEXT_AVAILABLE and run_context_analysis and file_path.suffix == '.py':
                try:
                    context_findings = run_context_analysis(file_path)
                    findings.extend(context_findings)
                except:
                    pass
            
            # Entropy-based secret detection
            if self.entropy_scanner:
                try:
                    entropy_findings = self.entropy_scanner.scan_file(file_path)
                    findings.extend(entropy_findings)
                except:
                    pass
            
            # OWASP Top 10 scanners (comprehensive coverage)
            if self.owasp_scanners:
                for category, scanner in self.owasp_scanners.items():
                    if scanner:
                        try:
                            owasp_findings = scanner.scan_file(file_path)
                            # Add severity scores and remediation to OWASP findings
                            for finding in owasp_findings:
                                if 'severity_score' not in finding:
                                    finding['severity_score'] = self.severity_scorer.calculate_severity_score(finding)
                                if 'remediation' not in finding:
                                    try:
                                        finding['remediation'] = self.remediation_fetcher.get_comprehensive_remediation(finding)
                                    except:
                                        finding['remediation'] = finding.get('recommendation', '')
                            findings.extend(owasp_findings)
                        except Exception as e:
                            # Silently continue if scanner fails
                            pass
            
            # ML-based scoring for findings (do NOT filter out any)
            if self.ml_classifier and findings:
                for finding in findings:
                    code_snippet = finding.get('line_content', '')
                    if not code_snippet:
                        continue
                    try:
                        is_vuln, confidence = self.ml_classifier.predict(
                            code_snippet,
                            {
                                'file_path': str(file_path),
                                'type': finding.get('type', ''),
                            },
                        )
                        finding['ml_confidence'] = confidence
                    except Exception:
                        # Ignore ML failures; keep raw finding
                        continue
            
            return findings
        
        # Scan files in parallel
        print(f"[*] Scanning {len(files)} files in parallel ({self.max_workers} workers)...")
        all_findings = self.parallel_scanner.scan_files_parallel(files, scan_single_file)
        self.findings.extend(all_findings)
        
        print(f"[+] SAST scan complete: {len(self.findings)} findings from {len(files)} files")
    
    def _run_sca_scan(self):
        """Run SCA scanner on dependency files."""
        if not self.dependency_parser or not self.cve_matcher:
            print("[!] SCA scanner not available")
            return
        
        project_path = Path(self.project_path)
        print(f"[*] Scanning dependencies in {project_path}")
        
        # Check for dependency files (also search subdirectories)
        dep_files = []
        for pattern in ['requirements.txt', 'package.json', 'pom.xml', 'Pipfile', 'poetry.lock', 'yarn.lock']:
            for dep_path in project_path.rglob(pattern):
                dep_files.append(dep_path)
        
        if not dep_files:
            print("[!] No dependency files found")
            return
        
        print(f"[*] Found {len(dep_files)} dependency files")
        
        total_vulns = 0
        for dep_path in dep_files:
            try:
                print(f"[*] Parsing {dep_path.name}...")
                dependencies = self.dependency_parser.parse(dep_path)
                print(f"[*] Found {len(dependencies)} dependencies in {dep_path.name}")
                
                if dependencies:
                    vulnerabilities = self.cve_matcher.match(dependencies)
                    print(f"[+] Found {len(vulnerabilities)} vulnerabilities in {dep_path.name}")
                    
                    for vuln in vulnerabilities:
                        severity_score = self.severity_scorer.calculate_severity_score({
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'owasp_category': 'A06',
                            'confidence': 'high'
                        })
                        
                        finding = {
                            'rule_id': f'SCA-{vuln.get("cve_id", "UNKNOWN")}-{hash(str(dep_path)) % 100000}',
                            'line_number': 0,
                            'line_content': f"{vuln['package']}=={vuln.get('version', 'unknown')}",
                            'match': vuln['package'],
                            'file_path': str(dep_path),
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'severity_score': severity_score,
                            'owasp_category': 'A06',
                            'owasp_category_full': 'A06:2021 - Vulnerable and Outdated Components',
                            'description': f"Vulnerable dependency: {vuln['package']} {vuln.get('version', 'unknown')} - {vuln.get('cve_id', 'UNKNOWN')}. {vuln.get('description', '')}",
                            'recommendation': f"Update {vuln['package']} to version {vuln.get('fixed_version', 'latest')}",
                            'cve_id': vuln.get('cve_id', 'UNKNOWN'),
                            'package': vuln['package'],
                            'version': vuln.get('version', 'unknown'),
                            'confidence': 'high',
                            'exploitability': 'high',
                            'scan_type': 'SCA'
                        }
                        
                        # Add remediation
                        try:
                            remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                            finding['remediation'] = remediation
                        except:
                            finding['remediation'] = f"Update {vuln['package']} to a secure version"
                        
                        self.findings.append(finding)
                        total_vulns += 1
                        
            except Exception as e:
                print(f"[!] Error scanning {dep_path}: {e}")
        
        print(f"[+] SCA scan complete: {total_vulns} dependency vulnerabilities found")
    
    def _run_config_scan(self):
        """Run configuration and secrets scanning."""
        if not self.secrets_scanner or not self.env_scanner:
            return
        
        files = list(self.file_loader.get_files())
        print(f"[*] Scanning {len(files)} files for secrets and misconfigurations...")
        
        secrets_count = 0
        config_count = 0
        
        for file_path in files:
            # Secrets scanning (scan all files, not just config files)
            try:
                secrets_findings = self.secrets_scanner.scan_file(file_path)
                if secrets_findings:
                    self.findings.extend(secrets_findings)
                    secrets_count += len(secrets_findings)
            except Exception as e:
                pass
            
            # Environment file scanning
            if '.env' in file_path.name.lower() or 'config' in file_path.name.lower() or 'settings' in file_path.name.lower():
                try:
                    env_findings = self.env_scanner.scan_file(file_path)
                    if env_findings:
                        self.findings.extend(env_findings)
                        config_count += len(env_findings)
                except Exception as e:
                    pass
        
        print(f"[+] Config scan complete: {secrets_count} secrets, {config_count} misconfigurations")
    
    def _post_process_findings(self):
        """Post-process findings: map to OWASP, assess risk."""
        # Ensure all findings have OWASP category
        for finding in self.findings:
            # If OWASP category not set, try to infer from type
            if 'owasp_category' not in finding or not finding.get('owasp_category') or finding.get('owasp_category') == 'UNKNOWN':
                finding_type = finding.get('type', '').lower()
                if 'sql' in finding_type or 'injection' in finding_type or 'command' in finding_type or 'nosql' in finding_type:
                    finding['owasp_category'] = 'A03'
                elif 'xss' in finding_type:
                    finding['owasp_category'] = 'A03'
                elif 'access' in finding_type or 'authorization' in finding_type or 'idor' in finding_type or 'csrf' in finding_type:
                    finding['owasp_category'] = 'A01'
                elif 'crypto' in finding_type or 'hash' in finding_type or 'encryption' in finding_type or 'weak' in finding_type:
                    finding['owasp_category'] = 'A02'
                elif 'secret' in finding_type or 'password' in finding_type or 'hardcoded' in finding_type:
                    finding['owasp_category'] = 'A02'
                elif 'auth' in finding_type or 'login' in finding_type or 'session' in finding_type:
                    finding['owasp_category'] = 'A07'
                elif 'ssrf' in finding_type:
                    finding['owasp_category'] = 'A10'
                elif 'deserialization' in finding_type or 'pickle' in finding_type or 'yaml' in finding_type:
                    finding['owasp_category'] = 'A08'
                elif 'logging' in finding_type or 'log' in finding_type:
                    finding['owasp_category'] = 'A09'
                elif 'config' in finding_type or 'misconfiguration' in finding_type or 'cors' in finding_type:
                    finding['owasp_category'] = 'A05'
                elif 'design' in finding_type or 'validation' in finding_type or 'default' in finding_type:
                    finding['owasp_category'] = 'A04'
                elif 'dependency' in finding_type or 'cve' in finding_type or 'vulnerable' in finding_type or 'sca' in finding_type.lower():
                    finding['owasp_category'] = 'A06'
                else:
                    finding['owasp_category'] = 'A04'  # Default to insecure design
        
        # Map to OWASP categories
        self.findings = [self.owasp_mapper.map_finding(f) for f in self.findings]
        
        # Ensure severity scores and lightweight remediation
        for finding in self.findings:
            if 'severity_score' not in finding:
                finding['severity_score'] = self.severity_scorer.calculate_severity_score(finding)
            # Avoid expensive online remediation calls for every finding to keep
            # post‑processing fast; prefer existing recommendation text.
            if 'remediation' not in finding:
                finding['remediation'] = finding.get(
                    'recommendation',
                    'Review and fix the vulnerability according to best practices for this issue type.',
                )
        
        # Assess risk
        self.findings = self.risk_engine.assess_findings(self.findings)
        
        # Sort by severity score (highest first)
        self.findings.sort(key=lambda x: x.get('severity_score', 0), reverse=True)

