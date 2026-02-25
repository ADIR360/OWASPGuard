"""
Comprehensive vulnerability scanner - detects ALL types of security issues.
Designed to match and exceed CodeRabbit's detection capabilities.
"""
import ast
import re
from pathlib import Path
from typing import List, Dict, Set, Optional
from core.rule_engine import RuleEngine
from core.file_loader import FileLoader
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher


class ComprehensiveScanner:
    """
    Comprehensive scanner that detects all types of vulnerabilities.
    Matches CodeRabbit's comprehensive detection approach.
    """
    
    def __init__(self, rule_engine: RuleEngine):
        """Initialize comprehensive scanner."""
        self.rule_engine = rule_engine
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
        
        # Comprehensive vulnerability patterns - expanded to match CodeRabbit coverage
        self.vulnerability_patterns = self._load_comprehensive_patterns()
        
        # Additional code quality and security patterns
        self.code_quality_patterns = self._load_code_quality_patterns()
    
    def _load_comprehensive_patterns(self) -> Dict[str, List[Dict]]:
        """Load comprehensive vulnerability patterns."""
        return {
            'injection': [
                {'pattern': r'execute\s*\([^)]*\+', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'query\s*\([^)]*\+', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'\.format\s*\([^)]*request\.', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'f["\'].*\{.*request\.', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'eval\s*\(', 'type': 'code_injection', 'severity': 'CRITICAL'},
                {'pattern': r'exec\s*\(', 'type': 'code_injection', 'severity': 'CRITICAL'},
                {'pattern': r'compile\s*\([^)]*str\s*\(', 'type': 'code_injection', 'severity': 'HIGH'},
                {'pattern': r'__import__\s*\(', 'type': 'code_injection', 'severity': 'HIGH'},
                {'pattern': r'os\.system\s*\(', 'type': 'command_injection', 'severity': 'CRITICAL'},
                {'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'type': 'command_injection', 'severity': 'HIGH'},
                {'pattern': r'popen\s*\(', 'type': 'command_injection', 'severity': 'HIGH'},
            ],
            'xss': [
                {'pattern': r'innerHTML\s*=', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'outerHTML\s*=', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'document\.write\s*\(', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'\.html\s*\([^)]*request\.', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'\.append\s*\([^)]*request\.', 'type': 'xss', 'severity': 'MEDIUM'},
            ],
            'crypto': [
                {'pattern': r'md5\s*\(', 'type': 'weak_crypto', 'severity': 'MEDIUM'},
                {'pattern': r'sha1\s*\(', 'type': 'weak_crypto', 'severity': 'MEDIUM'},
                {'pattern': r'hashlib\.md5', 'type': 'weak_crypto', 'severity': 'MEDIUM'},
                {'pattern': r'hashlib\.sha1', 'type': 'weak_crypto', 'severity': 'MEDIUM'},
                {'pattern': r'DES\s', 'type': 'weak_crypto', 'severity': 'HIGH'},
                {'pattern': r'RC4\s', 'type': 'weak_crypto', 'severity': 'HIGH'},
                {'pattern': r'password\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_secret', 'severity': 'CRITICAL'},
                {'pattern': r'api_key\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_secret', 'severity': 'CRITICAL'},
                {'pattern': r'secret\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_secret', 'severity': 'CRITICAL'},
                {'pattern': r'token\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_secret', 'severity': 'CRITICAL'},
            ],
            'access_control': [
                {'pattern': r'@app\.route\s*\([^)]*\)\s*\n\s*def\s+\w+\s*\(', 'type': 'missing_auth', 'severity': 'HIGH', 'multiline': True},
                {'pattern': r'def\s+(admin|delete|update|remove)\w*\s*\([^)]*\):', 'type': 'missing_auth', 'severity': 'MEDIUM'},
                {'pattern': r'if\s+.*==\s*["\']admin["\']:', 'type': 'weak_auth', 'severity': 'HIGH'},
            ],
            'misconfiguration': [
                {'pattern': r'DEBUG\s*=\s*True', 'type': 'debug_enabled', 'severity': 'MEDIUM'},
                {'pattern': r'debug\s*=\s*true', 'type': 'debug_enabled', 'severity': 'MEDIUM'},
                {'pattern': r'SECRET_KEY\s*=\s*["\'][^"\']{0,20}["\']', 'type': 'weak_secret', 'severity': 'CRITICAL'},
                {'pattern': r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']', 'type': 'wildcard_hosts', 'severity': 'HIGH'},
                {'pattern': r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True', 'type': 'cors_wildcard', 'severity': 'MEDIUM'},
            ],
            'ssrf': [
                {'pattern': r'requests\.(get|post|put|delete)\s*\([^)]*request\.', 'type': 'ssrf', 'severity': 'HIGH'},
                {'pattern': r'urllib\.(urlopen|request)\s*\([^)]*request\.', 'type': 'ssrf', 'severity': 'HIGH'},
                {'pattern': r'httplib\.(HTTPConnection|HTTPSConnection)\s*\([^)]*request\.', 'type': 'ssrf', 'severity': 'HIGH'},
            ],
            'path_traversal': [
                {'pattern': r'open\s*\([^)]*\.\./', 'type': 'path_traversal', 'severity': 'HIGH'},
                {'pattern': r'file\s*\([^)]*\.\./', 'type': 'path_traversal', 'severity': 'HIGH'},
                {'pattern': r'os\.path\.join\s*\([^)]*request\.', 'type': 'path_traversal', 'severity': 'MEDIUM'},
            ],
            'deserialization': [
                {'pattern': r'pickle\.(loads?|dumps?)', 'type': 'unsafe_deserialization', 'severity': 'HIGH'},
                {'pattern': r'yaml\.(load|safe_load)', 'type': 'unsafe_deserialization', 'severity': 'MEDIUM'},
                {'pattern': r'json\.loads\s*\([^)]*request\.', 'type': 'unsafe_deserialization', 'severity': 'MEDIUM'},
            ],
            'logging': [
                {'pattern': r'except\s+.*:\s*\n\s*pass', 'type': 'silent_exception', 'severity': 'MEDIUM', 'multiline': True},
                {'pattern': r'except\s+.*:\s*\n\s*return', 'type': 'no_error_logging', 'severity': 'LOW', 'multiline': True},
            ],
            'race_condition': [
                {'pattern': r'if\s+os\.path\.exists\s*\([^)]*\):\s*\n\s*open\s*\(', 'type': 'race_condition', 'severity': 'MEDIUM', 'multiline': True},
            ],
            'weak_random': [
                {'pattern': r'random\.(randint|choice|random)', 'type': 'weak_random', 'severity': 'MEDIUM'},
            ],
            'insecure_comparison': [
                {'pattern': r'password\s*==\s*', 'type': 'plaintext_password', 'severity': 'HIGH'},
                {'pattern': r'if\s+.*password\s*==', 'type': 'plaintext_password', 'severity': 'HIGH'},
            ],
            'information_disclosure': [
                {'pattern': r'print\s*\([^)]*(password|secret|key|token)', 'type': 'info_disclosure', 'severity': 'MEDIUM'},
                {'pattern': r'logger\.(debug|info)\s*\([^)]*(password|secret)', 'type': 'info_disclosure', 'severity': 'MEDIUM'},
                {'pattern': r'traceback\.print_exc\s*\(', 'type': 'stack_trace', 'severity': 'LOW'},
            ],
            'weak_ssl': [
                {'pattern': r'verify\s*=\s*False', 'type': 'ssl_verification_disabled', 'severity': 'HIGH'},
                {'pattern': r'ssl\._create_unverified_context', 'type': 'ssl_verification_disabled', 'severity': 'HIGH'},
            ],
            'weak_permissions': [
                {'pattern': r'os\.chmod\s*\([^)]*0o777', 'type': 'weak_permissions', 'severity': 'MEDIUM'},
                {'pattern': r'chmod\s+777', 'type': 'weak_permissions', 'severity': 'MEDIUM'},
            ],
            'insecure_random': [
                {'pattern': r'random\.(randint|choice|random|uniform)', 'type': 'insecure_random', 'severity': 'MEDIUM'},
                {'pattern': r'\.randint\s*\(', 'type': 'insecure_random', 'severity': 'MEDIUM'},
            ],
            'unsafe_eval': [
                {'pattern': r'eval\s*\(', 'type': 'unsafe_eval', 'severity': 'CRITICAL'},
                {'pattern': r'exec\s*\(', 'type': 'unsafe_eval', 'severity': 'CRITICAL'},
                {'pattern': r'__import__\s*\(', 'type': 'unsafe_eval', 'severity': 'HIGH'},
            ],
            'hardcoded_credentials': [
                {'pattern': r'password\s*=\s*["\'][^"\']{3,}["\']', 'type': 'hardcoded_password', 'severity': 'CRITICAL'},
                {'pattern': r'pwd\s*=\s*["\'][^"\']{3,}["\']', 'type': 'hardcoded_password', 'severity': 'CRITICAL'},
                {'pattern': r'api[_-]?key\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_api_key', 'severity': 'CRITICAL'},
                {'pattern': r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_secret', 'severity': 'CRITICAL'},
                {'pattern': r'token\s*=\s*["\'][^"\']+["\']', 'type': 'hardcoded_token', 'severity': 'CRITICAL'},
                {'pattern': r'aws[_-]?access[_-]?key\s*=\s*["\']', 'type': 'hardcoded_aws_key', 'severity': 'CRITICAL'},
            ],
            'sql_patterns': [
                {'pattern': r'\.execute\s*\([^)]*\+', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'\.execute\s*\([^)]*%', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'\.execute\s*\([^)]*\.format\s*\(', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'cursor\.execute\s*\([^)]*f["\']', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'query\s*\([^)]*\+', 'type': 'sql_injection', 'severity': 'HIGH'},
                {'pattern': r'SELECT\s+.*\+.*FROM', 'type': 'sql_injection', 'severity': 'HIGH'},
            ],
            'xss_patterns': [
                {'pattern': r'\.innerHTML\s*=\s*', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'\.outerHTML\s*=\s*', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'document\.write\s*\(', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'\.html\s*\([^)]*request\.', 'type': 'xss', 'severity': 'HIGH'},
                {'pattern': r'response\.write\s*\([^)]*request\.', 'type': 'xss', 'severity': 'HIGH'},
            ],
            'command_injection_patterns': [
                {'pattern': r'os\.system\s*\(', 'type': 'command_injection', 'severity': 'CRITICAL'},
                {'pattern': r'os\.popen\s*\(', 'type': 'command_injection', 'severity': 'CRITICAL'},
                {'pattern': r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'type': 'command_injection', 'severity': 'HIGH'},
                {'pattern': r'commands\.getoutput\s*\(', 'type': 'command_injection', 'severity': 'HIGH'},
            ],
            'path_traversal_patterns': [
                {'pattern': r'open\s*\([^)]*\.\./', 'type': 'path_traversal', 'severity': 'HIGH'},
                {'pattern': r'file\s*\([^)]*\.\./', 'type': 'path_traversal', 'severity': 'HIGH'},
                {'pattern': r'os\.path\.join\s*\([^)]*request\.', 'type': 'path_traversal', 'severity': 'MEDIUM'},
                {'pattern': r'\.\./\.\./', 'type': 'path_traversal', 'severity': 'MEDIUM'},
            ],
            'crypto_weak_patterns': [
                {'pattern': r'hashlib\.md5\s*\(', 'type': 'weak_hash', 'severity': 'MEDIUM'},
                {'pattern': r'hashlib\.sha1\s*\(', 'type': 'weak_hash', 'severity': 'MEDIUM'},
                {'pattern': r'md5\s*\(', 'type': 'weak_hash', 'severity': 'MEDIUM'},
                {'pattern': r'sha1\s*\(', 'type': 'weak_hash', 'severity': 'MEDIUM'},
                {'pattern': r'DES\s', 'type': 'weak_encryption', 'severity': 'HIGH'},
                {'pattern': r'RC4\s', 'type': 'weak_encryption', 'severity': 'HIGH'},
            ],
            'misconfig_patterns': [
                {'pattern': r'DEBUG\s*=\s*True', 'type': 'debug_mode', 'severity': 'MEDIUM'},
                {'pattern': r'SECRET_KEY\s*=\s*["\'][^"\']{0,20}["\']', 'type': 'weak_secret_key', 'severity': 'CRITICAL'},
                {'pattern': r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']', 'type': 'wildcard_hosts', 'severity': 'HIGH'},
                {'pattern': r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True', 'type': 'cors_wildcard', 'severity': 'MEDIUM'},
            ],
        }
    
    def _load_code_quality_patterns(self) -> Dict[str, List[Dict]]:
        """Load code quality and best practice patterns."""
        return {
            'code_smells': [
                {'pattern': r'except\s+:\s*pass', 'type': 'bare_except', 'severity': 'LOW'},
                {'pattern': r'except\s+Exception\s*:\s*pass', 'type': 'silent_exception', 'severity': 'MEDIUM'},
                {'pattern': r'print\s*\([^)]*(password|secret)', 'type': 'info_leak', 'severity': 'MEDIUM'},
                {'pattern': r'assert\s+', 'type': 'assert_usage', 'severity': 'LOW'},
                {'pattern': r'\.strip\s*\(\s*\)\s*==\s*["\']', 'type': 'string_comparison', 'severity': 'LOW'},
            ],
            'performance': [
                {'pattern': r'\.append\s*\([^)]*\)\s*\n\s*for\s+', 'type': 'inefficient_loop', 'severity': 'LOW', 'multiline': True},
                {'pattern': r'for\s+.*in\s+range\s*\(len\s*\(', 'type': 'inefficient_iteration', 'severity': 'LOW'},
            ],
            'best_practices': [
                {'pattern': r'import\s+\*', 'type': 'wildcard_import', 'severity': 'LOW'},
                {'pattern': r'global\s+', 'type': 'global_usage', 'severity': 'LOW'},
                {'pattern': r'\.readlines\s*\(\)', 'type': 'memory_inefficient', 'severity': 'LOW'},
            ],
        }
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Comprehensive scan of a file for ALL vulnerability types.
        
        Args:
            file_path: Path to file
        
        Returns:
            List of all findings
        """
        findings = []
        
        try:
            file_loader = FileLoader(str(file_path.parent))
            content = file_loader.get_file_content(file_path)
            
            if not content:
                return findings
            
            lines = content.split('\n')
            
            # Scan for all vulnerability patterns
            for category, patterns in self.vulnerability_patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info['pattern']
                    vuln_type = pattern_info['type']
                    severity = pattern_info.get('severity', 'MEDIUM')
                    multiline = pattern_info.get('multiline', False)
                    
                    if multiline:
                        # Multiline pattern matching
                        findings.extend(self._scan_multiline_pattern(
                            pattern, content, file_path, vuln_type, severity
                        ))
                    else:
                        # Single line pattern matching
                        findings.extend(self._scan_line_pattern(
                            pattern, lines, file_path, vuln_type, severity
                        ))
            
            # Scan for code quality patterns (lower severity but still important)
            for category, patterns in self.code_quality_patterns.items():
                for pattern_info in patterns:
                    pattern = pattern_info['pattern']
                    vuln_type = pattern_info['type']
                    severity = pattern_info.get('severity', 'LOW')
                    multiline = pattern_info.get('multiline', False)
                    
                    if multiline:
                        findings.extend(self._scan_multiline_pattern(
                            pattern, content, file_path, vuln_type, severity
                        ))
                    else:
                        findings.extend(self._scan_line_pattern(
                            pattern, lines, file_path, vuln_type, severity
                        ))
            
            # AST-based analysis for Python files
            if file_path.suffix == '.py':
                ast_findings = self._scan_ast_patterns(content, file_path)
                findings.extend(ast_findings)
            
            # Add severity scores and remediation to all findings
            for finding in findings:
                severity_score = self.severity_scorer.calculate_severity_score(finding)
                finding['severity_score'] = severity_score
                finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                
                try:
                    remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                    finding['remediation'] = remediation
                except:
                    pass
            
        except Exception as e:
            pass
        
        return findings
    
    def _scan_line_pattern(self, pattern: str, lines: List[str], file_path: Path,
                          vuln_type: str, severity: str) -> List[Dict]:
        """Scan lines for pattern matches."""
        findings = []
        
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            
            for line_num, line in enumerate(lines, 1):
                matches = compiled.finditer(line)
                for match in matches:
                    # Skip comments
                    if line.strip().startswith('#'):
                        continue
                    
                    # Skip obvious false positives
                    if self._is_false_positive(line):
                        continue
                    
                    finding = {
                        'rule_id': f'{vuln_type}-{line_num}-{hash(match.group(0)) % 10000}',
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'match': match.group(0),
                        'file_path': str(file_path),
                        'severity': severity,
                        'owasp_category': self._map_to_owasp(vuln_type),
                        'description': self._get_description(vuln_type, line),
                        'recommendation': self._get_recommendation(vuln_type),
                        'confidence': 'medium',
                        'exploitability': 'medium'
                    }
                    
                    findings.append(finding)
        except:
            pass
        
        return findings
    
    def _scan_multiline_pattern(self, pattern: str, content: str, file_path: Path,
                               vuln_type: str, severity: str) -> List[Dict]:
        """Scan multiline patterns."""
        findings = []
        
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            matches = compiled.finditer(content)
            
            for match in matches:
                # Get line number
                line_num = content[:match.start()].count('\n') + 1
                lines = content.split('\n')
                line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                
                rule_id = f'{vuln_type}-{line_num}-{abs(hash(match.group(0) + str(file_path)) % 100000)}'
                
                finding = {
                    'rule_id': rule_id,
                    'line_number': line_num,
                    'line_content': line_content.strip(),
                    'match': match.group(0)[:100],
                    'file_path': str(file_path),
                    'severity': severity,
                    'owasp_category': self._map_to_owasp(vuln_type),
                    'description': self._get_description(vuln_type, line_content),
                    'recommendation': self._get_recommendation(vuln_type),
                    'confidence': 'medium',
                    'exploitability': 'medium'
                }
                
                findings.append(finding)
        except:
            pass
        
        return findings
    
    def _scan_ast_patterns(self, content: str, file_path: Path) -> List[Dict]:
        """Scan using AST for deeper analysis."""
        findings = []
        
        try:
            tree = ast.parse(content, filename=str(file_path))
            
            # Visitor for comprehensive AST analysis
            class ComprehensiveVisitor(ast.NodeVisitor):
                def __init__(self, file_path, content):
                    self.file_path = file_path
                    self.content = content
                    self.findings = []
                
                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        
                        dangerous_funcs = {
                            'eval': ('code_injection', 'CRITICAL'),
                            'exec': ('code_injection', 'CRITICAL'),
                            'compile': ('code_injection', 'HIGH'),
                            '__import__': ('code_injection', 'HIGH'),
                        }
                        
                        if func_name in dangerous_funcs:
                            vuln_type, severity = dangerous_funcs[func_name]
                            line_num = node.lineno
                            lines = self.content.split('\n')
                            line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                            
                            self.findings.append({
                                'rule_id': f'{vuln_type}-AST-{line_num}',
                                'line_number': line_num,
                                'line_content': line_content.strip(),
                                'match': f'{func_name}() call',
                                'file_path': str(self.file_path),
                                'severity': severity,
                                'owasp_category': 'A03',
                                'description': f'Dangerous function {func_name}() detected',
                                'recommendation': f'Avoid using {func_name}(). Use safer alternatives.',
                                'confidence': 'high',
                                'exploitability': 'high'
                            })
                    
                    self.generic_visit(node)
            
            visitor = ComprehensiveVisitor(file_path, content)
            visitor.visit(tree)
            findings.extend(visitor.findings)
        except:
            pass
        
        return findings
    
    def _is_false_positive(self, line: str) -> bool:
        """Check if line is likely false positive."""
        line_lower = line.lower()
        
        # Skip comments
        if line.strip().startswith('#'):
            return True
        
        # Skip obvious examples
        if any(word in line_lower for word in ['example', 'todo', 'fixme', 'xxx', 'placeholder']):
            if '#' in line or '//' in line:
                return True
        
        return False
    
    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP category."""
        mapping = {
            'sql_injection': 'A03',
            'code_injection': 'A03',
            'command_injection': 'A03',
            'xss': 'A03',
            'weak_crypto': 'A02',
            'hardcoded_secret': 'A02',
            'missing_auth': 'A01',
            'weak_auth': 'A07',
            'debug_enabled': 'A05',
            'weak_secret': 'A05',
            'wildcard_hosts': 'A05',
            'cors_wildcard': 'A05',
            'ssrf': 'A10',
            'path_traversal': 'A01',
            'unsafe_deserialization': 'A08',
            'silent_exception': 'A09',
            'no_error_logging': 'A09',
            'race_condition': 'A04',
            'weak_random': 'A02',
            'plaintext_password': 'A07',
            'info_disclosure': 'A05',
            'stack_trace': 'A05',
            'ssl_verification_disabled': 'A02',
            'weak_permissions': 'A05',
        }
        return mapping.get(vuln_type, 'A05')
    
    def _get_description(self, vuln_type: str, line: str) -> str:
        """Get description for vulnerability type."""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability: User input concatenated into SQL query',
            'code_injection': 'Code Injection: Dangerous code execution function detected',
            'command_injection': 'Command Injection: User input in system command execution',
            'xss': 'Cross-Site Scripting (XSS): User input in DOM manipulation',
            'weak_crypto': 'Weak cryptographic algorithm detected',
            'hardcoded_secret': 'Hardcoded secret/credential detected',
            'missing_auth': 'Missing authentication/authorization check',
            'ssrf': 'Server-Side Request Forgery (SSRF) vulnerability',
            'path_traversal': 'Path Traversal vulnerability',
            'unsafe_deserialization': 'Unsafe deserialization detected',
            'silent_exception': 'Exception silently caught without logging',
            'race_condition': 'Potential race condition detected',
            'weak_random': 'Weak random number generator used',
            'plaintext_password': 'Plaintext password comparison detected',
            'info_disclosure': 'Potential information disclosure',
            'ssl_verification_disabled': 'SSL certificate verification disabled',
            'weak_permissions': 'Weak file permissions set',
        }
        return descriptions.get(vuln_type, f'{vuln_type} vulnerability detected')
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type."""
        recommendations = {
            'sql_injection': 'Use parameterized queries/prepared statements',
            'code_injection': 'Avoid eval() and exec(). Use safer alternatives',
            'command_injection': 'Use subprocess with argument lists, not shell=True',
            'xss': 'Escape user input before output. Use textContent instead of innerHTML',
            'weak_crypto': 'Use strong cryptographic algorithms (AES-256, SHA-256)',
            'hardcoded_secret': 'Move secrets to environment variables or secure vaults',
            'missing_auth': 'Add authentication and authorization checks',
            'ssrf': 'Validate URLs and block internal IP ranges',
            'path_traversal': 'Validate and sanitize file paths',
            'unsafe_deserialization': 'Use safe deserialization methods',
            'silent_exception': 'Add proper error logging',
            'race_condition': 'Use atomic operations or file locking',
            'weak_random': 'Use secrets module for cryptographic randomness',
            'plaintext_password': 'Use secure password hashing (bcrypt, argon2)',
            'info_disclosure': 'Remove sensitive information from logs/output',
            'ssl_verification_disabled': 'Enable SSL certificate verification',
            'weak_permissions': 'Use restrictive file permissions (0o600, 0o644)',
        }
        return recommendations.get(vuln_type, 'Review and fix the vulnerability')

