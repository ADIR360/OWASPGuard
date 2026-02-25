"""
JavaScript SAST scanner.
Detects XSS, injection, and other vulnerabilities in JS/TS code.
"""
from pathlib import Path
from typing import List, Dict
from core.rule_engine import RuleEngine
from core.file_loader import FileLoader
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher


class JavaScriptScanner:
    """Scans JavaScript/TypeScript code for security vulnerabilities."""
    
    def __init__(self, rule_engine: RuleEngine):
        """
        Initialize JavaScript scanner.
        
        Args:
            rule_engine: Rule engine instance
        """
        self.rule_engine = rule_engine
        self.rules = rule_engine.get_rules_for_language('javascript')
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a JavaScript file for vulnerabilities.
        
        Args:
            file_path: Path to JavaScript file
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Read file content
            file_loader = FileLoader(str(file_path.parent))
            content = file_loader.get_file_content(file_path)
            
            if not content:
                return findings
            
            # Apply regex-based rules
            for rule in self.rules:
                if rule.pattern_type == "regex":
                    rule_findings = self.rule_engine.match_rule(rule, content, file_path)
                    # Add severity scoring to all findings
                    for finding in rule_findings:
                        severity_score = self.severity_scorer.calculate_severity_score(finding)
                        finding['severity_score'] = severity_score
                        finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                        # Add remediation
                        try:
                            remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                            finding['remediation'] = remediation
                        except:
                            pass
                    findings.extend(rule_findings)
            
            # Additional pattern-based checks
            js_findings = self._check_javascript_patterns(content, file_path)
            # Add severity scoring
            for finding in js_findings:
                severity_score = self.severity_scorer.calculate_severity_score(finding)
                finding['severity_score'] = severity_score
                finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                try:
                    remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                    finding['remediation'] = remediation
                except:
                    pass
            findings.extend(js_findings)
            
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
        
        return findings
    
    def _check_javascript_patterns(self, content: str, file_path: Path) -> List[Dict]:
        """
        Check for JavaScript-specific vulnerability patterns.
        
        Args:
            content: File content
            file_path: Path to file
        
        Returns:
            List of findings
        """
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check for eval() with user input
            if 'eval(' in line and any(var in line for var in ['req.', 'req.body', 'req.query', 'req.params']):
                findings.append({
                    'rule_id': 'A03-INJECTION-EVAL-001',
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'match': 'eval() with user input',
                    'file_path': str(file_path),
                    'severity': 'HIGH',
                    'owasp_category': 'A03',
                    'description': 'Code Injection: eval() used with user-controlled input',
                    'recommendation': 'Avoid eval(). Use JSON.parse() or other safe alternatives',
                    'confidence': 'high',
                    'exploitability': 'high'
                })
            
            # Check for innerHTML with user input
            if '.innerHTML' in line and any(var in line for var in ['req.', 'req.body', 'req.query']):
                findings.append({
                    'rule_id': 'A03-XSS-INNERHTML-001',
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'match': 'innerHTML with user input',
                    'file_path': str(file_path),
                    'severity': 'HIGH',
                    'owasp_category': 'A03',
                    'description': 'XSS vulnerability: User input assigned to innerHTML',
                    'recommendation': 'Use textContent or sanitize input before assigning to innerHTML',
                    'confidence': 'high',
                    'exploitability': 'high'
                })
        
        return findings

