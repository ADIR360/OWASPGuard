"""
Environment file scanner.
Detects security misconfigurations in .env and config files.
Maps to A05 (Security Misconfiguration).
"""
from pathlib import Path
from typing import List, Dict
from core.rule_engine import RuleEngine
from core.file_loader import FileLoader
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher


class EnvScanner:
    """Scans environment and configuration files for misconfigurations."""
    
    def __init__(self, rule_engine: RuleEngine):
        """
        Initialize environment scanner.
        
        Args:
            rule_engine: Rule engine instance
        """
        self.rule_engine = rule_engine
        self.rules = rule_engine.get_rules_for_owasp('A05')
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a configuration file for misconfigurations.
        
        Args:
            file_path: Path to config file
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            file_loader = FileLoader(str(file_path.parent))
            content = file_loader.get_file_content(file_path)
            
            if not content:
                return findings
            
            # Apply misconfiguration rules
            for rule in self.rules:
                rule_findings = self.rule_engine.match_rule(rule, content, file_path)
                # Add severity scoring
                for finding in rule_findings:
                    severity_score = self.severity_scorer.calculate_severity_score(finding)
                    finding['severity_score'] = severity_score
                    finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                    try:
                        remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                        finding['remediation'] = remediation
                    except:
                        pass
                findings.extend(rule_findings)
            
            # Additional checks
            additional_findings = self._check_common_misconfigs(content, file_path)
            # Add severity scoring
            for finding in additional_findings:
                severity_score = self.severity_scorer.calculate_severity_score(finding)
                finding['severity_score'] = severity_score
                finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                try:
                    remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                    finding['remediation'] = remediation
                except:
                    pass
            findings.extend(additional_findings)
            
        except Exception as e:
            pass
        
        return findings
    
    def _check_common_misconfigs(self, content: str, file_path: Path) -> List[Dict]:
        """
        Check for common misconfiguration patterns.
        
        Args:
            content: File content
            file_path: Path to file
        
        Returns:
            List of findings
        """
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Debug mode enabled
            if 'debug' in line_lower and ('true' in line_lower or '1' in line_lower or 'on' in line_lower):
                findings.append({
                    'rule_id': 'A05-CONFIG-DEBUG-001',
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'match': 'Debug mode enabled',
                    'file_path': str(file_path),
                    'severity': 'MEDIUM',
                    'owasp_category': 'A05',
                    'description': 'Debug mode is enabled, which may expose sensitive information',
                    'recommendation': 'Disable debug mode in production environments',
                    'confidence': 'high',
                    'exploitability': 'medium'
                })
            
            # Verbose error messages
            if 'verbose' in line_lower and ('true' in line_lower or '1' in line_lower):
                findings.append({
                    'rule_id': 'A05-CONFIG-VERBOSE-001',
                    'line_number': line_num,
                    'line_content': line.strip(),
                    'match': 'Verbose error messages enabled',
                    'file_path': str(file_path),
                    'severity': 'MEDIUM',
                    'owasp_category': 'A05',
                    'description': 'Verbose error messages may leak sensitive information',
                    'recommendation': 'Use generic error messages in production',
                    'confidence': 'medium',
                    'exploitability': 'medium'
                })
        
        return findings

