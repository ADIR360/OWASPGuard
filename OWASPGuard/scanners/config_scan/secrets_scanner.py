"""
Secrets scanner - detects hardcoded API keys, tokens, passwords.
Maps to A02 (Cryptographic Failures) and A08 (Data Integrity).
"""
import re
from pathlib import Path
from typing import List, Dict
from core.rule_engine import RuleEngine
from core.file_loader import FileLoader
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher


class SecretsScanner:
    """Scans for hardcoded secrets and credentials."""
    
    # Common secret patterns
    SECRET_PATTERNS = {
        'api_key': [
            r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
            r'apikey\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        'aws_key': [
            r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']([^"\']+)["\']',
            r'AKIA[0-9A-Z]{16}',
        ],
        'password': [
            r'password\s*[=:]\s*["\']([^"\']+)["\']',
            r'pwd\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        'token': [
            r'token\s*[=:]\s*["\']([^"\']+)["\']',
            r'secret[_-]?token\s*[=:]\s*["\']([^"\']+)["\']',
        ],
        'private_key': [
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        ]
    }
    
    def __init__(self, rule_engine: RuleEngine):
        """
        Initialize secrets scanner.
        
        Args:
            rule_engine: Rule engine instance
        """
        self.rule_engine = rule_engine
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a file for hardcoded secrets.
        
        Args:
            file_path: Path to file
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            file_loader = FileLoader(str(file_path.parent))
            content = file_loader.get_file_content(file_path)
            
            if not content:
                return findings
            
            lines = content.split('\n')
            
            for line_num, line in enumerate(lines, 1):
                # Skip binary files and very long lines
                if len(line) > 1000:
                    continue
                
                # Check each secret pattern
                for secret_type, patterns in self.SECRET_PATTERNS.items():
                    for pattern in patterns:
                        try:
                            matches = re.finditer(pattern, line, re.IGNORECASE)
                            for match in matches:
                                # Skip if it's a comment or example
                                if self._is_false_positive(line):
                                    continue
                                
                                # Extract the matched secret (if captured)
                                matched_text = match.group(0)
                                if len(match.groups()) > 0:
                                    secret_value = match.group(1)
                                    # Check if it's actually a secret (not empty, not placeholder)
                                    if secret_value and len(secret_value) > 3 and secret_value.lower() not in ['none', 'null', 'false', 'true', 'placeholder', 'example']:
                                        matched_text = f"{matched_text[:20]}..." if len(matched_text) > 20 else matched_text
                                    else:
                                        continue  # Skip placeholder values
                                
                                finding = {
                                    'rule_id': f'A02-SECRET-{secret_type.upper()}-{line_num}-{hash(matched_text) % 10000}',
                                    'line_number': line_num,
                                    'line_content': line.strip()[:200],  # Limit length
                                    'match': matched_text[:50],  # Truncate for safety
                                    'file_path': str(file_path),
                                    'severity': 'CRITICAL' if secret_type in ['aws_key', 'private_key'] else 'HIGH',
                                    'owasp_category': 'A02',
                                    'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                                    'description': f'Hardcoded {secret_type.replace("_", " ")} detected in source code',
                                    'recommendation': f'Move {secret_type.replace("_", " ")} to environment variables or secure secret management system',
                                    'confidence': 'high',
                                    'exploitability': 'high',
                                    'secret_type': secret_type,
                                    'scan_type': 'SECRETS'
                                }
                                
                                # Add severity score
                                severity_score = self.severity_scorer.calculate_severity_score(finding)
                                finding['severity_score'] = severity_score
                                finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                                
                                # Add remediation
                                try:
                                    remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                                    finding['remediation'] = remediation
                                except:
                                    finding['remediation'] = f"Remove hardcoded {secret_type.replace('_', ' ')} and use environment variables"
                                
                                findings.append(finding)
                        except re.error:
                            continue  # Skip invalid regex patterns
            
        except Exception as e:
            pass
        
        return findings
    
    def _is_false_positive(self, line: str) -> bool:
        """
        Check if a match is likely a false positive.
        
        Args:
            line: Line content
        
        Returns:
            True if likely false positive
        """
        line_lower = line.lower().strip()
        
        # Common false positive patterns
        false_positives = [
            'example',
            'placeholder',
            'your_',
            'xxx',
            'todo',
            'fixme',
            '#',
            '//',
            '/*'
        ]
        
        return any(fp in line_lower for fp in false_positives)

