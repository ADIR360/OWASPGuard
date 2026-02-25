"""
OWASP A09: Security Logging and Monitoring Failures Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class LoggingFailuresScanner:
    """
    Detect logging and monitoring failures (OWASP A09:2021)
    
    Patterns:
    - Missing security logging
    - Insufficient logging
    - Logging sensitive data
    - Missing alerting
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for logging failures"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_missing_security_logging(content, file_path))
        findings.extend(self._check_logging_sensitive_data(content, file_path))
        findings.extend(self._check_insufficient_logging(content, file_path))
        
        return findings
    
    def _check_missing_security_logging(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing security event logging"""
        findings = []
        
        # Pattern: Security events without logging
        security_events = [
            r'login\s*\(',
            r'authenticate\s*\(',
            r'delete\s*\(',
            r'update\s*\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in security_events:
                if re.search(pattern, line, re.IGNORECASE):
                    context = '\n'.join(lines[max(0, i-5):min(i+10, len(lines))])
                    has_logging = any(log in context for log in [
                        'log', 'logger', 'logging', 'audit'
                    ])
                    
                    if not has_logging:
                        findings.append({
                            'rule_id': f'A09-LOG-{i}-{hash(line) % 10000}',
                            'type': 'missing_security_logging',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A09',
                            'owasp_category_full': 'A09:2021 - Security Logging and Monitoring Failures',
                            'description': 'Security event without logging',
                            'confidence': 0.7,
                            'recommendation': 'Log all security-relevant events (login, auth failures, etc.)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_logging_sensitive_data(self, content: str, file_path: Path) -> List[Dict]:
        """Check for logging sensitive data"""
        findings = []
        
        # Pattern: Logging passwords, tokens, etc.
        sensitive_patterns = [
            r'log\s*\([^)]*password',
            r'logger\.\w+\([^)]*password',
            r'print\s*\([^)]*token',
            r'log\s*\([^)]*secret',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in sensitive_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A09-SENSITIVE-{i}-{hash(line) % 10000}',
                        'type': 'logging_sensitive_data',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip()[:100],  # Truncate
                        'file_path': str(file_path),
                        'owasp_category': 'A09',
                        'owasp_category_full': 'A09:2021 - Security Logging and Monitoring Failures',
                        'description': 'Sensitive data being logged',
                        'confidence': 0.9,
                        'recommendation': 'Never log passwords, tokens, or other sensitive data',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_insufficient_logging(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insufficient logging detail"""
        findings = []
        
        # Pattern: Generic error messages without context
        if 'except' in content or 'catch' in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'except' in line or 'catch' in line:
                    # Check if error is logged with context
                    context = '\n'.join(lines[i:min(i+5, len(lines))])
                    has_detailed_logging = any(detail in context for detail in [
                        'logger.error', 'log.exception', 'traceback', 'stack'
                    ])
                    
                    if not has_detailed_logging:
                        findings.append({
                            'rule_id': f'A09-INSUFFICIENT-{i}-{hash(line) % 10000}',
                            'type': 'insufficient_logging',
                            'severity': 'LOW',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A09',
                            'owasp_category_full': 'A09:2021 - Security Logging and Monitoring Failures',
                            'description': 'Insufficient error logging - missing context',
                            'confidence': 0.6,
                            'recommendation': 'Log errors with full context (stack trace, user, timestamp)',
                            'scan_type': 'SAST'
                        })
        
        return findings

