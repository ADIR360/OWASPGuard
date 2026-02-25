"""
OWASP A04: Insecure Design Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class InsecureDesignScanner:
    """
    Detect insecure design patterns (OWASP A04:2021)
    
    Patterns:
    - Missing security controls
    - Insecure default configurations
    - Missing input validation
    - Insecure error handling
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for insecure design issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_missing_validation(content, file_path))
        findings.extend(self._check_insecure_defaults(content, file_path))
        findings.extend(self._check_missing_security_headers(content, file_path))
        findings.extend(self._check_insecure_error_handling(content, file_path))
        
        return findings
    
    def _check_missing_validation(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing input validation"""
        findings = []
        
        # Pattern: User input used without validation
        patterns = [
            r'request\.(GET|POST|args|form)\[[^]]+\]',
            r'request\.(json|data)',
            r'input\s*\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if validated nearby
                    context = '\n'.join(lines[max(0, i-5):min(i+5, len(lines))])
                    has_validation = any(val in context for val in [
                        'validate', 'sanitize', 'check', 'verify', 'is_valid'
                    ])
                    
                    if not has_validation:
                        findings.append({
                            'rule_id': f'A04-VALID-{i}-{hash(line) % 10000}',
                            'type': 'missing_validation',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A04',
                            'owasp_category_full': 'A04:2021 - Insecure Design',
                            'description': 'User input used without validation',
                            'confidence': 0.7,
                            'recommendation': 'Add input validation before using user data',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_insecure_defaults(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure default configurations"""
        findings = []
        
        # Pattern: Insecure defaults
        insecure_defaults = [
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*True',
            r'SECRET_KEY\s*=\s*["\']dev["\']',
            r'ALLOWED_HOSTS\s*=\s*\[\s*["\']\*["\']',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_defaults:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A04-DEFAULT-{i}-{hash(line) % 10000}',
                        'type': 'insecure_default',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A04',
                        'owasp_category_full': 'A04:2021 - Insecure Design',
                        'description': 'Insecure default configuration detected',
                        'confidence': 0.9,
                        'recommendation': 'Use secure defaults for production',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_missing_security_headers(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing security headers"""
        findings = []
        
        # Pattern: Missing security headers in response
        if 'Response(' in content or 'HttpResponse(' in content:
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'Response(' in line or 'HttpResponse(' in line:
                    # Check for security headers
                    context = '\n'.join(lines[i:min(i+10, len(lines))])
                    has_security_headers = any(header in context for header in [
                        'X-Content-Type-Options',
                        'X-Frame-Options',
                        'Content-Security-Policy',
                        'Strict-Transport-Security'
                    ])
                    
                    if not has_security_headers:
                        findings.append({
                            'rule_id': f'A04-HEADER-{i}-{hash(line) % 10000}',
                            'type': 'missing_security_headers',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A04',
                            'owasp_category_full': 'A04:2021 - Insecure Design',
                            'description': 'Missing security headers in HTTP response',
                            'confidence': 0.7,
                            'recommendation': 'Add security headers (CSP, X-Frame-Options, etc.)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_insecure_error_handling(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure error handling"""
        findings = []
        
        # Pattern: Exposing sensitive information in errors
        patterns = [
            r'raise\s+\w+Error\([^)]*request\.',
            r'print\s*\([^)]*traceback',
            r'return\s+.*error.*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A04-ERROR-{i}-{hash(line) % 10000}',
                        'type': 'insecure_error_handling',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A04',
                        'owasp_category_full': 'A04:2021 - Insecure Design',
                        'description': 'Potential information disclosure in error handling',
                        'confidence': 0.7,
                        'recommendation': 'Avoid exposing sensitive information in error messages',
                        'scan_type': 'SAST'
                    })
        
        return findings

