"""
OWASP A10: Server-Side Request Forgery (SSRF) Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class SSRFScanner:
    """
    Detect SSRF vulnerabilities (OWASP A10:2021)
    
    Patterns:
    - User-controlled URLs
    - Internal network access
    - Missing URL validation
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for SSRF vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_ssrf_requests(content, file_path))
        findings.extend(self._check_internal_network_access(content, file_path))
        findings.extend(self._check_missing_url_validation(content, file_path))
        
        return findings
    
    def _check_ssrf_requests(self, content: str, file_path: Path) -> List[Dict]:
        """Check for SSRF in HTTP requests"""
        findings = []
        
        # Pattern: User input in HTTP requests
        ssrf_patterns = [
            r'requests\.(get|post|put|delete)\([^)]*request\.',
            r'urllib\.(request|urlopen)\([^)]*request\.',
            r'httplib\.(HTTP|HTTPS)\([^)]*request\.',
            r'fetch\s*\([^)]*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in ssrf_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A10-SSRF-{i}-{hash(line) % 10000}',
                        'type': 'ssrf',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A10',
                        'owasp_category_full': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                        'description': 'Potential SSRF - user input in HTTP request',
                        'confidence': 0.85,
                        'recommendation': 'Validate and whitelist allowed URLs, block internal network access',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_internal_network_access(self, content: str, file_path: Path) -> List[Dict]:
        """Check for internal network access"""
        findings = []
        
        # Pattern: Accessing internal IPs
        internal_patterns = [
            r'127\.0\.0\.1',
            r'localhost',
            r'192\.168\.',
            r'10\.',
            r'172\.(1[6-9]|2[0-9]|3[0-1])\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in internal_patterns:
                if re.search(pattern, line) and any(req in line for req in ['requests', 'urllib', 'http']):
                    findings.append({
                        'rule_id': f'A10-INTERNAL-{i}-{hash(line) % 10000}',
                        'type': 'internal_network_access',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A10',
                        'owasp_category_full': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                        'description': 'Potential internal network access - SSRF risk',
                        'confidence': 0.8,
                        'recommendation': 'Block access to internal/private IP addresses',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_missing_url_validation(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing URL validation"""
        findings = []
        
        # Pattern: URL from user input without validation
        url_patterns = [
            r'url\s*=\s*request\.',
            r'url\s*=\s*input\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in url_patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[i:min(i+10, len(lines))])
                    has_validation = any(val in context for val in [
                        'validate', 'whitelist', 'allowed', 'check', 'verify'
                    ])
                    
                    if not has_validation:
                        findings.append({
                            'rule_id': f'A10-VALID-{i}-{hash(line) % 10000}',
                            'type': 'missing_url_validation',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A10',
                            'owasp_category_full': 'A10:2021 - Server-Side Request Forgery (SSRF)',
                            'description': 'URL from user input without validation',
                            'confidence': 0.7,
                            'recommendation': 'Validate and whitelist allowed URL patterns',
                            'scan_type': 'SAST'
                        })
        
        return findings

