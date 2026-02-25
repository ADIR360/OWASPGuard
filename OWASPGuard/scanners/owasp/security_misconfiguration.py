"""
OWASP A05: Security Misconfiguration Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class SecurityMisconfigurationScanner:
    """
    Detect security misconfigurations (OWASP A05:2021)
    
    Patterns:
    - Exposed sensitive files
    - Insecure CORS configuration
    - Missing security headers
    - Exposed debug information
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for security misconfigurations"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_exposed_files(content, file_path))
        findings.extend(self._check_insecure_cors(content, file_path))
        findings.extend(self._check_exposed_debug(content, file_path))
        findings.extend(self._check_missing_https(content, file_path))
        
        return findings
    
    def _check_exposed_files(self, content: str, file_path: Path) -> List[Dict]:
        """Check for exposed sensitive files"""
        findings = []
        
        # Pattern: Exposing .env, .git, etc.
        exposed_patterns = [
            r'\.env',
            r'\.git',
            r'\.pem',
            r'\.key',
            r'\.sql',
            r'\.db',
        ]
        
        # Check if file itself is sensitive
        if any(pattern.replace('\\', '') in str(file_path) for pattern in exposed_patterns):
            findings.append({
                'rule_id': f'A05-EXPOSED-{hash(str(file_path)) % 100000}',
                'type': 'exposed_sensitive_file',
                'severity': 'HIGH',
                'line_number': 1,
                'line_content': str(file_path),
                'file_path': str(file_path),
                'owasp_category': 'A05',
                'owasp_category_full': 'A05:2021 - Security Misconfiguration',
                'description': f'Sensitive file exposed: {file_path.name}',
                'confidence': 0.9,
                'recommendation': 'Add sensitive files to .gitignore and restrict access',
                'scan_type': 'CONFIG'
            })
        
        return findings
    
    def _check_insecure_cors(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure CORS configuration"""
        findings = []
        
        # Pattern: Insecure CORS
        insecure_cors = [
            r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True',
            r'Access-Control-Allow-Origin:\s*\*',
            r'cors\(origin=["\']\*["\']',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_cors:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A05-CORS-{i}-{hash(line) % 10000}',
                        'type': 'insecure_cors',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A05',
                        'owasp_category_full': 'A05:2021 - Security Misconfiguration',
                        'description': 'Insecure CORS configuration - allows all origins',
                        'confidence': 0.9,
                        'recommendation': 'Restrict CORS to specific trusted origins',
                        'scan_type': 'CONFIG'
                    })
        
        return findings
    
    def _check_exposed_debug(self, content: str, file_path: Path) -> List[Dict]:
        """Check for exposed debug information"""
        findings = []
        
        # Pattern: Debug mode enabled
        debug_patterns = [
            r'DEBUG\s*=\s*True',
            r'debug\s*=\s*True',
            r'development\s*=\s*True',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in debug_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A05-DEBUG-{i}-{hash(line) % 10000}',
                        'type': 'exposed_debug',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A05',
                        'owasp_category_full': 'A05:2021 - Security Misconfiguration',
                        'description': 'Debug mode enabled - may expose sensitive information',
                        'confidence': 0.8,
                        'recommendation': 'Disable debug mode in production',
                        'scan_type': 'CONFIG'
                    })
        
        return findings
    
    def _check_missing_https(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing HTTPS enforcement"""
        findings = []
        
        # Pattern: HTTP instead of HTTPS
        http_patterns = [
            r'http://[^"\']+',
            r'url\s*=\s*["\']http://',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in http_patterns:
                if re.search(pattern, line) and 'localhost' not in line and '127.0.0.1' not in line:
                    findings.append({
                        'rule_id': f'A05-HTTPS-{i}-{hash(line) % 10000}',
                        'type': 'missing_https',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A05',
                        'owasp_category_full': 'A05:2021 - Security Misconfiguration',
                        'description': 'HTTP used instead of HTTPS',
                        'confidence': 0.7,
                        'recommendation': 'Use HTTPS for all external connections',
                        'scan_type': 'CONFIG'
                    })
        
        return findings

