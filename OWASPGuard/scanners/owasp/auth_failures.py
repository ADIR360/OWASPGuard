"""
OWASP A07: Identification and Authentication Failures Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class AuthenticationFailuresScanner:
    """
    Detect authentication failures (OWASP A07:2021)
    
    Patterns:
    - Weak passwords
    - Missing authentication
    - Insecure session management
    - Password in plaintext
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for authentication failures"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_weak_passwords(content, file_path))
        findings.extend(self._check_plaintext_passwords(content, file_path))
        findings.extend(self._check_insecure_sessions(content, file_path))
        findings.extend(self._check_missing_mfa(content, file_path))
        
        return findings
    
    def _check_weak_passwords(self, content: str, file_path: Path) -> List[Dict]:
        """Check for weak password policies"""
        findings = []
        
        # Pattern: Weak password validation
        weak_patterns = [
            r'len\(password\)\s*<\s*8',
            r'password\.length\s*<\s*8',
            r'min_length\s*=\s*[0-7]',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in weak_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A07-WEAK-{i}-{hash(line) % 10000}',
                        'type': 'weak_password_policy',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A07',
                        'owasp_category_full': 'A07:2021 - Identification and Authentication Failures',
                        'description': 'Weak password policy - minimum length less than 8',
                        'confidence': 0.8,
                        'recommendation': 'Enforce strong password policy (min 12 chars, complexity)',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_plaintext_passwords(self, content: str, file_path: Path) -> List[Dict]:
        """Check for plaintext password storage"""
        findings = []
        
        # Pattern: Password stored without hashing
        patterns = [
            r'password\s*=\s*request\.',
            r'user\.password\s*=\s*',
            r'\.save\(\)\s*#.*password',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if hashed
                    context = '\n'.join(lines[max(0, i-3):min(i+3, len(lines))])
                    has_hashing = any(hash_func in context for hash_func in [
                        'hash', 'bcrypt', 'pbkdf2', 'scrypt', 'argon2'
                    ])
                    
                    if not has_hashing:
                        findings.append({
                            'rule_id': f'A07-PLAIN-{i}-{hash(line) % 10000}',
                            'type': 'plaintext_password',
                            'severity': 'CRITICAL',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A07',
                            'owasp_category_full': 'A07:2021 - Identification and Authentication Failures',
                            'description': 'Password stored in plaintext or without proper hashing',
                            'confidence': 0.9,
                            'recommendation': 'Use bcrypt, Argon2, or PBKDF2 for password hashing',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_insecure_sessions(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure session management"""
        findings = []
        
        # Pattern: Insecure session configuration
        insecure_patterns = [
            r'SESSION_COOKIE_SECURE\s*=\s*False',
            r'SESSION_COOKIE_HTTPONLY\s*=\s*False',
            r'cookie\.secure\s*=\s*False',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A07-SESSION-{i}-{hash(line) % 10000}',
                        'type': 'insecure_session',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A07',
                        'owasp_category_full': 'A07:2021 - Identification and Authentication Failures',
                        'description': 'Insecure session cookie configuration',
                        'confidence': 0.9,
                        'recommendation': 'Enable Secure and HttpOnly flags for session cookies',
                        'scan_type': 'CONFIG'
                    })
        
        return findings
    
    def _check_missing_mfa(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing multi-factor authentication"""
        findings = []
        
        # Pattern: Login without MFA
        if 'login' in content.lower() or 'authenticate' in content.lower():
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'login' in line.lower() or 'authenticate' in line.lower():
                    context = '\n'.join(lines[max(0, i-10):min(i+10, len(lines))])
                    has_mfa = any(mfa in context for mfa in [
                        'mfa', '2fa', 'two_factor', 'totp', 'otp', 'sms_code'
                    ])
                    
                    # Only flag if it's a sensitive endpoint
                    if not has_mfa and any(keyword in context.lower() for keyword in ['admin', 'root', 'privileged']):
                        findings.append({
                            'rule_id': f'A07-MFA-{i}-{hash(line) % 10000}',
                            'type': 'missing_mfa',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A07',
                            'owasp_category_full': 'A07:2021 - Identification and Authentication Failures',
                            'description': 'Missing multi-factor authentication for sensitive accounts',
                            'confidence': 0.6,
                            'recommendation': 'Implement MFA for privileged accounts',
                            'scan_type': 'SAST'
                        })
        
        return findings

