"""
OWASP A02: Cryptographic Failures Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class CryptoScanner:
    """
    Detect cryptographic failures (OWASP A02:2021)
    
    Patterns:
    - Weak hash algorithms (MD5, SHA1)
    - Weak encryption (DES, ECB mode)
    - Hardcoded secrets
    - Insecure random number generation
    """
    
    WEAK_HASHES = ['MD5', 'SHA1', 'md5', 'sha1', 'md4', 'sha0']
    WEAK_CIPHERS = ['DES', 'RC4', '3DES', 'Blowfish', 'RC2']
    INSECURE_MODES = ['ECB']
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for cryptographic issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_weak_hashes(content, file_path))
        findings.extend(self._check_weak_encryption(content, file_path))
        findings.extend(self._check_insecure_random(content, file_path))
        findings.extend(self._check_hardcoded_secrets(content, file_path))
        findings.extend(self._check_weak_ssl_tls(content, file_path))
        
        return findings
    
    def _check_weak_hashes(self, content: str, file_path: Path) -> List[Dict]:
        """Check for weak hash algorithms"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for weak_hash in self.WEAK_HASHES:
                # Check for usage (not just in comments)
                if weak_hash in line and not line.strip().startswith('#'):
                    # Exclude false positives
                    if ('hashlib.' + weak_hash.lower() in line or 
                        weak_hash + '(' in line or
                        'hashlib.new("' + weak_hash.lower() in line.lower()):
                        findings.append({
                            'rule_id': f'A02-HASH-{i}-{hash(line) % 10000}',
                            'type': 'weak_hash_algorithm',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A02',
                            'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                            'description': f'Weak hash algorithm: {weak_hash}',
                            'algorithm': weak_hash,
                            'confidence': 0.95,
                            'recommendation': 'Use SHA-256, SHA-3, or bcrypt for password hashing',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_weak_encryption(self, content: str, file_path: Path) -> List[Dict]:
        """Check for weak encryption"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            # Check for weak ciphers
            for cipher in self.WEAK_CIPHERS:
                if cipher in line and not line.strip().startswith('#'):
                    findings.append({
                        'rule_id': f'A02-CIPHER-{i}-{hash(line) % 10000}',
                        'type': 'weak_encryption',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A02',
                        'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                        'description': f'Weak encryption algorithm: {cipher}',
                        'algorithm': cipher,
                        'confidence': 0.95,
                        'recommendation': 'Use AES-256-GCM or ChaCha20-Poly1305',
                        'scan_type': 'SAST'
                    })
            
            # Check for ECB mode
            for mode in self.INSECURE_MODES:
                if mode in line and ('MODE_' + mode in line or 'mode=' + mode.lower() in line.lower()):
                    findings.append({
                        'rule_id': f'A02-MODE-{i}-{hash(line) % 10000}',
                        'type': 'insecure_encryption_mode',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A02',
                        'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                        'description': f'Insecure encryption mode: {mode}',
                        'mode': mode,
                        'confidence': 0.95,
                        'recommendation': 'Use CBC or GCM mode with proper IV',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_insecure_random(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure random number generation"""
        findings = []
        
        # Pattern: Using random module for security purposes
        insecure_patterns = [
            r'random\.random\(',
            r'random\.randint\(',
            r'Math\.random\(',
            r'random\.choice\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_patterns:
                if re.search(pattern, line):
                    # Check context for security usage
                    context_lines = '\n'.join(lines[max(0, i-3):min(i+3, len(lines))])
                    
                    security_keywords = ['token', 'password', 'secret', 'key', 'salt', 'nonce', 'session']
                    
                    if any(keyword in context_lines.lower() for keyword in security_keywords):
                        findings.append({
                            'rule_id': f'A02-RAND-{i}-{hash(line) % 10000}',
                            'type': 'insecure_random',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A02',
                            'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                            'description': 'Insecure random number generator for security purpose',
                            'confidence': 0.8,
                            'recommendation': 'Use secrets module (Python) or crypto.randomBytes (Node.js)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_hardcoded_secrets(self, content: str, file_path: Path) -> List[Dict]:
        """Check for hardcoded cryptographic secrets"""
        findings = []
        
        # Pattern: Hardcoded keys, passwords, secrets
        secret_patterns = [
            r'(?:password|secret|key|token)\s*=\s*["\']([^"\']{8,})["\']',
            r'PRIVATE_KEY\s*=\s*["\']',
            r'API_KEY\s*=\s*["\']',
            r'SECRET_KEY\s*=\s*["\']',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Skip if it's a comment or example
                    if line.strip().startswith('#') or 'example' in line.lower() or 'placeholder' in line.lower():
                        continue
                    
                    findings.append({
                        'rule_id': f'A02-SECRET-{i}-{hash(line) % 10000}',
                        'type': 'hardcoded_secret',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip()[:100],  # Truncate for security
                        'file_path': str(file_path),
                        'owasp_category': 'A02',
                        'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                        'description': 'Hardcoded cryptographic secret detected',
                        'confidence': 0.9,
                        'recommendation': 'Store secrets in environment variables or secure vault',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_weak_ssl_tls(self, content: str, file_path: Path) -> List[Dict]:
        """Check for weak SSL/TLS configurations"""
        findings = []
        
        # Pattern: Disabled SSL verification
        weak_ssl_patterns = [
            r'verify\s*=\s*False',
            r'VERIFY_SSL\s*=\s*False',
            r'ssl\._create_unverified_context',
            r'rejectUnauthorized\s*:\s*false',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in weak_ssl_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'rule_id': f'A02-SSL-{i}-{hash(line) % 10000}',
                        'type': 'weak_ssl_tls',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A02',
                        'owasp_category_full': 'A02:2021 - Cryptographic Failures',
                        'description': 'SSL/TLS verification disabled',
                        'confidence': 0.9,
                        'recommendation': 'Enable SSL certificate verification',
                        'scan_type': 'SAST'
                    })
        
        return findings

