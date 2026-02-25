"""
Entropy-based secret detection.
Detects high-entropy strings that are likely to be secrets.
"""
import re
import math
from typing import List, Dict
from pathlib import Path


class EntropyScanner:
    """
    Detect secrets using entropy analysis
    
    High-entropy strings are likely to be:
    - API keys
    - Tokens
    - Passwords
    - Cryptographic keys
    """
    
    MIN_ENTROPY = 4.5  # Threshold for high entropy
    MIN_LENGTH = 16
    MAX_LENGTH = 200
    
    # Common variable names that might contain secrets
    SECRET_KEYWORDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
        'apikey', 'access_key', 'private_key', 'auth', 'credential',
        'aws_key', 'aws_secret', 'api_secret', 'client_secret'
    }
    
    def calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        H(X) = -Σ P(x) * log2(P(x))
        
        Returns:
            Entropy value (0 to 8 for random strings)
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def scan_string(self, value: str, var_name: str = '') -> Dict:
        """
        Check if string is likely a secret based on entropy
        
        Args:
            value: String value to check
            var_name: Variable name (for context)
        
        Returns:
            Finding dict if secret detected, None otherwise
        """
        # Skip if too short or too long
        if len(value) < self.MIN_LENGTH or len(value) > self.MAX_LENGTH:
            return None
        
        # Calculate entropy
        entropy = self.calculate_entropy(value)
        
        # Check if high entropy
        if entropy < self.MIN_ENTROPY:
            return None
        
        # Additional checks
        is_hex = bool(re.match(r'^[0-9a-fA-F]+$', value))
        is_base64 = bool(re.match(r'^[A-Za-z0-9+/]+=*$', value))
        has_secret_keyword = any(kw in var_name.lower() for kw in self.SECRET_KEYWORDS)
        
        # Calculate confidence
        confidence = min(0.95, entropy / 8.0)
        
        if has_secret_keyword:
            confidence = min(0.99, confidence + 0.2)
        
        # Determine secret type
        secret_type = 'unknown'
        if 'api' in var_name.lower() or 'key' in var_name.lower():
            secret_type = 'api_key'
        elif 'token' in var_name.lower():
            secret_type = 'token'
        elif 'password' in var_name.lower() or 'pwd' in var_name.lower():
            secret_type = 'password'
        elif 'secret' in var_name.lower():
            secret_type = 'secret'
        
        return {
            'type': 'high_entropy_secret',
            'severity': 'HIGH',
            'value': value[:20] + '...' if len(value) > 20 else value,
            'entropy': round(entropy, 2),
            'confidence': confidence,
            'is_hex': is_hex,
            'is_base64': is_base64,
            'context': var_name,
            'secret_type': secret_type
        }
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan file for high-entropy secrets"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Look for assignment patterns
                    matches = re.finditer(
                        r'(\w+)\s*[=:]\s*["\']([^"\']{16,})["\']',
                        line
                    )
                    
                    for match in matches:
                        var_name, value = match.groups()
                        
                        # Skip if it's clearly not a secret
                        if value.lower() in ['none', 'null', 'false', 'true', 'placeholder', 'example']:
                            continue
                        
                        result = self.scan_string(value, var_name)
                        
                        if result:
                            secret_type = result.get('secret_type', 'unknown')
                            result['file_path'] = str(file_path)
                            result['line_number'] = line_num
                            result['line_content'] = line.strip()
                            result['rule_id'] = f'ENTROPY-{secret_type}-{line_num}-{hash(value) % 10000}'
                            result['owasp_category'] = 'A02'
                            result['owasp_category_full'] = 'A02:2021 - Cryptographic Failures'
                            result['description'] = f'High-entropy secret detected: {var_name} (entropy: {result["entropy"]})'
                            result['recommendation'] = f'Move {var_name} to environment variables or secure secret management'
                            result['scan_type'] = 'ENTROPY'
                            findings.append(result)
        
        except Exception as e:
            pass
        
        return findings

