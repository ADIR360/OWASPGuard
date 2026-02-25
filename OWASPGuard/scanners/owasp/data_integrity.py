"""
OWASP A08: Software and Data Integrity Failures Scanner
"""
import re
from pathlib import Path
from typing import List, Dict

class DataIntegrityScanner:
    """
    Detect data integrity failures (OWASP A08:2021)
    
    Patterns:
    - Unsigned code/updates
    - Insecure deserialization
    - Missing integrity checks
    - Insecure CI/CD
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for data integrity failures"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_insecure_deserialization(content, file_path))
        findings.extend(self._check_missing_integrity_checks(content, file_path))
        findings.extend(self._check_insecure_downloads(content, file_path))
        
        return findings
    
    def _check_insecure_deserialization(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure deserialization"""
        findings = []
        
        # Pattern: Insecure deserialization
        insecure_patterns = [
            r'pickle\.loads\(',
            r'yaml\.load\(',
            r'json\.loads\([^)]*request\.',
            r'unmarshal\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_patterns:
                if re.search(pattern, line):
                    # Check if safe alternative used
                    is_safe = 'safe_load' in line or 'safe_loads' in line
                    
                    if not is_safe:
                        findings.append({
                            'rule_id': f'A08-DESER-{i}-{hash(line) % 10000}',
                            'type': 'insecure_deserialization',
                            'severity': 'CRITICAL',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A08',
                            'owasp_category_full': 'A08:2021 - Software and Data Integrity Failures',
                            'description': 'Insecure deserialization - may allow code execution',
                            'confidence': 0.9,
                            'recommendation': 'Use safe deserialization methods (yaml.safe_load, json.loads with validation)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_missing_integrity_checks(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing integrity checks"""
        findings = []
        
        # Pattern: File downloads without integrity verification
        download_patterns = [
            r'requests\.get\([^)]*\.download',
            r'urllib\.urlretrieve\(',
            r'wget\s+',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in download_patterns:
                if re.search(pattern, line):
                    context = '\n'.join(lines[i:min(i+10, len(lines))])
                    has_integrity = any(check in context for check in [
                        'hash', 'checksum', 'signature', 'verify', 'sha256'
                    ])
                    
                    if not has_integrity:
                        findings.append({
                            'rule_id': f'A08-INTEGRITY-{i}-{hash(line) % 10000}',
                            'type': 'missing_integrity_check',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A08',
                            'owasp_category_full': 'A08:2021 - Software and Data Integrity Failures',
                            'description': 'File download without integrity verification',
                            'confidence': 0.8,
                            'recommendation': 'Verify file integrity using checksums or signatures',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_insecure_downloads(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure file downloads"""
        findings = []
        
        # Pattern: Downloading from untrusted sources
        patterns = [
            r'requests\.get\([^)]*http://',
            r'wget\s+http://',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line) and 'localhost' not in line:
                    findings.append({
                        'rule_id': f'A08-DOWNLOAD-{i}-{hash(line) % 10000}',
                        'type': 'insecure_download',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A08',
                        'owasp_category_full': 'A08:2021 - Software and Data Integrity Failures',
                        'description': 'Downloading from HTTP (insecure) source',
                        'confidence': 0.7,
                        'recommendation': 'Use HTTPS and verify source authenticity',
                        'scan_type': 'SAST'
                    })
        
        return findings

