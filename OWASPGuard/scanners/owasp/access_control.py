"""
OWASP A01: Broken Access Control Scanner
"""
import ast
import re
from pathlib import Path
from typing import List, Dict

class AccessControlScanner:
    """
    Detect broken access control (OWASP A01:2021)
    
    Patterns:
    - Missing authentication checks
    - Insecure direct object references (IDOR)
    - Missing authorization
    - Path traversal
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for access control issues"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        # Pattern 1: Routes without authentication
        findings.extend(self._check_unprotected_routes(content, file_path))
        
        # Pattern 2: Direct object access without authorization
        findings.extend(self._check_idor(content, file_path))
        
        # Pattern 3: Path traversal
        findings.extend(self._check_path_traversal(content, file_path))
        
        # Pattern 4: Missing CSRF protection
        findings.extend(self._check_csrf_protection(content, file_path))
        
        # Pattern 5: Insecure file permissions
        findings.extend(self._check_file_permissions(content, file_path))
        
        return findings
    
    def _check_unprotected_routes(self, content: str, file_path: Path) -> List[Dict]:
        """Check for routes without authentication"""
        findings = []
        
        # Flask/Django route patterns
        route_patterns = [
            r'@app\.route\(["\']([^"\']+)["\']\)',
            r'@route\(["\']([^"\']+)["\']\)',
            r'path\(["\']([^"\']+)["\']\s*,\s*views\.\w+\)',
            r'@.*\.route\(["\']([^"\']+)["\']\)',
        ]
        
        auth_decorators = [
            '@login_required',
            '@authenticate',
            '@permission_required',
            '@require_auth',
            '@jwt_required',
            '@token_required'
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in route_patterns:
                match = re.search(pattern, line)
                if match:
                    route = match.group(1)
                    
                    # Check previous lines for auth decorators
                    has_auth = False
                    for j in range(max(0, i-5), i):
                        if any(dec in lines[j] for dec in auth_decorators):
                            has_auth = True
                            break
                    
                    # Admin/sensitive routes without auth
                    sensitive_keywords = ['admin', 'delete', 'edit', 'manage', 'update', 'create', 'remove', 'destroy']
                    if not has_auth and any(keyword in route.lower() for keyword in sensitive_keywords):
                        findings.append({
                            'rule_id': f'A01-ROUTE-{i}-{hash(route) % 10000}',
                            'type': 'missing_authentication',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A01',
                            'owasp_category_full': 'A01:2021 - Broken Access Control',
                            'description': f'Sensitive route {route} without authentication',
                            'route': route,
                            'confidence': 0.85,
                            'recommendation': 'Add authentication decorator (@login_required, @authenticate, etc.)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_idor(self, content: str, file_path: Path) -> List[Dict]:
        """Check for Insecure Direct Object References"""
        findings = []
        
        # Pattern: Getting object by ID from request without checking ownership
        idor_patterns = [
            r'get_object_or_404\(\w+,\s*id=request\.(GET|POST)\[',
            r'Model\.objects\.get\(id=request\.(GET|POST|args|form)\[',
            r'Session\.query\(\w+\)\.filter\(\w+\.id\s*==\s*request\.(args|form)\[',
            r'\.get\(id=request\.',
            r'\.filter\(id=request\.',
            r'\.filter_by\(id=request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in idor_patterns:
                if re.search(pattern, line):
                    # Check if there's ownership verification nearby
                    has_ownership_check = False
                    
                    # Look ahead for ownership checks
                    for j in range(i, min(i+15, len(lines))):
                        if any(keyword in lines[j] for keyword in [
                            '.user ==', '.owner ==', '.created_by ==',
                            'if obj.user', 'check_permission', 'has_permission',
                            'verify_ownership', 'check_access'
                        ]):
                            has_ownership_check = True
                            break
                    
                    if not has_ownership_check:
                        findings.append({
                            'rule_id': f'A01-IDOR-{i}-{hash(line) % 10000}',
                            'type': 'idor',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A01',
                            'owasp_category_full': 'A01:2021 - Broken Access Control',
                            'description': 'Potential IDOR - object accessed by ID without ownership check',
                            'confidence': 0.75,
                            'recommendation': 'Verify user ownership or permissions before accessing objects',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_path_traversal(self, content: str, file_path: Path) -> List[Dict]:
        """Check for path traversal vulnerabilities"""
        findings = []
        
        # Pattern: File operations with user input
        patterns = [
            r'open\([^)]*request\.(args|form|GET|POST)\[',
            r'os\.path\.join\([^)]*request\.',
            r'Path\([^)]*request\.',
            r'file\([^)]*request\.',
            r'read\([^)]*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check for safety measures
                    has_safety = any(safe in line for safe in [
                        'os.path.abspath',
                        'os.path.normpath',
                        'secure_filename',
                        'safe_join',
                        'os.path.basename'
                    ])
                    
                    if not has_safety:
                        findings.append({
                            'rule_id': f'A01-PATH-{i}-{hash(line) % 10000}',
                            'type': 'path_traversal',
                            'severity': 'HIGH',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A01',
                            'owasp_category_full': 'A01:2021 - Broken Access Control',
                            'description': 'Path traversal - user input in file path without sanitization',
                            'confidence': 0.8,
                            'recommendation': 'Use os.path.basename() or secure_filename() to sanitize paths',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_csrf_protection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for missing CSRF protection"""
        findings = []
        
        # Check for POST/PUT/DELETE routes without CSRF
        post_patterns = [
            r'@app\.route\(["\'][^"\']+["\'],\s*methods=\[["\']POST["\']',
            r'@app\.route\(["\'][^"\']+["\'],\s*methods=\[["\']PUT["\']',
            r'@app\.route\(["\'][^"\']+["\'],\s*methods=\[["\']DELETE["\']',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in post_patterns:
                if re.search(pattern, line):
                    # Check for CSRF protection
                    has_csrf = False
                    for j in range(max(0, i-3), min(i+10, len(lines))):
                        if any(csrf in lines[j] for csrf in ['csrf', 'CSRF', 'csrf_token', '@csrf_protect']):
                            has_csrf = True
                            break
                    
                    if not has_csrf:
                        findings.append({
                            'rule_id': f'A01-CSRF-{i}-{hash(line) % 10000}',
                            'type': 'missing_csrf',
                            'severity': 'MEDIUM',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A01',
                            'owasp_category_full': 'A01:2021 - Broken Access Control',
                            'description': 'POST/PUT/DELETE route without CSRF protection',
                            'confidence': 0.7,
                            'recommendation': 'Add CSRF protection using @csrf_protect or csrf_token',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_file_permissions(self, content: str, file_path: Path) -> List[Dict]:
        """Check for insecure file permissions"""
        findings = []
        
        # Pattern: chmod with world-writable permissions
        insecure_chmod = [
            r'chmod\s*\([^,]+,\s*0o777',
            r'chmod\s*\([^,]+,\s*0o666',
            r'os\.chmod\([^,]+,\s*0o777',
            r'os\.chmod\([^,]+,\s*0o666',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in insecure_chmod:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A01-PERM-{i}-{hash(line) % 10000}',
                        'type': 'insecure_file_permissions',
                        'severity': 'MEDIUM',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A01',
                        'owasp_category_full': 'A01:2021 - Broken Access Control',
                        'description': 'Insecure file permissions - world-writable files',
                        'confidence': 0.8,
                        'recommendation': 'Use restrictive file permissions (0o600 or 0o644)',
                        'scan_type': 'SAST'
                    })
        
        return findings

