"""
OWASP A03: Injection Scanner (Comprehensive)
"""
import re
import ast
from pathlib import Path
from typing import List, Dict

class InjectionScanner:
    """
    Comprehensive injection detection (OWASP A03:2021)
    
    Types:
    - SQL Injection
    - Command Injection
    - NoSQL Injection
    - LDAP Injection
    - XML Injection (XXE)
    - Template Injection (SSTI)
    - Code Injection
    """
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """Scan for all injection types"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except:
            return []
        
        findings.extend(self._check_sql_injection(content, file_path))
        findings.extend(self._check_command_injection(content, file_path))
        findings.extend(self._check_nosql_injection(content, file_path))
        findings.extend(self._check_ldap_injection(content, file_path))
        findings.extend(self._check_xxe(content, file_path))
        findings.extend(self._check_ssti(content, file_path))
        findings.extend(self._check_code_injection(content, file_path))
        
        return findings
    
    def _check_sql_injection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for SQL injection"""
        findings = []
        
        # Pattern: SQL queries with string concatenation
        sql_patterns = [
            r'execute\s*\([^)]*\+',
            r'executemany\s*\([^)]*\+',
            r'query\s*=\s*["\'].*\+.*request\.',
            r'cursor\.execute\([^)]*\+',
            r'db\.execute\([^)]*\+',
            r'\.query\([^)]*\+',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in sql_patterns:
                if re.search(pattern, line):
                    # Check if parameterized
                    is_parameterized = any(param in line for param in ['?', '%s', '%(', ':', 'execute('])
                    
                    if not is_parameterized or '+' in line:
                        findings.append({
                            'rule_id': f'A03-SQL-{i}-{hash(line) % 10000}',
                            'type': 'sql_injection',
                            'severity': 'CRITICAL',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A03',
                            'owasp_category_full': 'A03:2021 - Injection',
                            'description': 'Potential SQL injection - string concatenation in SQL query',
                            'confidence': 0.9,
                            'recommendation': 'Use parameterized queries (prepared statements)',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_command_injection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for command injection"""
        findings = []
        
        # Pattern: Command execution with user input
        cmd_patterns = [
            r'os\.system\([^)]*\+',
            r'subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
            r'os\.popen\([^)]*\+',
            r'popen\s*\([^)]*\+',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in cmd_patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A03-CMD-{i}-{hash(line) % 10000}',
                        'type': 'command_injection',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A03',
                        'owasp_category_full': 'A03:2021 - Injection',
                        'description': 'Potential command injection - user input in command execution',
                        'confidence': 0.9,
                        'recommendation': 'Use subprocess with list arguments and shell=False, or use shlex.quote()',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_nosql_injection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for NoSQL injection (MongoDB)"""
        findings = []
        
        # Pattern: User input in MongoDB queries
        patterns = [
            r'db\.\w+\.find\({[^}]*request\.',
            r'\.find\(\$where:\s*["\'].*request\.',
            r'collection\.find_one\({[^}]*request\.',
            r'\.find\([^)]*\+',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A03-NOSQL-{i}-{hash(line) % 10000}',
                        'type': 'nosql_injection',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A03',
                        'owasp_category_full': 'A03:2021 - Injection',
                        'description': 'Potential NoSQL injection',
                        'confidence': 0.8,
                        'recommendation': 'Validate and sanitize user input before using in NoSQL queries',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_ldap_injection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for LDAP injection"""
        findings = []
        
        patterns = [
            r'ldap\.search\([^)]*request\.',
            r'LDAPSearchFilter.*request\.',
            r'ldap\.bind\([^)]*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A03-LDAP-{i}-{hash(line) % 10000}',
                        'type': 'ldap_injection',
                        'severity': 'HIGH',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A03',
                        'owasp_category_full': 'A03:2021 - Injection',
                        'description': 'Potential LDAP injection',
                        'confidence': 0.8,
                        'recommendation': 'Escape LDAP special characters or use parameterized LDAP queries',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_xxe(self, content: str, file_path: Path) -> List[Dict]:
        """Check for XML External Entity (XXE) attacks"""
        findings = []
        
        # Pattern: XML parsing without disabling external entities
        patterns = [
            r'DocumentBuilderFactory\.newInstance\(\)',
            r'SAXParserFactory\.newInstance\(\)',
            r'XMLReader',
            r'etree\.parse\(',
            r'lxml\.etree\.parse\(',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    # Check if external entities are disabled
                    context = '\n'.join(lines[i:min(i+15, len(lines))])
                    
                    has_protection = any(safe in context for safe in [
                        'setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)',
                        'setFeature("http://xml.org/sax/features/external-general-entities", false)',
                        'defusedxml',
                        'XMLParser(resolve_entities=False)',
                    ])
                    
                    if not has_protection:
                        findings.append({
                            'rule_id': f'A03-XXE-{i}-{hash(line) % 10000}',
                            'type': 'xxe',
                            'severity': 'CRITICAL',
                            'line_number': i + 1,
                            'line_content': line.strip(),
                            'file_path': str(file_path),
                            'owasp_category': 'A03',
                            'owasp_category_full': 'A03:2021 - Injection',
                            'description': 'XML parser vulnerable to XXE attacks',
                            'confidence': 0.85,
                            'recommendation': 'Disable external entity processing or use defusedxml',
                            'scan_type': 'SAST'
                        })
        
        return findings
    
    def _check_ssti(self, content: str, file_path: Path) -> List[Dict]:
        """Check for Server-Side Template Injection"""
        findings = []
        
        # Pattern: render_template_string with user input
        patterns = [
            r'render_template_string\([^)]*request\.',
            r'Template\([^)]*request\.',
            r'jinja2\.Template\([^)]*request\.',
            r'\.render\([^)]*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A03-SSTI-{i}-{hash(line) % 10000}',
                        'type': 'ssti',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A03',
                        'owasp_category_full': 'A03:2021 - Injection',
                        'description': 'Server-Side Template Injection vulnerability',
                        'confidence': 0.9,
                        'recommendation': 'Use render_template() with separate template files instead of render_template_string()',
                        'scan_type': 'SAST'
                    })
        
        return findings
    
    def _check_code_injection(self, content: str, file_path: Path) -> List[Dict]:
        """Check for code injection (eval, exec, etc.)"""
        findings = []
        
        # Pattern: Dynamic code execution
        patterns = [
            r'eval\s*\([^)]*request\.',
            r'exec\s*\([^)]*request\.',
            r'compile\s*\([^)]*request\.',
            r'__import__\s*\([^)]*request\.',
        ]
        
        lines = content.split('\n')
        
        for i, line in enumerate(lines):
            for pattern in patterns:
                if re.search(pattern, line):
                    findings.append({
                        'rule_id': f'A03-CODE-{i}-{hash(line) % 10000}',
                        'type': 'code_injection',
                        'severity': 'CRITICAL',
                        'line_number': i + 1,
                        'line_content': line.strip(),
                        'file_path': str(file_path),
                        'owasp_category': 'A03',
                        'owasp_category_full': 'A03:2021 - Injection',
                        'description': 'Code injection - user input in dynamic code execution',
                        'confidence': 0.95,
                        'recommendation': 'Never execute user input as code. Use safe alternatives.',
                        'scan_type': 'SAST'
                    })
        
        return findings

