"""
Context-aware pattern matching with AST analysis.
Reduces false positives by understanding code context.
"""
import ast
from typing import List, Dict, Optional
from pathlib import Path


class ContextAwareScanner(ast.NodeVisitor):
    """
    AST-based scanner that understands code context
    
    Reduces false positives by analyzing:
    - Variable scope
    - Function context
    - Control flow
    - Defensive programming patterns
    """
    
    def __init__(self, source_code: str, filename: str):
        self.source_code = source_code
        self.filename = filename
        self.findings = []
        self.current_function = None
        self.in_try_block = False
        self.safe_functions = set()
    
    def analyze(self) -> List[Dict]:
        """Run context-aware analysis"""
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self.visit(tree)
            return self.findings
        except:
            return []
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function context"""
        prev_function = self.current_function
        self.current_function = node.name
        
        # Check for validation decorators
        has_validation = any(
            isinstance(dec, ast.Name) and dec.id in {'validate', 'sanitize', 'check', 'login_required'}
            for dec in node.decorator_list
        )
        
        if has_validation:
            self.safe_functions.add(node.name)
        
        self.generic_visit(node)
        self.current_function = prev_function
    
    def visit_Try(self, node: ast.Try):
        """Track try-except blocks"""
        prev_try = self.in_try_block
        self.in_try_block = True
        
        # Visit try body
        for child in node.body:
            self.visit(child)
        
        self.in_try_block = prev_try
        
        # Visit handlers and other parts
        for handler in node.handlers:
            self.visit(handler)
        for child in node.orelse:
            self.visit(child)
        for child in node.finalbody:
            self.visit(child)
    
    def visit_Call(self, node: ast.Call):
        """Analyze function calls with rich context (eval/exec, SQLi, command exec, deserialization, TLS, etc.)"""
        func_name = self._get_function_name(node.func)
        
        # ---- Dangerous eval/exec style usage ----
        if func_name in {'eval', 'exec', 'compile'}:
            if node.args and isinstance(node.args[0], ast.Constant):
                confidence = 0.3  # constant expression is less risky
            elif self._has_validation(node):
                confidence = 0.5
            else:
                confidence = 0.95
            
            self.findings.append({
                'rule_id': f'CONTEXT-{func_name}-{node.lineno}',
                'line_number': node.lineno,
                'line_content': self._get_line_content(node.lineno),
                'code_snippet': self._get_code_snippet(node.lineno),
                'match': f'{func_name}() call',
                'file_path': self.filename,
                'severity': 'HIGH',
                'owasp_category': 'A03',
                'description': f'Use of {func_name}() with possibly dynamic input',
                'recommendation': f'Avoid using {func_name}() on untrusted data. Use safer, explicit logic instead.',
                'confidence': 'high' if confidence >= 0.8 else 'medium',
                'exploitability': 'high',
                'scan_type': 'CONTEXT',
                'type': 'code_injection',
                'function': func_name,
                'in_try_block': self.in_try_block
            })
        
        # ---- SQL Injection patterns ----
        elif func_name in {'execute', 'executemany', 'raw'}:
            if node.args:
                query_arg = node.args[0]
                
                is_parameterized = len(node.args) > 1 or any(
                    isinstance(kw.value, (ast.List, ast.Tuple, ast.Dict))
                    for kw in node.keywords
                    if kw.arg in {'params', 'parameters'}
                )
                
                if is_parameterized:
                    confidence = 0.1
                elif isinstance(query_arg, ast.Constant):
                    confidence = 0.1
                elif self._contains_string_format(query_arg):
                    confidence = 0.95
                else:
                    confidence = 0.6
                
                if confidence > 0.5:
                    self.findings.append({
                        'rule_id': f'CONTEXT-SQL-{node.lineno}',
                        'line_number': node.lineno,
                        'line_content': self._get_line_content(node.lineno),
                        'code_snippet': self._get_code_snippet(node.lineno),
                        'match': f'{func_name}() with potential SQL injection',
                        'file_path': self.filename,
                        'severity': 'HIGH',
                        'owasp_category': 'A03',
                        'description': 'Potential SQL injection: dynamic query construction without clear parameterization.',
                        'recommendation': 'Use parameterized queries / bound parameters instead of string concatenation or formatting.',
                        'confidence': 'high' if confidence >= 0.8 else 'medium',
                        'exploitability': 'high',
                        'scan_type': 'CONTEXT',
                        'type': 'sql_injection',
                        'parameterized': is_parameterized
                    })
        
        # ---- Command injection via OS/subprocess ----
        elif func_name in {
            'os.system',
            'subprocess.call',
            'subprocess.run',
            'subprocess.Popen',
        }:
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.arg == 'shell' and kw.value.value is True
                for kw in node.keywords
            )
            uses_format = any(self._contains_string_format(arg) for arg in node.args)
            dynamic_input = any(not isinstance(arg, ast.Constant) for arg in node.args)
            
            if shell_true or uses_format or dynamic_input:
                self.findings.append({
                    'rule_id': f'CONTEXT-CMD-{node.lineno}',
                    'line_number': node.lineno,
                    'line_content': self._get_line_content(node.lineno),
                    'code_snippet': self._get_code_snippet(node.lineno),
                    'match': f'{func_name}() with dynamic command',
                    'file_path': self.filename,
                    'severity': 'HIGH',
                    'owasp_category': 'A03',
                    'description': 'Potential command injection via OS/subprocess call with dynamic input or shell=True.',
                    'recommendation': 'Avoid shell=True, validate/whitelist arguments, and prefer passing argument lists instead of shell commands.',
                    'confidence': 'high' if shell_true or uses_format else 'medium',
                    'exploitability': 'high',
                    'scan_type': 'CONTEXT',
                    'type': 'command_injection',
                    'shell_true': shell_true
                })
        
        # ---- Unsafe deserialization (pickle / yaml.load) ----
        elif func_name in {'pickle.load', 'pickle.loads', 'yaml.load'}:
            unsafe_yaml = False
            if func_name == 'yaml.load':
                # Look for a safe Loader; if none, treat as unsafe
                has_safe_loader = any(
                    isinstance(arg, ast.Name) and 'SafeLoader' in arg.id
                    for arg in node.args
                ) or any(
                    isinstance(kw.value, ast.Name) and 'SafeLoader' in kw.value.id
                    for kw in node.keywords
                )
                unsafe_yaml = not has_safe_loader
            
            if func_name != 'yaml.load' or unsafe_yaml:
                self.findings.append({
                    'rule_id': f'CONTEXT-DESER-{node.lineno}',
                    'line_number': node.lineno,
                    'line_content': self._get_line_content(node.lineno),
                    'code_snippet': self._get_code_snippet(node.lineno),
                    'match': f'Unsafe deserialization via {func_name}()',
                    'file_path': self.filename,
                    'severity': 'HIGH',
                    'owasp_category': 'A08',
                    'description': f'Unsafe deserialization using {func_name}() can lead to arbitrary code execution.',
                    'recommendation': 'Avoid untrusted data with pickle / yaml.load; use safe formats (JSON) or safe loaders (yaml.safe_load).',
                    'confidence': 'high',
                    'exploitability': 'high',
                    'scan_type': 'CONTEXT',
                    'type': 'unsafe_deserialization'
                })
        
        # ---- Insecure TLS / certificate verification ----
        elif func_name.startswith('requests.'):
            verify_false = any(
                kw.arg == 'verify'
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )
            if verify_false:
                self.findings.append({
                    'rule_id': f'CONTEXT-TLS-{node.lineno}',
                    'line_number': node.lineno,
                    'line_content': self._get_line_content(node.lineno),
                    'code_snippet': self._get_code_snippet(node.lineno),
                    'match': f'{func_name}() with verify=False',
                    'file_path': self.filename,
                    'severity': 'MEDIUM',
                    'owasp_category': 'A02',
                    'description': 'TLS certificate verification is explicitly disabled (verify=False).',
                    'recommendation': 'Remove verify=False and use proper certificates; only disable verification in tightly controlled testing.',
                    'confidence': 'high',
                    'exploitability': 'medium',
                    'scan_type': 'CONTEXT',
                    'type': 'tls_verification_disabled'
                })
        
        self.generic_visit(node)
    
    def _get_function_name(self, node) -> str:
        """Extract function name"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parts = []
            current = node
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return ''
    
    def _contains_string_format(self, node) -> bool:
        """Check if node contains string formatting"""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        elif isinstance(node, ast.JoinedStr):  # f-strings
            return True
        elif isinstance(node, ast.Call):
            func_name = self._get_function_name(node.func)
            if 'format' in func_name:
                return True
        return False
    
    def _has_validation(self, node: ast.Call) -> bool:
        """Check if call is preceded by validation"""
        # Check if arguments have validation calls
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_function_name(arg.func)
                if any(v in func_name.lower() for v in ['validate', 'sanitize', 'escape', 'clean']):
                    return True
        return False
    
    def _get_line_content(self, line_num: int) -> str:
        """Get line content from source code"""
        lines = self.source_code.split('\n')
        if 1 <= line_num <= len(lines):
            return lines[line_num - 1].strip()
        return ''

    def _get_code_snippet(self, line_num: int, context: int = 2) -> str:
        """Get a small code snippet around the given line for better UI context."""
        lines = self.source_code.split('\n')
        if not (1 <= line_num <= len(lines)):
            return ''
        start = max(1, line_num - context)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end + 1):
            prefix = '>> ' if i == line_num else '   '
            snippet_lines.append(f"{prefix}{lines[i - 1].rstrip()}")
        return '\n'.join(snippet_lines)


def run_context_analysis(file_path: Path) -> List[Dict]:
    """Run context-aware analysis on a Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        scanner = ContextAwareScanner(source_code, str(file_path))
        findings = scanner.analyze()
        
        return findings
    
    except Exception as e:
        return []

