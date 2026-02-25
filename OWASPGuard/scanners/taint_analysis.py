"""
Taint analysis for vulnerability detection.
Tracks data flow from user input sources to dangerous sinks.
"""
import ast
from typing import Set, Dict, List, Tuple
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TaintedVariable:
    """Represents a tainted (user-controlled) variable"""
    name: str
    source: str  # 'request', 'input', 'file', etc.
    line: int
    sanitized: bool = False


class TaintAnalyzer(ast.NodeVisitor):
    """
    Lightweight taint analysis for Python code
    
    Tracks data flow from user input sources to dangerous sinks
    without requiring full symbolic execution.
    """
    
    # User input sources
    TAINT_SOURCES = {
        'request.GET', 'request.POST', 'request.COOKIES', 'request.FILES',
        'request.args', 'request.form', 'request.json', 'request.data',
        'input', 'raw_input', 'sys.argv', 'os.environ',
        'file.read', 'open', 'urllib.request',
        'flask.request', 'django.request',
    }
    
    # Dangerous sinks
    SINKS = {
        'sql_injection': {'execute', 'executemany', 'raw', 'cursor.execute'},
        'command_injection': {'system', 'popen', 'subprocess.call', 'os.system', 'eval', 'exec'},
        'xss': {'render_template_string', 'send', 'jsonify', 'Response'},
        'path_traversal': {'open', 'file', 'os.path.join', 'pathlib.Path'},
        'ssrf': {'requests.get', 'requests.post', 'urllib.request.urlopen'},
    }
    
    # Sanitization functions
    SANITIZERS = {
        'sql_injection': {'escape', 'quote', 'parameterize', 'escape_string'},
        'command_injection': {'shlex.quote', 'pipes.quote'},
        'xss': {'escape', 'Markup', 'bleach.clean', 'html.escape'},
        'path_traversal': {'os.path.abspath', 'os.path.normpath', 'secure_filename'},
        'ssrf': {'urlparse', 'validate_url'},
    }
    
    def __init__(self, source_code: str, filename: str):
        self.source_code = source_code
        self.filename = filename
        self.tainted_vars: Dict[str, TaintedVariable] = {}
        self.findings: List[Dict] = []
        self.current_function = None
        self.assignments: Dict[str, Set[str]] = {}  # var -> sources
    
    def analyze(self) -> List[Dict]:
        """Run taint analysis and return findings"""
        try:
            tree = ast.parse(self.source_code, filename=self.filename)
            self.visit(tree)
            return self.findings
        except SyntaxError as e:
            return []
        except Exception as e:
            return []
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Track function context"""
        prev_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = prev_function
    
    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments from tainted sources"""
        # Check if right side is a taint source
        tainted = self._is_tainted_expr(node.value)
        
        if tainted:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted_vars[var_name] = TaintedVariable(
                        name=var_name,
                        source=tainted,
                        line=node.lineno
                    )
                    self.assignments[var_name] = {tainted}
        
        # Propagate taint through assignments
        elif isinstance(node.value, ast.Name):
            source_var = node.value.id
            if source_var in self.tainted_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_var = target.id
                        self.tainted_vars[target_var] = self.tainted_vars[source_var]
                        self.assignments[target_var] = self.assignments.get(source_var, set())
        
        # Taint propagation through operations
        elif isinstance(node.value, ast.BinOp):
            tainted_operands = []
            for operand in [node.value.left, node.value.right]:
                if isinstance(operand, ast.Name) and operand.id in self.tainted_vars:
                    tainted_operands.append(operand.id)
            
            if tainted_operands:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_var = target.id
                        if tainted_operands[0] in self.tainted_vars:
                            self.tainted_vars[target_var] = self.tainted_vars[tainted_operands[0]]
                            self.assignments[target_var] = set()
                            for op in tainted_operands:
                                self.assignments[target_var].update(self.assignments.get(op, set()))
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Check for tainted data flowing into dangerous sinks"""
        func_name = self._get_function_name(node.func)
        
        # Check if this is a dangerous sink
        vuln_type = None
        for vtype, sinks in self.SINKS.items():
            if any(sink in func_name for sink in sinks):
                vuln_type = vtype
                break
        
        if vuln_type:
            # Check if arguments are tainted
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    tainted_var = self.tainted_vars[arg.id]
                    
                    # Check if sanitized
                    if not self._is_sanitized(arg.id, vuln_type):
                        self.findings.append({
                            'rule_id': f'TAINT-{vuln_type}-{node.lineno}',
                            'line_number': node.lineno,
                            'line_content': self._get_line_content(node.lineno),
                            'match': f'{func_name}() with tainted input',
                            'file_path': self.filename,
                            'severity': 'HIGH',
                            'owasp_category': self._map_to_owasp(vuln_type),
                            'description': f'Tainted data from {tainted_var.source} flows into {func_name}',
                            'recommendation': f'Sanitize {arg.id} before using in {func_name}',
                            'confidence': 'high',
                            'exploitability': 'high',
                            'scan_type': 'TAINT',
                            'variable': arg.id,
                            'source_line': tainted_var.line,
                            'sink': func_name,
                            'data_flow': self._construct_data_flow(arg.id)
                        })
        
        # Check if this is a sanitization function
        sanitizer_type = None
        for vtype, sanitizers in self.SANITIZERS.items():
            if any(san in func_name for san in sanitizers):
                sanitizer_type = vtype
                break
        
        if sanitizer_type:
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                    self.tainted_vars[arg.id].sanitized = True
        
        self.generic_visit(node)
    
    def _is_tainted_expr(self, expr) -> str:
        """Check if expression is a taint source"""
        if isinstance(expr, ast.Attribute):
            full_name = self._get_full_attribute_name(expr)
            for source in self.TAINT_SOURCES:
                if source in full_name:
                    return source
        
        elif isinstance(expr, ast.Call):
            func_name = self._get_function_name(expr.func)
            for source in self.TAINT_SOURCES:
                if source in func_name:
                    return source
        
        return None
    
    def _get_function_name(self, node) -> str:
        """Extract function name from call node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_full_attribute_name(node)
        return ''
    
    def _get_full_attribute_name(self, node) -> str:
        """Get full dotted attribute name (e.g., 'request.GET.get')"""
        parts = []
        current = node
        
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        
        if isinstance(current, ast.Name):
            parts.append(current.id)
        
        return '.'.join(reversed(parts))
    
    def _is_sanitized(self, var_name: str, vuln_type: str) -> bool:
        """Check if variable has been sanitized"""
        if var_name in self.tainted_vars:
            return self.tainted_vars[var_name].sanitized
        return False
    
    def _construct_data_flow(self, var_name: str) -> str:
        """Construct human-readable data flow description"""
        if var_name not in self.tainted_vars:
            return ''
        
        tainted = self.tainted_vars[var_name]
        flow = f"Line {tainted.line}: {var_name} = {tainted.source}"
        
        return flow
    
    def _get_line_content(self, line_num: int) -> str:
        """Get line content from source code"""
        lines = self.source_code.split('\n')
        if 1 <= line_num <= len(lines):
            return lines[line_num - 1].strip()
        return ''
    
    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP category"""
        mapping = {
            'sql_injection': 'A03',
            'command_injection': 'A03',
            'xss': 'A03',
            'path_traversal': 'A01',
            'ssrf': 'A10',
        }
        return mapping.get(vuln_type, 'A03')


def run_taint_analysis(file_path: Path) -> List[Dict]:
    """Run taint analysis on a Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        analyzer = TaintAnalyzer(source_code, str(file_path))
        findings = analyzer.analyze()
        
        return findings
    
    except Exception as e:
        return []

