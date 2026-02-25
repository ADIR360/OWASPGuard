"""
Context-aware code analyzer.
Understands code context to reduce false positives and provide accurate findings.
"""
import ast
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path


class CodeContext:
    """Represents code context for a finding."""
    def __init__(self):
        self.function_name: Optional[str] = None
        self.class_name: Optional[str] = None
        self.variable_sources: List[str] = []  # Where variables come from
        self.sanitization_checks: List[str] = []  # Sanitization functions called
        self.is_user_input: bool = False
        self.is_constant: bool = False
        self.is_parameterized: bool = False
        self.code_snippet: str = ""
        self.surrounding_lines: List[str] = []


class ContextAnalyzer:
    """Analyzes code context to understand vulnerability context."""
    
    # Common sanitization functions
    SANITIZATION_FUNCTIONS = {
        'escape', 'sanitize', 'clean', 'validate', 'escape_string',
        'html_escape', 'quote', 'parameterize', 'escape_sql'
    }
    
    # User input sources
    USER_INPUT_SOURCES = {
        'request', 'req', 'input', 'argv', 'get', 'post', 'query',
        'params', 'body', 'form', 'cookies', 'headers', 'args'
    }
    
    # Safe patterns (not vulnerabilities)
    SAFE_PATTERNS = {
        'cursor.execute': ['%s', '?', ':name'],  # Parameterized queries
        'prepared': True,
        'parameterized': True
    }
    
    def analyze_injection_context(self, node: ast.AST, source_code: str, 
                                  file_path: Path) -> CodeContext:
        """
        Analyze context for injection vulnerabilities.
        
        Args:
            node: AST node to analyze
            source_code: Full source code
            file_path: Path to file
        
        Returns:
            CodeContext object
        """
        context = CodeContext()
        lines = source_code.split('\n')
        
        # Get line number
        if hasattr(node, 'lineno'):
            line_num = node.lineno
            context.code_snippet = lines[line_num - 1] if line_num <= len(lines) else ""
            
            # Get surrounding context
            start = max(0, line_num - 5)
            end = min(len(lines), line_num + 5)
            context.surrounding_lines = lines[start:end]
        
        # Find function context
        for parent in ast.walk(ast.parse(source_code)):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if hasattr(node, 'lineno') and parent.lineno <= node.lineno <= parent.end_lineno:
                    context.function_name = parent.name
                    break
        
        # Analyze if it's user input
        context.is_user_input = self._is_user_input(node, source_code)
        
        # Check for sanitization
        context.sanitization_checks = self._check_sanitization(node, source_code)
        
        # Check if parameterized
        context.is_parameterized = self._is_parameterized(node, source_code)
        
        # Check if constant
        context.is_constant = self._is_constant(node)
        
        return context
    
    def _is_user_input(self, node: ast.AST, source_code: str) -> bool:
        """Check if node represents user input."""
        if isinstance(node, ast.Call):
            # Check function name
            if isinstance(node.func, ast.Attribute):
                attr_name = node.func.attr.lower()
                if any(source in attr_name for source in self.USER_INPUT_SOURCES):
                    return True
            elif isinstance(node.func, ast.Name):
                if node.func.id.lower() in self.USER_INPUT_SOURCES:
                    return True
        
        # Check for request attributes
        try:
            if hasattr(ast, 'unparse'):
                source_str = ast.unparse(node)
            else:
                # Fallback for Python < 3.9
                source_str = self._ast_to_string(node)
        except:
            source_str = str(node)
        source_lower = source_str.lower()
        
        for source in self.USER_INPUT_SOURCES:
            if f'.{source}' in source_lower or f'[{source}' in source_lower:
                return True
        
        return False
    
    def _check_sanitization(self, node: ast.AST, source_code: str) -> List[str]:
        """Check for sanitization functions."""
        sanitization_found = []
        
        # Walk up the AST to find sanitization calls
        try:
            if hasattr(ast, 'unparse'):
                source_str = ast.unparse(node)
            else:
                source_str = self._ast_to_string(node)
        except:
            source_str = str(node)
        source_lower = source_str.lower()
        
        for sanit_func in self.SANITIZATION_FUNCTIONS:
            if sanit_func in source_lower:
                sanitization_found.append(sanit_func)
        
        return sanitization_found
    
    def _is_parameterized(self, node: ast.AST, source_code: str) -> bool:
        """Check if query is parameterized."""
        if isinstance(node, ast.Call):
            # Check arguments
            for arg in node.args:
                arg_str = ast.unparse(arg) if hasattr(ast, 'unparse') else str(arg)
                
                # Check for parameterized query patterns
                if any(pattern in arg_str for pattern in ['%s', '?', ':name', '?1', '?2']):
                    # Check if second argument is a list/tuple (parameters)
                    if len(node.args) > 1:
                        return True
        
        # Check for prepared statements
        try:
            if hasattr(ast, 'unparse'):
                source_str = ast.unparse(node)
            else:
                source_str = self._ast_to_string(node)
        except:
            source_str = str(node)
        if 'prepared' in source_str.lower() or 'parameterized' in source_str.lower():
            return True
        
        return False
    
    def _is_constant(self, node: ast.AST) -> bool:
        """Check if node is a constant value."""
        return isinstance(node, (ast.Constant, ast.Str, ast.Num))
    
    def is_false_positive(self, context: CodeContext, vulnerability_type: str) -> bool:
        """
        Determine if a finding is likely a false positive.
        
        Args:
            context: Code context
            vulnerability_type: Type of vulnerability
        
        Returns:
            True if likely false positive
        """
        # SQL Injection false positives
        if vulnerability_type == 'sql_injection':
            # Parameterized queries are safe
            if context.is_parameterized:
                return True
            
            # If sanitized, likely safe
            if context.sanitization_checks:
                return True
            
            # Constants are safe
            if context.is_constant:
                return True
        
        # XSS false positives
        if vulnerability_type == 'xss':
            # If sanitized
            if context.sanitization_checks:
                return True
            
            # If using safe methods like textContent
            if 'textcontent' in context.code_snippet.lower():
                return True
        
        return False
    
    def trace_data_flow(self, source_node: ast.AST, sink_node: ast.AST, 
                       source_code: str) -> bool:
        """
        Trace data flow from source to sink.
        
        Args:
            source_node: Source of user input
            sink_node: Sink (vulnerable function)
            source_code: Source code
        
        Returns:
            True if data flows from source to sink without sanitization
        """
        # Simplified data flow analysis
        # In production, use more sophisticated taint analysis
        
        source_str = ast.unparse(source_node) if hasattr(ast, 'unparse') else str(source_node)
        sink_str = ast.unparse(sink_node) if hasattr(ast, 'unparse') else str(sink_node)
        
        # Check if source variable is used in sink
        try:
            if hasattr(ast, 'unparse'):
                source_str = ast.unparse(source_node)
                sink_str = ast.unparse(sink_node)
            else:
                source_str = self._ast_to_string(source_node)
                sink_str = self._ast_to_string(sink_node)
        except:
            source_str = str(source_node)
            sink_str = str(sink_node)
        
        if isinstance(source_node, ast.Name):
            var_name = source_node.id
            if var_name in sink_str:
                # Check for sanitization between source and sink
                source_line = source_node.lineno if hasattr(source_node, 'lineno') else 0
                sink_line = sink_node.lineno if hasattr(sink_node, 'lineno') else 0
                
                # Get code between source and sink
                lines = source_code.split('\n')
                if source_line < sink_line:
                    between_code = '\n'.join(lines[source_line:sink_line])
                    
                    # Check for sanitization
                    for sanit_func in self.SANITIZATION_FUNCTIONS:
                        if sanit_func in between_code.lower() and var_name in between_code:
                            return False  # Sanitized, not vulnerable
                    
                    return True  # No sanitization found
        
        return False

