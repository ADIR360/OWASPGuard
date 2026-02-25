"""
Python SAST scanner with AST-based analysis and context awareness.
Detects injection vulnerabilities, crypto failures, and more.
Uses data flow analysis to reduce false positives.
"""
import ast
from pathlib import Path
from typing import List, Dict, Set, Optional
from core.rule_engine import RuleEngine
from core.file_loader import FileLoader
from core.context_analyzer import ContextAnalyzer
from core.ml_detector import MLVulnerabilityDetector
from core.severity_scorer import SeverityScorer
from core.remediation_fetcher import RemediationFetcher


class PythonScanner:
    """Scans Python code for security vulnerabilities."""
    
    def __init__(self, rule_engine: RuleEngine):
        """
        Initialize Python scanner.
        
        Args:
            rule_engine: Rule engine instance
        """
        self.rule_engine = rule_engine
        self.rules = rule_engine.get_rules_for_language('python')
        self.context_analyzer = ContextAnalyzer()
        self.ml_detector = MLVulnerabilityDetector()
        self.severity_scorer = SeverityScorer()
        self.remediation_fetcher = RemediationFetcher()
    
    def scan_file(self, file_path: Path) -> List[Dict]:
        """
        Scan a Python file for vulnerabilities.
        
        Args:
            file_path: Path to Python file
        
        Returns:
            List of findings
        """
        findings = []
        
        try:
            # Read file content
            file_loader = FileLoader(str(file_path.parent))
            content = file_loader.get_file_content(file_path)
            
            if not content:
                return findings
            
            # Phase 1: AST-based analysis (more accurate)
            try:
                tree = ast.parse(content, filename=str(file_path))
                ast_findings = self._analyze_ast(tree, file_path, content)
                
                # Filter false positives using context analysis + ML
                for finding in ast_findings:
                    context = self.context_analyzer.analyze_injection_context(
                        self._get_node_at_line(tree, finding['line_number']),
                        content,
                        file_path
                    )
                    
                    # Skip if false positive
                    if self.context_analyzer.is_false_positive(context, 'sql_injection'):
                        continue
                    
                    # ML-based validation for high accuracy
                    line_content = finding.get('line_content', '')
                    is_vuln, ml_confidence = self.ml_detector.detect_vulnerability(
                        line_content, 
                        {'function': context.function_name, 'file': str(file_path)},
                        'sql_injection'
                    )
                    
                    # ML validation - tuned for higher recall:
                    # keep almost all positives and only drop very low-confidence negatives
                    if is_vuln and ml_confidence >= 0.30:
                        finding['ml_confidence'] = ml_confidence
                        finding['confidence'] = 'high' if ml_confidence >= 0.9 else 'medium' if ml_confidence >= 0.8 else 'low'
                        
                        # Calculate numeric severity score (1-100)
                        severity_score = self.severity_scorer.calculate_severity_score(finding)
                        finding['severity_score'] = severity_score
                        finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                        
                        # Fetch online remediation (async to avoid blocking)
                        try:
                            remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                            finding['remediation'] = remediation
                            finding['recommendation'] = self.remediation_fetcher.fetch_remediation(finding).get('recommendation', finding.get('recommendation', ''))
                        except:
                            # Fallback to default recommendation if fetch fails
                            finding['recommendation'] = finding.get('recommendation', 'Review and fix the vulnerability')
                        
                        findings.append(finding)
                    elif not is_vuln and ml_confidence < 0.20:
                        # Very low confidence negative - likely false positive, skip
                        continue
                    else:
                        # Medium confidence - include but mark as lower confidence
                        finding['ml_confidence'] = ml_confidence
                        finding['confidence'] = 'medium'
                        severity_score = self.severity_scorer.calculate_severity_score(finding)
                        finding['severity_score'] = severity_score
                        finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                        findings.append(finding)
            
            except SyntaxError:
                # Skip files with syntax errors
                pass
            
            # Phase 2: Regex-based rule matching (for patterns not caught by AST)
            for rule in self.rules:
                if rule.pattern_type == "regex":
                    rule_findings = self.rule_engine.match_rule(rule, content, file_path)
                    # Process each finding with ML validation
                    for finding in rule_findings:
                        # Skip obvious false positives
                        if not self._is_likely_vulnerable(finding, content, file_path):
                            continue
                        
                        # Apply ML validation to regex findings too
                        line_content = finding.get('line_content', '')
                        vuln_type = self._determine_vuln_type(rule.id)
                        
                        if vuln_type:
                            is_vuln, ml_confidence = self.ml_detector.detect_vulnerability(
                                line_content,
                                {'file': str(file_path), 'rule_id': rule.id},
                                vuln_type
                            )
                            
                            # Include if ML confirms or if confidence is not extremely low
                            if is_vuln or ml_confidence >= 0.30:
                                finding['ml_confidence'] = ml_confidence
                                finding['confidence'] = 'high' if ml_confidence >= 0.9 else 'medium' if ml_confidence >= 0.8 else 'low'
                                
                                # Calculate severity
                                severity_score = self.severity_scorer.calculate_severity_score(finding)
                                finding['severity_score'] = severity_score
                                finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                                
                                # Add remediation
                                try:
                                    remediation = self.remediation_fetcher.get_comprehensive_remediation(finding)
                                    finding['remediation'] = remediation
                                except:
                                    pass
                                
                                findings.append(finding)
                        else:
                            # No ML validation available, include with basic scoring
                            severity_score = self.severity_scorer.calculate_severity_score(finding)
                            finding['severity_score'] = severity_score
                            finding['severity'] = self.severity_scorer.get_severity_level(severity_score)
                            findings.append(finding)
            
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
        
        return findings
    
    def _analyze_ast(self, tree: ast.AST, file_path: Path, content: str) -> List[Dict]:
        """
        Analyze AST for injection vulnerabilities.
        
        Args:
            tree: Parsed AST
            file_path: Path to file
            content: File content
        
        Returns:
            List of AST-based findings
        """
        findings = []
        
        # Visitor to find SQL injection patterns with data flow analysis
        class SQLInjectionVisitor(ast.NodeVisitor):
            def __init__(self, file_path, content, context_analyzer, tree):
                self.file_path = file_path
                self.content = content
                self.context_analyzer = context_analyzer
                self.findings = []
                self.user_input_vars: Set[str] = set()
                self._collect_user_inputs(tree)
            
            def _collect_user_inputs(self, tree: ast.AST):
                """Collect variables that come from user input."""
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                # Check if value comes from user input
                                if isinstance(node.value, ast.Call):
                                    if isinstance(node.value.func, ast.Attribute):
                                        attr_name = node.value.func.attr.lower()
                                        if any(source in attr_name for source in ['get', 'post', 'input', 'request']):
                                            self.user_input_vars.add(target.id)
            
            def visit_Call(self, node):
                # Check for cursor.execute() with string concatenation
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['execute', 'executemany']:
                        # Check if arguments contain string concatenation
                        for arg in node.args:
                            # Check for string concatenation
                            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                # Check if it involves user input
                                is_vulnerable = self._check_user_input_in_node(arg)
                                
                                if is_vulnerable:
                                    # Check if it's parameterized (second arg is list/tuple)
                                    is_parameterized = len(node.args) > 1 and isinstance(
                                        node.args[1], (ast.List, ast.Tuple, ast.Dict)
                                    )
                                    
                                    if not is_parameterized:
                                        line_num = node.lineno
                                        lines = self.content.split('\n')
                                        line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                                        
                                        self.findings.append({
                                            'rule_id': 'A03-SQLI-AST-001',
                                            'line_number': line_num,
                                            'line_content': line_content.strip(),
                                            'match': 'String concatenation in SQL execution with user input',
                                            'file_path': str(self.file_path),
                                            'severity': 'HIGH',
                                            'owasp_category': 'A03',
                                            'description': 'SQL Injection vulnerability: User input concatenated into SQL query without parameterization',
                                            'recommendation': 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
                                            'confidence': 'high',
                                            'exploitability': 'high'
                                        })
                            
                            # Check for format strings with user input
                            elif isinstance(arg, ast.JoinedStr) or (isinstance(arg, ast.Call) and 
                                    isinstance(arg.func, ast.Attribute) and arg.func.attr == 'format'):
                                is_vulnerable = self._check_user_input_in_node(arg)
                                if is_vulnerable:
                                    line_num = node.lineno
                                    lines = self.content.split('\n')
                                    line_content = lines[line_num - 1] if line_num <= len(lines) else ''
                                    
                                    self.findings.append({
                                        'rule_id': 'A03-SQLI-AST-002',
                                        'line_number': line_num,
                                        'line_content': line_content.strip(),
                                        'match': 'Formatted string in SQL execution with user input',
                                        'file_path': str(self.file_path),
                                        'severity': 'HIGH',
                                        'owasp_category': 'A03',
                                        'description': 'SQL Injection vulnerability: User input used in formatted SQL query',
                                        'recommendation': 'Use parameterized queries instead of string formatting',
                                        'confidence': 'high',
                                        'exploitability': 'high'
                                    })
                
                self.generic_visit(node)
            
            def _check_user_input_in_node(self, node: ast.AST) -> bool:
                """Check if node contains user input variables."""
                if isinstance(node, ast.Name):
                    return node.id in self.user_input_vars
                elif isinstance(node, ast.BinOp):
                    return (self._check_user_input_in_node(node.left) or 
                           self._check_user_input_in_node(node.right))
                elif isinstance(node, ast.Call):
                    # Check if function call is user input source
                    if isinstance(node.func, ast.Attribute):
                        attr_name = node.func.attr.lower()
                        if any(source in attr_name for source in ['get', 'post', 'input', 'request']):
                            return True
                    # Check arguments
                    for arg in node.args:
                        if self._check_user_input_in_node(arg):
                            return True
                elif isinstance(node, ast.Attribute):
                    # Check attribute access (e.g., request.args.get)
                    if isinstance(node.value, ast.Name):
                        if node.value.id.lower() in ['request', 'req']:
                            return True
                return False
        
        visitor = SQLInjectionVisitor(file_path, content, self.context_analyzer, tree)
        visitor.visit(tree)
        
        return visitor.findings
    
    def _get_node_at_line(self, tree: ast.AST, line_num: int) -> Optional[ast.AST]:
        """Get AST node at specific line number."""
        for node in ast.walk(tree):
            if hasattr(node, 'lineno') and node.lineno == line_num:
                return node
        return None
    
    def _is_likely_vulnerable(self, finding: Dict, content: str, file_path: Path) -> bool:
        """Check if finding is likely a real vulnerability (not false positive)."""
        line_content = finding.get('line_content', '').lower()
        
        # Skip if it's a comment
        if line_content.strip().startswith('#'):
            return False
        
        # Skip if it's a test file (but be less strict)
        if 'test' in file_path.name.lower() and 'test_' in line_content:
            # Only skip obvious test patterns
            if 'test_' in line_content or 'mock' in line_content:
                return False
        
        # Check for obvious false positives (but be less aggressive)
        false_positive_patterns = [
            'example', 'todo', 'fixme', 'xxx', 'placeholder',
        ]
        
        # Only skip if it's clearly a comment or example
        for pattern in false_positive_patterns:
            if pattern in line_content and ('#' in line_content or '//' in line_content):
                return False
        
        return True
    
    def _determine_vuln_type(self, rule_id: str) -> Optional[str]:
        """Determine vulnerability type from rule ID."""
        rule_lower = rule_id.lower()
        
        if 'sql' in rule_lower or 'sqli' in rule_lower:
            return 'sql_injection'
        elif 'xss' in rule_lower:
            return 'xss'
        elif 'command' in rule_lower or 'cmd' in rule_lower:
            return 'command_injection'
        elif 'path' in rule_lower or 'traversal' in rule_lower:
            return 'path_traversal'
        elif 'crypto' in rule_lower or 'md5' in rule_lower or 'sha1' in rule_lower:
            return 'crypto_weak'
        
        return None

