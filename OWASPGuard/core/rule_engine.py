"""
Rule engine for loading and applying security rules.
This is the core IP of the tool.
"""
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Rule:
    """Represents a security detection rule."""
    id: str
    language: str
    pattern: str
    severity: str
    owasp_category: str
    description: str
    recommendation: str
    pattern_type: str = "regex"  # regex, ast, or file_pattern
    file_pattern: Optional[str] = None  # For config file scanning
    compiled_pattern: Optional[re.Pattern] = None
    
    def __post_init__(self):
        """Compile regex pattern for performance."""
        if self.pattern_type == "regex" and self.pattern:
            try:
                self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error:
                self.compiled_pattern = None


class RuleEngine:
    """Loads and applies security rules."""
    
    def __init__(self, rules_dir: str = "rules"):
        """
        Initialize rule engine.
        
        Args:
            rules_dir: Directory containing rule JSON files
        """
        self.rules_dir = Path(rules_dir)
        self.rules: List[Rule] = []
        self._load_rules()
    
    def _load_rules(self):
        """Load all rules from JSON files."""
        if not self.rules_dir.exists():
            # Use default rules directory relative to this file
            self.rules_dir = Path(__file__).parent.parent / "rules"
        
        rule_files = [
            "injection.json",
            "crypto_failures.json",
            "access_control.json",
            "misconfiguration.json",
            "ssrf.json",
            "auth_failures.json",
            "logging_failures.json",
            "insecure_design.json",
            "data_integrity.json"
        ]
        
        for rule_file in rule_files:
            rule_path = self.rules_dir / rule_file
            if rule_path.exists():
                self._load_rule_file(rule_path)
    
    def _load_rule_file(self, rule_path: Path):
        """
        Load rules from a JSON file.
        
        Args:
            rule_path: Path to rule JSON file
        """
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                if isinstance(data, list):
                    # List of rules
                    for rule_data in data:
                        rule = self._create_rule(rule_data)
                        if rule:
                            self.rules.append(rule)
                elif isinstance(data, dict) and 'rules' in data:
                    # Object with rules array
                    for rule_data in data['rules']:
                        rule = self._create_rule(rule_data)
                        if rule:
                            self.rules.append(rule)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load rules from {rule_path}: {e}")
    
    def _create_rule(self, rule_data: Dict[str, Any]) -> Optional[Rule]:
        """
        Create a Rule object from dictionary.
        
        Args:
            rule_data: Rule data dictionary
        
        Returns:
            Rule object or None if invalid
        """
        try:
            return Rule(
                id=rule_data.get('id', ''),
                language=rule_data.get('language', 'any'),
                pattern=rule_data.get('pattern', ''),
                severity=rule_data.get('severity', 'MEDIUM'),
                owasp_category=rule_data.get('owasp', ''),
                description=rule_data.get('description', ''),
                recommendation=rule_data.get('recommendation', ''),
                pattern_type=rule_data.get('pattern_type', 'regex'),
                file_pattern=rule_data.get('file_pattern')
            )
        except Exception as e:
            print(f"Warning: Invalid rule data: {e}")
            return None
    
    def get_rules_for_language(self, language: str) -> List[Rule]:
        """
        Get rules applicable to a specific language.
        
        Args:
            language: Programming language (python, javascript, java, any)
        
        Returns:
            List of applicable rules
        """
        return [r for r in self.rules if r.language in [language, 'any']]
    
    def get_rules_for_owasp(self, owasp_category: str) -> List[Rule]:
        """
        Get rules for a specific OWASP category.
        
        Args:
            owasp_category: OWASP category (A01, A02, etc.)
        
        Returns:
            List of rules for the category
        """
        return [r for r in self.rules if r.owasp_category == owasp_category]
    
    def match_rule(self, rule: Rule, content: str, file_path: Path) -> List[Dict[str, Any]]:
        """
        Match a rule against file content.
        
        Args:
            rule: Rule to apply
            content: File content to scan
            file_path: Path to file being scanned
        
        Returns:
            List of findings (empty if no matches)
        """
        findings = []
        
        if rule.pattern_type == "regex" and rule.compiled_pattern:
            # Regex-based matching
            for line_num, line in enumerate(content.split('\n'), 1):
                matches = rule.compiled_pattern.finditer(line)
                for match in matches:
                    findings.append({
                        'rule_id': rule.id,
                        'line_number': line_num,
                        'line_content': line.strip(),
                        'match': match.group(0),
                        'file_path': str(file_path),
                        'severity': rule.severity,
                        'owasp_category': rule.owasp_category,
                        'description': rule.description,
                        'recommendation': rule.recommendation
                    })
        
        elif rule.pattern_type == "file_pattern":
            # File pattern matching (for config files)
            if rule.file_pattern and rule.file_pattern in file_path.name:
                if rule.compiled_pattern and rule.compiled_pattern.search(content):
                    findings.append({
                        'rule_id': rule.id,
                        'line_number': 0,
                        'line_content': '',
                        'match': 'File pattern match',
                        'file_path': str(file_path),
                        'severity': rule.severity,
                        'owasp_category': rule.owasp_category,
                        'description': rule.description,
                        'recommendation': rule.recommendation
                    })
        
        return findings

