"""
Numeric severity scoring system (1-100).
Provides precise severity ratings for vulnerabilities.
"""
from typing import Dict
from enum import Enum


class SeverityLevel(Enum):
    """Severity level enumeration."""
    CRITICAL = (90, 100)
    HIGH = (70, 89)
    MEDIUM = (40, 69)
    LOW = (20, 39)
    INFO = (1, 19)


class SeverityScorer:
    """
    Calculates numeric severity scores (1-100) for vulnerabilities.
    Considers multiple factors for accurate scoring.
    """
    
    def __init__(self):
        """Initialize severity scorer."""
        # Base severity weights
        self.base_severity_weights = {
            'CRITICAL': 90,
            'HIGH': 70,
            'MEDIUM': 50,
            'LOW': 30,
            'INFO': 10,
        }
        
        # Impact factors
        self.impact_factors = {
            'data_breach': 15,      # Can lead to data breach
            'system_compromise': 20, # Can compromise system
            'authentication_bypass': 18, # Bypasses authentication
            'privilege_escalation': 17,  # Allows privilege escalation
            'code_execution': 20,   # Allows code execution
            'information_disclosure': 10, # Information disclosure
            'dos': 8,               # Denial of service
        }
        
        # Exploitability factors
        self.exploitability_factors = {
            'remote': 10,          # Remotely exploitable
            'network': 8,          # Network accessible
            'local': 5,            # Requires local access
            'physical': 2,         # Requires physical access
            'low_complexity': 8,   # Easy to exploit
            'medium_complexity': 5,
            'high_complexity': 2,
        }
    
    def calculate_severity_score(self, finding: Dict) -> int:
        """
        Calculate numeric severity score (1-100).
        
        Args:
            finding: Finding dictionary with vulnerability details
        
        Returns:
            Integer severity score from 1-100
        """
        # Start with base severity
        base_severity = finding.get('severity', 'MEDIUM')
        base_score = self.base_severity_weights.get(base_severity, 50)
        
        # Adjust based on vulnerability type
        vuln_type = finding.get('owasp_category', '')
        owasp_code = finding.get('owasp_code', '')
        
        # Impact adjustments
        impact_score = self._calculate_impact(finding, vuln_type, owasp_code)
        
        # Exploitability adjustments
        exploitability_score = self._calculate_exploitability(finding)
        
        # Confidence adjustments (handle both string and numeric confidence)
        raw_confidence = finding.get('confidence', 'medium')
        if isinstance(raw_confidence, (int, float)):
            # Numeric confidence assumed 0.0–1.0; map to buckets
            try:
                c_val = float(raw_confidence)
            except (TypeError, ValueError):
                c_val = 0.8
            if c_val >= 0.8:
                confidence_key = 'high'
            elif c_val >= 0.5:
                confidence_key = 'medium'
            else:
                confidence_key = 'low'
        else:
            confidence_key = str(raw_confidence).lower()

        confidence_multiplier = {
            'high': 1.0,
            'medium': 0.9,
            'low': 0.7,
        }.get(confidence_key, 0.9)
        
        # Calculate final score
        final_score = base_score + impact_score + exploitability_score
        final_score = int(final_score * confidence_multiplier)
        
        # Clamp to 1-100 range
        final_score = max(1, min(100, final_score))
        
        return final_score
    
    def _calculate_impact(self, finding: Dict, vuln_type: str, owasp_code: str) -> float:
        """Calculate impact score."""
        impact = 0.0
        
        # SQL Injection - high impact
        if 'A03' in owasp_code or 'injection' in vuln_type.lower():
            if 'sql' in finding.get('description', '').lower():
                impact += self.impact_factors['data_breach']
                impact += self.impact_factors['system_compromise']
        
        # Command Injection - very high impact
        if 'command' in finding.get('description', '').lower():
            impact += self.impact_factors['code_execution']
            impact += self.impact_factors['system_compromise']
        
        # XSS - medium-high impact
        if 'xss' in finding.get('description', '').lower() or 'cross-site' in finding.get('description', '').lower():
            impact += self.impact_factors['authentication_bypass']
            impact += self.impact_factors['information_disclosure']
        
        # Broken Access Control - high impact
        if 'A01' in owasp_code or 'access' in vuln_type.lower():
            impact += self.impact_factors['privilege_escalation']
            impact += self.impact_factors['authentication_bypass']
        
        # Cryptographic Failures - high impact
        if 'A02' in owasp_code or 'crypto' in vuln_type.lower():
            impact += self.impact_factors['data_breach']
            impact += self.impact_factors['information_disclosure']
        
        # SSRF - high impact
        if 'A10' in owasp_code or 'ssrf' in vuln_type.lower():
            impact += self.impact_factors['system_compromise']
            impact += self.impact_factors['information_disclosure']
        
        # Hardcoded secrets - critical
        if 'secret' in finding.get('description', '').lower() or 'password' in finding.get('description', '').lower():
            impact += self.impact_factors['system_compromise']
            impact += self.impact_factors['authentication_bypass']
        
        return min(impact, 20.0)  # Cap impact at 20 points
    
    def _calculate_exploitability(self, finding: Dict) -> float:
        """Calculate exploitability score."""
        exploitability = 0.0
        
        # Check if remotely exploitable
        if finding.get('url') or 'http' in str(finding.get('file_path', '')).lower():
            exploitability += self.exploitability_factors['remote']
            exploitability += self.exploitability_factors['network']
        
        # Check exploitability level
        exploit_level = finding.get('exploitability', 'medium').lower()
        if exploit_level == 'high':
            exploitability += self.exploitability_factors['low_complexity']
        elif exploit_level == 'medium':
            exploitability += self.exploitability_factors['medium_complexity']
        else:
            exploitability += self.exploitability_factors['high_complexity']
        
        # Check if authentication required
        if 'auth' in finding.get('file_path', '').lower() or 'login' in finding.get('file_path', '').lower():
            exploitability -= 3  # Slightly harder if requires auth
        
        return min(exploitability, 15.0)  # Cap exploitability at 15 points
    
    def get_severity_level(self, score: int) -> str:
        """
        Get severity level from numeric score.
        
        Args:
            score: Numeric severity score (1-100)
        
        Returns:
            Severity level string
        """
        if score >= 90:
            return 'CRITICAL'
        elif score >= 70:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'INFO'
    
    def get_severity_color(self, score: int) -> str:
        """
        Get color code for severity score.
        
        Args:
            score: Numeric severity score
        
        Returns:
            Hex color code
        """
        if score >= 90:
            return '#e74c3c'  # Red
        elif score >= 70:
            return '#e67e22'  # Orange
        elif score >= 40:
            return '#f39c12'  # Yellow
        elif score >= 20:
            return '#3498db'  # Blue
        else:
            return '#95a5a6'  # Gray

