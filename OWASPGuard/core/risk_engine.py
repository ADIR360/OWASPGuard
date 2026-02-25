"""
Risk assessment and scoring engine.
Calculates risk levels based on severity, exploitability, and confidence.
"""
from typing import Dict, List
from enum import Enum
from core.severity_scorer import SeverityScorer


class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFORMATIONAL"


class RiskEngine:
    """Calculates risk scores and levels for findings."""
    
    # Severity weights
    SEVERITY_WEIGHTS = {
        'CRITICAL': 100,
        'HIGH': 75,
        'MEDIUM': 50,
        'LOW': 25,
        'INFO': 10
    }
    
    # Exploitability factors
    EXPLOITABILITY_FACTORS = {
        'high': 1.2,      # Easy to exploit
        'medium': 1.0,    # Moderate difficulty
        'low': 0.8        # Difficult to exploit
    }
    
    # Confidence factors
    CONFIDENCE_FACTORS = {
        'high': 1.0,      # Confident detection
        'medium': 0.8,    # Probable
        'low': 0.6        # Possible
    }
    
    @staticmethod
    def calculate_risk_score(finding: Dict) -> float:
        """
        Calculate risk score for a finding.
        
        Formula: risk = severity × exploitability × confidence
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Risk score (0-100)
        """
        # Severity is always treated as a string code
        severity_raw = finding.get('severity', 'MEDIUM')
        severity = str(severity_raw).upper()

        # Exploitability may be string (high/medium/low) or numeric
        exploit_raw = finding.get('exploitability', 'medium')
        if isinstance(exploit_raw, (int, float)):
            try:
                e_val = float(exploit_raw)
            except (TypeError, ValueError):
                e_val = 0.8
            if e_val >= 0.8:
                exploitability = 'high'
            elif e_val >= 0.5:
                exploitability = 'medium'
            else:
                exploitability = 'low'
        else:
            exploitability = str(exploit_raw).lower()

        # Confidence may also be numeric (0.0–1.0) or categorical
        conf_raw = finding.get('confidence', 'medium')
        if isinstance(conf_raw, (int, float)):
            try:
                c_val = float(conf_raw)
            except (TypeError, ValueError):
                c_val = 0.8
            if c_val >= 0.8:
                confidence = 'high'
            elif c_val >= 0.5:
                confidence = 'medium'
            else:
                confidence = 'low'
        else:
            confidence = str(conf_raw).lower()

        # Get base severity score
        base_score = RiskEngine.SEVERITY_WEIGHTS.get(severity, 50)

        # Apply exploitability factor
        exploit_factor = RiskEngine.EXPLOITABILITY_FACTORS.get(exploitability, 1.0)

        # Apply confidence factor
        conf_factor = RiskEngine.CONFIDENCE_FACTORS.get(confidence, 0.8)
        
        # Calculate final score
        risk_score = base_score * exploit_factor * conf_factor
        
        # Cap at 100
        return min(100, max(0, risk_score))
    
    @staticmethod
    def assign_risk_level(risk_score: float) -> RiskLevel:
        """
        Assign risk level based on score.
        
        Args:
            risk_score: Calculated risk score
        
        Returns:
            RiskLevel enum
        """
        if risk_score >= 80:
            return RiskLevel.CRITICAL
        elif risk_score >= 60:
            return RiskLevel.HIGH
        elif risk_score >= 40:
            return RiskLevel.MEDIUM
        elif risk_score >= 20:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    @staticmethod
    def assess_finding(finding: Dict) -> Dict:
        """
        Assess a finding and assign risk level.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Finding with risk assessment added
        """
        # Use severity scorer if available (1-100 scale)
        if 'severity_score' not in finding:
            severity_scorer = SeverityScorer()
            severity_score = severity_scorer.calculate_severity_score(finding)
            finding['severity_score'] = severity_score
            finding['severity'] = severity_scorer.get_severity_level(severity_score)
        
        # Also calculate traditional risk score for compatibility
        risk_score = RiskEngine.calculate_risk_score(finding)
        
        # Assign risk level
        risk_level = RiskEngine.assign_risk_level(risk_score)
        
        # Add to finding
        finding['risk_score'] = round(risk_score, 2)
        finding['risk_level'] = risk_level.value
        
        return finding
    
    @staticmethod
    def assess_findings(findings: List[Dict]) -> List[Dict]:
        """
        Assess multiple findings.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            List of findings with risk assessment
        """
        return [RiskEngine.assess_finding(f) for f in findings]

