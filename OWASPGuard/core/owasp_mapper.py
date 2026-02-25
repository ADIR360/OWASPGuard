"""
OWASP Top 10 category mapper.
Maps findings to OWASP Top 10 categories.
"""
from typing import Dict, List
from enum import Enum


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 - Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 - Cryptographic Failures"
    A03_INJECTION = "A03:2021 - Injection"
    A04_INSECURE_DESIGN = "A04:2021 - Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 - Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 - Vulnerable and Outdated Components"
    A07_AUTHENTICATION_FAILURES = "A07:2021 - Identification and Authentication Failures"
    A08_DATA_INTEGRITY_FAILURES = "A08:2021 - Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 - Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 - Server-Side Request Forgery (SSRF)"


class OWASPMapper:
    """Maps findings to OWASP Top 10 categories."""
    
    # Mapping from rule IDs/patterns to OWASP categories
    CATEGORY_MAP = {
        'A01': OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
        'A02': OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
        'A03': OWASPCategory.A03_INJECTION,
        'A04': OWASPCategory.A04_INSECURE_DESIGN,
        'A05': OWASPCategory.A05_SECURITY_MISCONFIGURATION,
        'A06': OWASPCategory.A06_VULNERABLE_COMPONENTS,
        'A07': OWASPCategory.A07_AUTHENTICATION_FAILURES,
        'A08': OWASPCategory.A08_DATA_INTEGRITY_FAILURES,
        'A09': OWASPCategory.A09_LOGGING_FAILURES,
        'A10': OWASPCategory.A10_SSRF,
    }
    
    @staticmethod
    def map_finding(finding: Dict) -> Dict:
        """
        Map a finding to OWASP category.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Finding with OWASP category mapped
        """
        owasp_code = finding.get('owasp_category', '')
        
        # Extract OWASP code (e.g., "A03" from "A03-INJECTION")
        if owasp_code:
            code_prefix = owasp_code[:3]  # Get "A01", "A02", etc.
            if code_prefix in OWASPMapper.CATEGORY_MAP:
                finding['owasp_category_full'] = OWASPMapper.CATEGORY_MAP[code_prefix].value
                finding['owasp_code'] = code_prefix
            else:
                finding['owasp_category_full'] = "Unknown"
                finding['owasp_code'] = owasp_code
        else:
            finding['owasp_category_full'] = "Unknown"
            finding['owasp_code'] = "UNKNOWN"
        
        return finding
    
    @staticmethod
    def categorize_findings(findings: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Group findings by OWASP category.
        
        Args:
            findings: List of findings
        
        Returns:
            Dictionary mapping OWASP categories to findings
        """
        categorized = {}
        
        for finding in findings:
            finding = OWASPMapper.map_finding(finding)
            category = finding.get('owasp_category_full', 'Unknown')
            
            if category not in categorized:
                categorized[category] = []
            
            categorized[category].append(finding)
        
        return categorized

