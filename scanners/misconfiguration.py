"""
Security Misconfiguration vulnerability scanner.
"""
import requests
import time
from typing import List, Optional, Dict
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory
from utils.payloads import PayloadLibrary


class MisconfigurationScanner:
    """Scans for Security Misconfiguration vulnerabilities."""
    
    def __init__(self, delay: float = 0.5):
        """
        Initialize Misconfiguration scanner.
        
        Args:
            delay: Delay between requests (seconds)
        """
        self.delay = delay
        self.payload_lib = PayloadLibrary()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_security_headers(self, url: str) -> List[Vulnerability]:
        """Check for missing security headers."""
        vulnerabilities = []
        
        try:
            response = self.session.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            missing_headers = []
            
            # Check for critical security headers
            header_checks = {
                'X-Frame-Options': {
                    'required': True,
                    'risk': RiskLevel.MEDIUM,
                    'description': 'Prevents clickjacking attacks'
                },
                'X-Content-Type-Options': {
                    'required': True,
                    'risk': RiskLevel.LOW,
                    'description': 'Prevents MIME type sniffing'
                },
                'Strict-Transport-Security': {
                    'required': False,  # Only for HTTPS
                    'risk': RiskLevel.MEDIUM,
                    'description': 'Enforces HTTPS connections'
                },
                'Content-Security-Policy': {
                    'required': True,
                    'risk': RiskLevel.HIGH,
                    'description': 'Prevents XSS and injection attacks'
                },
                'X-XSS-Protection': {
                    'required': False,  # Deprecated but still checked
                    'risk': RiskLevel.LOW,
                    'description': 'XSS protection (deprecated)'
                },
            }
            
            for header_name, check_info in header_checks.items():
                if header_name not in headers:
                    if check_info['required']:
                        missing_headers.append({
                            'name': header_name,
                            'risk': check_info['risk'],
                            'description': check_info['description']
                        })
            
            if missing_headers:
                for missing in missing_headers:
                    vulnerabilities.append(Vulnerability(
                        id=f"MISCONFIG-HEADER-{hash(url + missing['name']) % 10000}",
                        title=f"Security Misconfiguration - Missing {missing['name']} Header",
                        description=f"Missing security header '{missing['name']}' at {url}. {missing['description']}",
                        category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        risk_level=missing['risk'],
                        url=url,
                        method='HEAD',
                        evidence=f"Header '{missing['name']}' not present in response",
                        recommendation=f"Add '{missing['name']}' header to all HTTP responses. "
                                    f"Configure appropriate values based on application requirements."
                    ))
            
            time.sleep(self.delay)
            
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def check_server_info_disclosure(self, url: str) -> Optional[Vulnerability]:
        """Check for server information disclosure."""
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            # Check Server header
            server_header = headers.get('Server', '')
            if server_header:
                # Extract version information if present
                if any(char.isdigit() for char in server_header):
                    return Vulnerability(
                        id=f"MISCONFIG-SERVER-{hash(url) % 10000}",
                        title="Security Misconfiguration - Server Information Disclosure",
                        description=f"Server header exposes version information: {server_header}",
                        category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        risk_level=RiskLevel.LOW,
                        url=url,
                        method='GET',
                        evidence=f"Server header: {server_header}",
                        recommendation="Remove or minimize server version information in headers. "
                                    "Configure web server to hide version details."
                    )
            
            # Check X-Powered-By header
            powered_by = headers.get('X-Powered-By', '')
            if powered_by:
                return Vulnerability(
                    id=f"MISCONFIG-POWERED-{hash(url) % 10000}",
                    title="Security Misconfiguration - Technology Stack Disclosure",
                    description=f"X-Powered-By header exposes technology stack: {powered_by}",
                    category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                    risk_level=RiskLevel.LOW,
                    url=url,
                    method='GET',
                    evidence=f"X-Powered-By header: {powered_by}",
                    recommendation="Remove X-Powered-By header. Disable technology stack disclosure."
                )
            
            time.sleep(self.delay)
            
        except Exception as e:
            pass
        
        return None
    
    def check_debug_mode(self, url: str) -> Optional[Vulnerability]:
        """Check if debug mode is enabled."""
        try:
            response = self.session.get(url, timeout=10)
            content_lower = response.text.lower()
            
            debug_indicators = [
                'debug mode',
                'debug=true',
                'debugging enabled',
                'traceback',
                'stack trace',
                'exception details',
                'error details',
            ]
            
            for indicator in debug_indicators:
                if indicator in content_lower:
                    return Vulnerability(
                        id=f"MISCONFIG-DEBUG-{hash(url) % 10000}",
                        title="Security Misconfiguration - Debug Mode Enabled",
                        description=f"Debug mode appears to be enabled at {url}, exposing sensitive information.",
                        category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        risk_level=RiskLevel.MEDIUM,
                        url=url,
                        method='GET',
                        evidence=f"Debug indicator found: {indicator}",
                        recommendation="Disable debug mode in production environments. "
                                    "Ensure error pages don't expose stack traces or sensitive information."
                    )
            
            time.sleep(self.delay)
            
        except Exception as e:
            pass
        
        return None
    
    def check_error_handling(self, url: str) -> Optional[Vulnerability]:
        """Check for improper error handling."""
        try:
            # Test with invalid input to trigger errors
            test_url = f"{url}?test=../../../../etc/passwd"
            response = self.session.get(test_url, timeout=10)
            
            content_lower = response.text.lower()
            
            # Check for exposed error messages
            error_indicators = [
                'stack trace',
                'exception',
                'error in',
                'fatal error',
                'warning:',
                'notice:',
                'parse error',
                'syntax error',
            ]
            
            for indicator in error_indicators:
                if indicator in content_lower:
                    return Vulnerability(
                        id=f"MISCONFIG-ERROR-{hash(url) % 10000}",
                        title="Security Misconfiguration - Improper Error Handling",
                        description=f"Error messages expose sensitive information at {url}",
                        category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        risk_level=RiskLevel.MEDIUM,
                        url=url,
                        method='GET',
                        evidence=f"Error indicator found: {indicator}",
                        recommendation="Implement proper error handling. Use generic error messages for users. "
                                    "Log detailed errors server-side only. Don't expose stack traces or system information."
                    )
            
            time.sleep(self.delay)
            
        except Exception as e:
            pass
        
        return None
    
    def scan(self, endpoints: List[dict]) -> List[Vulnerability]:
        """
        Scan endpoints for Security Misconfiguration vulnerabilities.
        
        Args:
            endpoints: List of endpoint dictionaries from crawler
        
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        print("[*] Testing for Security Misconfiguration vulnerabilities...")
        
        # Test unique URLs only
        tested_urls = set()
        
        for endpoint in endpoints:
            url = endpoint['url']
            
            if url in tested_urls:
                continue
            
            tested_urls.add(url)
            
            print(f"[*] Testing misconfiguration: {url}")
            
            # Check security headers
            header_vulns = self.check_security_headers(url)
            vulnerabilities.extend(header_vulns)
            
            # Check server info disclosure
            server_vuln = self.check_server_info_disclosure(url)
            if server_vuln:
                vulnerabilities.append(server_vuln)
            
            # Check debug mode
            debug_vuln = self.check_debug_mode(url)
            if debug_vuln:
                vulnerabilities.append(debug_vuln)
            
            # Check error handling
            error_vuln = self.check_error_handling(url)
            if error_vuln:
                vulnerabilities.append(error_vuln)
        
        return vulnerabilities

