"""
Broken Access Control vulnerability scanner.
"""
import requests
import time
from typing import List, Optional
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory
from utils.payloads import PayloadLibrary


class AccessControlScanner:
    """Scans for Broken Access Control vulnerabilities."""
    
    def __init__(self, delay: float = 0.5):
        """
        Initialize Access Control scanner.
        
        Args:
            delay: Delay between requests (seconds)
        """
        self.delay = delay
        self.payload_lib = PayloadLibrary()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_unauthorized_access(self, url: str, method: str = 'GET') -> Optional[Vulnerability]:
        """
        Check if a protected resource is accessible without authentication.
        
        Args:
            url: Target URL
            method: HTTP method
        
        Returns:
            Vulnerability object if found, None otherwise
        """
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=10, allow_redirects=False)
            else:
                response = self.session.request(method, url, timeout=10, allow_redirects=False)
            
            # Check for successful access (200 OK)
            if response.status_code == 200:
                # Check if it's an admin/sensitive page
                content_lower = response.text.lower()
                sensitive_keywords = ['admin', 'dashboard', 'config', 'settings', 'user', 
                                    'password', 'api', 'backup', 'database']
                
                keyword_count = sum(1 for keyword in sensitive_keywords if keyword in content_lower)
                
                if keyword_count >= 2:  # Multiple sensitive keywords indicate sensitive page
                    return Vulnerability(
                        id=f"AC-{hash(url) % 10000}",
                        title="Broken Access Control - Unauthorized Access",
                        description=f"Unauthorized access detected to potentially protected resource: {url}. "
                                  f"The resource returned 200 OK without authentication.",
                        category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                        risk_level=RiskLevel.HIGH,
                        url=url,
                        method=method,
                        evidence=f"Status code: {response.status_code}. Content contains sensitive keywords.",
                        recommendation="Implement proper authentication and authorization checks. "
                                    "Use role-based access control (RBAC). Verify user permissions on every request. "
                                    "Restrict access to sensitive endpoints."
                    )
            
            # Check for directory listing
            if response.status_code == 200 and self.is_directory_listing(response.text):
                return Vulnerability(
                    id=f"AC-DIR-{hash(url) % 10000}",
                    title="Broken Access Control - Directory Listing Enabled",
                    description=f"Directory listing is enabled at {url}, exposing file structure.",
                    category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                    risk_level=RiskLevel.MEDIUM,
                    url=url,
                    method=method,
                    evidence="Directory listing detected in response",
                    recommendation="Disable directory listing on web servers. Use proper access controls. "
                                "Configure web server to deny directory browsing."
                )
            
            # Check for information disclosure (sensitive files)
            if response.status_code == 200:
                if self.is_sensitive_file(url, response.text):
                    return Vulnerability(
                        id=f"AC-FILE-{hash(url) % 10000}",
                        title="Broken Access Control - Sensitive File Exposure",
                        description=f"Sensitive file accessible without authentication: {url}",
                        category=OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
                        risk_level=RiskLevel.HIGH,
                        url=url,
                        method=method,
                        evidence="Sensitive file content detected",
                        recommendation="Restrict access to configuration files, backups, and sensitive data. "
                                    "Use proper file permissions. Implement authentication for sensitive resources."
                    )
            
            time.sleep(self.delay)
            
        except Exception as e:
            pass
        
        return None
    
    def is_directory_listing(self, content: str) -> bool:
        """Check if response indicates directory listing."""
        indicators = [
            'index of',
            'directory listing',
            '<title>index of',
            'parent directory',
            '[parent directory]',
            '<a href="../">',
        ]
        content_lower = content.lower()
        return any(indicator in content_lower for indicator in indicators)
    
    def is_sensitive_file(self, url: str, content: str) -> bool:
        """Check if the file contains sensitive information."""
        sensitive_patterns = [
            'password',
            'api_key',
            'secret',
            'private_key',
            'database',
            'db_password',
            'aws_access',
            'mysql',
            'postgresql',
            'mongodb',
        ]
        
        content_lower = content.lower()
        pattern_count = sum(1 for pattern in sensitive_patterns if pattern in content_lower)
        
        # Check URL for sensitive file extensions
        sensitive_extensions = ['.env', '.config', '.conf', '.bak', '.backup', '.sql', '.log']
        if any(url.lower().endswith(ext) for ext in sensitive_extensions):
            return True
        
        # If multiple sensitive patterns found, likely sensitive file
        return pattern_count >= 3
    
    def scan(self, endpoints: List[dict], base_url: str) -> List[Vulnerability]:
        """
        Scan endpoints for Broken Access Control vulnerabilities.
        
        Args:
            endpoints: List of endpoint dictionaries from crawler
            base_url: Base URL of the application
        
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Test common admin/sensitive paths
        sensitive_paths = self.payload_lib.ACCESS_CONTROL_PATHS
        
        print("[*] Testing for Broken Access Control vulnerabilities...")
        
        # Test discovered endpoints
        for endpoint in endpoints:
            url = endpoint['url']
            method = endpoint.get('method', 'GET')
            
            print(f"[*] Testing access control: {method} {url}")
            vuln = self.check_unauthorized_access(url, method)
            
            if vuln:
                vulnerabilities.append(vuln)
                print(f"[+] Broken Access Control found: {url}")
        
        # Test common sensitive paths
        for path in sensitive_paths[:20]:  # Limit to first 20 paths
            test_url = f"{base_url.rstrip('/')}{path}"
            
            print(f"[*] Testing sensitive path: {test_url}")
            vuln = self.check_unauthorized_access(test_url, 'GET')
            
            if vuln:
                vulnerabilities.append(vuln)
                print(f"[+] Broken Access Control found: {test_url}")
        
        return vulnerabilities

