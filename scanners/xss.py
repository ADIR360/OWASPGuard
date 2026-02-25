"""
Cross-Site Scripting (XSS) vulnerability scanner.
"""
import requests
import time
from typing import List, Optional
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory
from utils.payloads import PayloadLibrary, get_payloads


class XSSScanner:
    """Scans for Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self, delay: float = 0.5):
        """
        Initialize XSS scanner.
        
        Args:
            delay: Delay between requests (seconds)
        """
        self.delay = delay
        self.payload_lib = PayloadLibrary()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_reflection(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected in response."""
        # Check for exact reflection
        if payload in response_text:
            return True
        
        # Check for HTML-encoded reflection
        encoded_payload = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded_payload in response_text:
            return True
        
        # Check for reflection indicators
        response_lower = response_text.lower()
        for indicator in self.payload_lib.XSS_REFLECTION_INDICATORS:
            if indicator.lower() in response_lower:
                # Verify it's not just part of the page structure
                if payload.lower()[:20] in response_lower:
                    return True
        
        return False
    
    def check_context(self, payload: str, response_text: str) -> str:
        """Determine the context where payload is reflected."""
        if f'<script>{payload}</script>' in response_text or f'<script>{payload}' in response_text:
            return "script_tag"
        elif f'"{payload}"' in response_text or f"'{payload}'" in response_text:
            return "attribute"
        elif f'>{payload}<' in response_text or f'>{payload}' in response_text:
            return "html_content"
        else:
            return "unknown"
    
    def scan_endpoint(self, url: str, method: str, parameter: str,
                     input_type: str = 'text') -> Optional[Vulnerability]:
        """
        Scan a single endpoint for XSS vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST)
            parameter: Parameter name to test
            input_type: Type of input field
        
        Returns:
            Vulnerability object if found, None otherwise
        """
        payloads = get_payloads("xss")
        
        # Test each payload
        for payload in payloads[:15]:  # Limit to first 15 payloads for performance
            try:
                if method.upper() == 'GET':
                    # Test GET parameter
                    parsed_url = requests.utils.urlparse(url)
                    params = requests.utils.parse_qs(parsed_url.query)
                    params[parameter] = [payload]
                    test_url = requests.utils.urlunparse((
                        parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                        parsed_url.params, requests.utils.urlencode(params, doseq=True),
                        parsed_url.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10)
                    
                else:
                    # Test POST parameter
                    data = {parameter: payload}
                    response = self.session.post(url, data=data, timeout=10)
                
                # Check for reflection
                if self.check_reflection(payload, response.text):
                    context = self.check_context(payload, response.text)
                    
                    # Determine risk level based on context
                    if context == "script_tag":
                        risk_level = RiskLevel.HIGH
                    elif context == "attribute":
                        risk_level = RiskLevel.MEDIUM
                    else:
                        risk_level = RiskLevel.MEDIUM
                    
                    return Vulnerability(
                        id=f"XSS-{hash(url + parameter + payload) % 10000}",
                        title="Cross-Site Scripting (XSS) Vulnerability",
                        description=f"XSS vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"The payload is reflected in the response without proper sanitization.",
                        category=OWASPCategory.A03_INJECTION,
                        risk_level=risk_level,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Payload reflected in {context} context. Response contains: {payload[:50]}...",
                        recommendation="Implement proper output encoding/escaping. Use Content Security Policy (CSP). "
                                    "Validate and sanitize all user inputs. Use framework's built-in XSS protection mechanisms."
                    )
                
                time.sleep(self.delay)
                
            except Exception as e:
                continue
        
        return None
    
    def scan(self, input_points: List[dict]) -> List[Vulnerability]:
        """
        Scan multiple input points for XSS vulnerabilities.
        
        Args:
            input_points: List of input point dictionaries from crawler
        
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        for input_point in input_points:
            url = input_point['url']
            method = input_point['method']
            
            for inp in input_point['inputs']:
                param_name = inp['name']
                param_type = inp.get('type', 'text')
                
                # Skip certain input types
                if param_type in ['hidden', 'submit', 'button', 'image']:
                    continue
                
                print(f"[*] Testing XSS: {method} {url} - Parameter: {param_name}")
                vuln = self.scan_endpoint(url, method, param_name, param_type)
                
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[+] XSS found: {url} - {param_name}")
        
        return vulnerabilities

