"""
Server-Side Request Forgery (SSRF) vulnerability scanner.
"""
import requests
import time
from typing import List, Optional
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory
from utils.payloads import PayloadLibrary, get_payloads


class SSRFScanner:
    """Scans for Server-Side Request Forgery (SSRF) vulnerabilities."""
    
    def __init__(self, delay: float = 0.5):
        """
        Initialize SSRF scanner.
        
        Args:
            delay: Delay between requests (seconds)
        """
        self.delay = delay
        self.payload_lib = PayloadLibrary()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        # Use a test server to detect SSRF
        self.test_server = "http://httpbin.org/get"  # Public test endpoint
    
    def check_ssrf_indicator(self, response_text: str, payload: str) -> bool:
        """Check if response indicates SSRF vulnerability."""
        # Check if response contains SSRF indicators
        indicators = [
            'connection refused',
            'connection timeout',
            'no route to host',
            'internal server error',
            'bad request',
        ]
        
        response_lower = response_text.lower()
        
        # Check if payload URL appears in response
        if payload in response_text or payload.replace('http://', '') in response_text:
            return True
        
        # Check for error messages that might indicate SSRF attempt
        for indicator in indicators:
            if indicator in response_lower:
                return True
        
        return False
    
    def check_response_time(self, original_time: float, test_time: float, threshold: float = 2.0) -> bool:
        """Check if response time indicates SSRF (connection attempts)."""
        return test_time - original_time >= threshold
    
    def scan_endpoint(self, url: str, method: str, parameter: str,
                     input_type: str = 'text') -> Optional[Vulnerability]:
        """
        Scan a single endpoint for SSRF vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST)
            parameter: Parameter name to test
            input_type: Type of input field
        
        Returns:
            Vulnerability object if found, None otherwise
        """
        payloads = get_payloads("ssrf")
        
        # Get baseline response time
        try:
            if method.upper() == 'GET':
                baseline_start = time.time()
                baseline_response = self.session.get(url, timeout=5)
                baseline_time = time.time() - baseline_start
            else:
                baseline_start = time.time()
                baseline_response = self.session.post(url, timeout=5)
                baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 1.0
        
        # Test each payload
        for payload in payloads[:10]:  # Limit to first 10 payloads
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
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=10)
                    elapsed_time = time.time() - start_time
                    
                else:
                    # Test POST parameter
                    data = {parameter: payload}
                    start_time = time.time()
                    response = self.session.post(url, data=data, timeout=10)
                    elapsed_time = time.time() - start_time
                
                # Check for SSRF indicators
                if self.check_ssrf_indicator(response.text, payload):
                    return Vulnerability(
                        id=f"SSRF-{hash(url + parameter + payload) % 10000}",
                        title="Server-Side Request Forgery (SSRF) Vulnerability",
                        description=f"SSRF vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"The application appears to make server-side requests based on user input.",
                        category=OWASPCategory.A10_SSRF,
                        risk_level=RiskLevel.HIGH,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"SSRF indicator detected in response. Response time: {elapsed_time:.2f}s",
                        recommendation="Validate and sanitize all URLs provided by users. Use allowlists for permitted URLs. "
                                    "Block access to internal/private IP addresses. Implement proper network segmentation. "
                                    "Use URL parsing libraries to prevent bypasses."
                    )
                
                # Check for time-based indicators
                if self.check_response_time(baseline_time, elapsed_time):
                    return Vulnerability(
                        id=f"SSRF-TIME-{hash(url + parameter + payload) % 10000}",
                        title="Server-Side Request Forgery (SSRF) Vulnerability - Time-based",
                        description=f"Potential SSRF vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"Response delay suggests server-side connection attempts.",
                        category=OWASPCategory.A10_SSRF,
                        risk_level=RiskLevel.MEDIUM,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Response delay detected: {elapsed_time:.2f}s (baseline: {baseline_time:.2f}s)",
                        recommendation="Validate and sanitize all URLs provided by users. Use allowlists for permitted URLs. "
                                    "Block access to internal/private IP addresses."
                    )
                
                # Check for localhost/127.0.0.1 access
                if '127.0.0.1' in payload or 'localhost' in payload.lower():
                    if response.status_code != baseline_response.status_code or len(response.text) != len(baseline_response.text):
                        return Vulnerability(
                            id=f"SSRF-LOCAL-{hash(url + parameter + payload) % 10000}",
                            title="Server-Side Request Forgery (SSRF) Vulnerability - Localhost Access",
                            description=f"SSRF vulnerability detected in parameter '{parameter}' at {url}. "
                                      f"The application appears to access localhost/internal resources.",
                            category=OWASPCategory.A10_SSRF,
                            risk_level=RiskLevel.CRITICAL,
                            url=url,
                            method=method,
                            parameter=parameter,
                            payload=payload,
                            evidence="Response differs when accessing localhost/internal resources",
                            recommendation="Block access to localhost, 127.0.0.1, and internal IP ranges. "
                                        "Validate all URLs against allowlists. Implement network-level protections."
                        )
                
                time.sleep(self.delay)
                
            except requests.exceptions.Timeout:
                # Timeout might indicate SSRF attempt
                if '127.0.0.1' in payload or 'localhost' in payload.lower():
                    return Vulnerability(
                        id=f"SSRF-TIMEOUT-{hash(url + parameter + payload) % 10000}",
                        title="Server-Side Request Forgery (SSRF) Vulnerability - Timeout",
                        description=f"Potential SSRF vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"Request timeout when accessing localhost/internal resources.",
                        category=OWASPCategory.A10_SSRF,
                        risk_level=RiskLevel.MEDIUM,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence="Request timeout detected with localhost/internal payload",
                        recommendation="Block access to localhost and internal IP ranges. Validate URLs against allowlists."
                    )
            except Exception as e:
                continue
        
        return None
    
    def scan(self, input_points: List[dict]) -> List[Vulnerability]:
        """
        Scan multiple input points for SSRF vulnerabilities.
        
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
                
                # Focus on URL-like parameters
                url_keywords = ['url', 'link', 'uri', 'endpoint', 'api', 'webhook', 'callback']
                if not any(keyword in param_name.lower() for keyword in url_keywords):
                    # Still test all parameters, but prioritize URL-like ones
                    pass
                
                print(f"[*] Testing SSRF: {method} {url} - Parameter: {param_name}")
                vuln = self.scan_endpoint(url, method, param_name, param_type)
                
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[+] SSRF found: {url} - {param_name}")
        
        return vulnerabilities

