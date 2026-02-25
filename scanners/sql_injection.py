"""
SQL Injection vulnerability scanner.
"""
import requests
import time
from typing import List, Optional
from utils.vulnerability import Vulnerability, RiskLevel, OWASPCategory
from utils.payloads import PayloadLibrary, get_payloads


class SQLInjectionScanner:
    """Scans for SQL Injection vulnerabilities."""
    
    def __init__(self, delay: float = 0.5):
        """
        Initialize SQL Injection scanner.
        
        Args:
            delay: Delay between requests (seconds)
        """
        self.delay = delay
        self.payload_lib = PayloadLibrary()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check_sql_error_patterns(self, response_text: str) -> bool:
        """Check if response contains SQL error patterns."""
        response_lower = response_text.lower()
        for pattern in self.payload_lib.SQL_ERROR_PATTERNS:
            if pattern.lower() in response_lower:
                return True
        return False
    
    def check_time_based_injection(self, original_time: float, test_time: float, threshold: float = 3.0) -> bool:
        """Check if time-based SQL injection is detected."""
        return test_time - original_time >= threshold
    
    def scan_endpoint(self, url: str, method: str, parameter: str, 
                     input_type: str = 'text') -> Optional[Vulnerability]:
        """
        Scan a single endpoint for SQL Injection vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST)
            parameter: Parameter name to test
            input_type: Type of input field
        
        Returns:
            Vulnerability object if found, None otherwise
        """
        payloads = get_payloads("sql_injection")
        
        # Get baseline response
        try:
            if method.upper() == 'GET':
                baseline_response = self.session.get(url, timeout=10)
                baseline_time = time.time()
                time.sleep(0.1)
                baseline_time = time.time() - baseline_time
            else:
                baseline_response = self.session.post(url, timeout=10)
                baseline_time = time.time()
                time.sleep(0.1)
                baseline_time = time.time() - baseline_time
            
            baseline_text = baseline_response.text
            baseline_length = len(baseline_text)
        except Exception as e:
            return None
        
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
                    
                    start_time = time.time()
                    response = self.session.get(test_url, timeout=15)
                    elapsed_time = time.time() - start_time
                    
                else:
                    # Test POST parameter
                    data = {parameter: payload}
                    start_time = time.time()
                    response = self.session.post(url, data=data, timeout=15)
                    elapsed_time = time.time() - start_time
                
                # Check for SQL error patterns
                if self.check_sql_error_patterns(response.text):
                    return Vulnerability(
                        id=f"SQLI-{hash(url + parameter + payload) % 10000}",
                        title="SQL Injection Vulnerability",
                        description=f"SQL Injection vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"The application returned SQL error messages when injected with payload: {payload}",
                        category=OWASPCategory.A03_INJECTION,
                        risk_level=RiskLevel.HIGH,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"SQL error pattern detected in response. Response length: {len(response.text)}",
                        recommendation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs. "
                                    "Implement least privilege database access. Use ORM frameworks that prevent SQL injection."
                    )
                
                # Check for time-based injection
                if self.check_time_based_injection(baseline_time, elapsed_time):
                    return Vulnerability(
                        id=f"SQLI-TIME-{hash(url + parameter + payload) % 10000}",
                        title="SQL Injection Vulnerability (Time-based)",
                        description=f"Time-based SQL Injection vulnerability detected in parameter '{parameter}' at {url}. "
                                  f"The application exhibited delayed response when injected with payload: {payload}",
                        category=OWASPCategory.A03_INJECTION,
                        risk_level=RiskLevel.HIGH,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=payload,
                        evidence=f"Response delay detected: {elapsed_time:.2f}s (baseline: {baseline_time:.2f}s)",
                        recommendation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs. "
                                    "Implement least privilege database access."
                    )
                
                # Check for boolean-based injection (response length difference)
                if abs(len(response.text) - baseline_length) > baseline_length * 0.1:
                    # Additional check: verify it's not just normal variation
                    if len(response.text) != baseline_length:
                        return Vulnerability(
                            id=f"SQLI-BOOL-{hash(url + parameter + payload) % 10000}",
                            title="SQL Injection Vulnerability (Boolean-based)",
                            description=f"Potential SQL Injection vulnerability detected in parameter '{parameter}' at {url}. "
                                      f"Response length significantly differs when injected with payload: {payload}",
                            category=OWASPCategory.A03_INJECTION,
                            risk_level=RiskLevel.MEDIUM,
                            url=url,
                            method=method,
                            parameter=parameter,
                            payload=payload,
                            evidence=f"Response length difference: {abs(len(response.text) - baseline_length)} bytes",
                            recommendation="Use parameterized queries/prepared statements. Validate and sanitize all user inputs."
                        )
                
                time.sleep(self.delay)
                
            except Exception as e:
                continue
        
        return None
    
    def scan(self, input_points: List[dict]) -> List[Vulnerability]:
        """
        Scan multiple input points for SQL Injection vulnerabilities.
        
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
                
                print(f"[*] Testing SQL Injection: {method} {url} - Parameter: {param_name}")
                vuln = self.scan_endpoint(url, method, param_name, param_type)
                
                if vuln:
                    vulnerabilities.append(vuln)
                    print(f"[+] SQL Injection found: {url} - {param_name}")
        
        return vulnerabilities

