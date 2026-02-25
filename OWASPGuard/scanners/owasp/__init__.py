"""
OWASP Top 10 specific scanners
"""
try:
    from scanners.owasp.access_control import AccessControlScanner
    from scanners.owasp.crypto_failures import CryptoScanner
    from scanners.owasp.injection import InjectionScanner
    from scanners.owasp.insecure_design import InsecureDesignScanner
    from scanners.owasp.security_misconfiguration import SecurityMisconfigurationScanner
    from scanners.owasp.auth_failures import AuthenticationFailuresScanner
    from scanners.owasp.data_integrity import DataIntegrityScanner
    from scanners.owasp.logging_failures import LoggingFailuresScanner
    from scanners.owasp.ssrf import SSRFScanner
except ImportError:
    AccessControlScanner = None
    CryptoScanner = None
    InjectionScanner = None
    InsecureDesignScanner = None
    SecurityMisconfigurationScanner = None
    AuthenticationFailuresScanner = None
    DataIntegrityScanner = None
    LoggingFailuresScanner = None
    SSRFScanner = None

__all__ = [
    'AccessControlScanner',
    'CryptoScanner',
    'InjectionScanner',
    'InsecureDesignScanner',
    'SecurityMisconfigurationScanner',
    'AuthenticationFailuresScanner',
    'DataIntegrityScanner',
    'LoggingFailuresScanner',
    'SSRFScanner',
]

