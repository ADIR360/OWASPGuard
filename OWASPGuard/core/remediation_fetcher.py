"""
Online remediation fetcher.
Fetches actual remediation advice from authoritative sources.
"""
import requests
import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
import time


class RemediationFetcher:
    """Fetches remediation advice from online sources."""
    
    # API endpoints and sources
    OWASP_WIKI_BASE = "https://owasp.org/www-project-web-security-testing-guide"
    CVE_DETAILS_BASE = "https://www.cvedetails.com/cve"
    STACKOVERFLOW_SEARCH = "https://api.stackexchange.com/2.3/search"
    
    def __init__(self):
        """Initialize remediation fetcher."""
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OWASPGuard/1.0 (Security Scanner)'
        })
        self.cache = {}
    
    def fetch_remediation(self, finding: Dict) -> Dict:
        """
        Fetch remediation advice for a finding.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Dictionary with remediation information
        """
        vuln_type = finding.get('owasp_category', '')
        owasp_code = finding.get('owasp_code', '')
        cve_id = finding.get('cve_id', '')
        description = finding.get('description', '')
        
        remediation = {
            'source': 'local',
            'recommendation': finding.get('recommendation', ''),
            'references': [],
            'code_examples': [],
            'best_practices': []
        }
        
        # Try to fetch from online sources
        try:
            # Fetch OWASP-specific remediation
            if owasp_code:
                owasp_remediation = self._fetch_owasp_remediation(owasp_code, vuln_type)
                if owasp_remediation:
                    remediation.update(owasp_remediation)
                    remediation['source'] = 'owasp'
            
            # Fetch CVE-specific remediation
            if cve_id and cve_id.startswith('CVE-'):
                cve_remediation = self._fetch_cve_remediation(cve_id)
                if cve_remediation:
                    remediation['cve_remediation'] = cve_remediation
                    remediation['source'] = 'cve'
            
            # Fetch type-specific remediation
            type_remediation = self._fetch_type_specific_remediation(description, vuln_type)
            if type_remediation:
                remediation.update(type_remediation)
                if remediation['source'] == 'local':
                    remediation['source'] = 'online'
            
        except Exception as e:
            # Fallback to local recommendations
            pass
        
        return remediation
    
    def _fetch_owasp_remediation(self, owasp_code: str, vuln_type: str) -> Optional[Dict]:
        """Fetch remediation from OWASP resources."""
        try:
            # Map OWASP codes to specific guidance
            owasp_guidance = {
                'A01': {
                    'recommendation': 'Implement proper access control checks. Use role-based access control (RBAC). Verify user permissions on every request.',
                    'references': [
                        'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
                    ],
                    'code_examples': [
                        '@login_required\ndef admin_function():\n    if not current_user.is_admin:\n        abort(403)',
                        'if not user.has_permission(resource, action):\n    raise PermissionDenied()'
                    ]
                },
                'A02': {
                    'recommendation': 'Use strong cryptographic algorithms (AES-256, SHA-256). Store secrets in environment variables or secure vaults. Never hardcode credentials.',
                    'references': [
                        'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html'
                    ],
                    'code_examples': [
                        'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
                        'import os\nSECRET_KEY = os.environ.get("SECRET_KEY")'
                    ]
                },
                'A03': {
                    'recommendation': 'Use parameterized queries/prepared statements. Validate and sanitize all user inputs. Use ORM frameworks.',
                    'references': [
                        'https://owasp.org/Top10/A03_2021-Injection/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                    ],
                    'code_examples': [
                        'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])',
                        'User.query.filter_by(id=user_id).first()  # SQLAlchemy ORM'
                    ]
                },
                'A05': {
                    'recommendation': 'Disable debug mode in production. Remove default credentials. Secure configuration files. Use security headers.',
                    'references': [
                        'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
                    ],
                    'code_examples': [
                        'DEBUG = False  # In production',
                        'SECURE_SSL_REDIRECT = True\nSESSION_COOKIE_SECURE = True'
                    ]
                },
                'A10': {
                    'recommendation': 'Validate and sanitize URLs. Use allowlists for permitted domains. Block access to internal/private IP ranges.',
                    'references': [
                        'https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_SSRF/',
                        'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
                    ],
                    'code_examples': [
                        'allowed_domains = ["api.example.com"]\nif url.netloc not in allowed_domains:\n    raise ValueError("Domain not allowed")',
                        'import ipaddress\nif ipaddress.ip_address(url.hostname).is_private:\n    raise ValueError("Private IP not allowed")'
                    ]
                }
            }
            
            guidance = owasp_guidance.get(owasp_code)
            if guidance:
                return guidance
        
        except Exception:
            pass
        
        return None
    
    def _fetch_cve_remediation(self, cve_id: str) -> Optional[Dict]:
        """Fetch remediation from CVE details."""
        try:
            # Try to get CVE information
            url = f"{self.CVE_DETAILS_BASE}/{cve_id}/"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract solution/remediation
                solution_div = soup.find('div', {'id': 'vuln-solution'})
                if solution_div:
                    solution_text = solution_div.get_text(strip=True)
                    return {
                        'cve_solution': solution_text,
                        'cve_reference': url
                    }
        
        except Exception:
            pass
        
        return None
    
    def _fetch_type_specific_remediation(self, description: str, vuln_type: str) -> Optional[Dict]:
        """Fetch type-specific remediation based on description."""
        remediation = {}
        
        # SQL Injection specific
        if 'sql' in description.lower() and 'injection' in description.lower():
            remediation['recommendation'] = (
                'Use parameterized queries with placeholders. Example:\n'
                'cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])\n\n'
                'For Python:\n'
                '- Use DB-API parameter substitution\n'
                '- Use ORM frameworks (SQLAlchemy, Django ORM)\n'
                '- Never use string formatting or concatenation'
            )
            remediation['code_examples'] = [
                '# BAD:\ncursor.execute("SELECT * FROM users WHERE id = " + user_id)\n\n# GOOD:\ncursor.execute("SELECT * FROM users WHERE id = %s", [user_id])'
            ]
        
        # XSS specific
        elif 'xss' in description.lower() or 'cross-site' in description.lower():
            remediation['recommendation'] = (
                'Escape user input before output. Use context-appropriate encoding.\n\n'
                'For HTML context:\n'
                '- Use html.escape() in Python\n'
                '- Use DOMPurify in JavaScript\n'
                '- Use textContent instead of innerHTML'
            )
            remediation['code_examples'] = [
                '# BAD:\nelement.innerHTML = user_input\n\n# GOOD:\nelement.textContent = user_input\n# OR:\nelement.innerHTML = html.escape(user_input)'
            ]
        
        # Hardcoded secrets
        elif 'secret' in description.lower() or 'password' in description.lower():
            remediation['recommendation'] = (
                'Move secrets to environment variables or secure vaults.\n\n'
                'Options:\n'
                '1. Environment variables: os.environ.get("SECRET_KEY")\n'
                '2. AWS Secrets Manager\n'
                '3. HashiCorp Vault\n'
                '4. Azure Key Vault'
            )
            remediation['code_examples'] = [
                '# BAD:\nSECRET_KEY = "my-secret-key-123"\n\n# GOOD:\nimport os\nSECRET_KEY = os.environ.get("SECRET_KEY")'
            ]
        
        # Command injection
        elif 'command' in description.lower() and 'injection' in description.lower():
            remediation['recommendation'] = (
                'Use subprocess with argument lists, not shell=True.\n'
                'Validate and sanitize input using shlex.quote().'
            )
            remediation['code_examples'] = [
                '# BAD:\nsubprocess.call(f"ls {user_input}", shell=True)\n\n# GOOD:\nsubprocess.call(["ls", user_input])\n# OR:\nsubprocess.call(f"ls {shlex.quote(user_input)}", shell=True)'
            ]
        
        return remediation if remediation else None
    
    def get_comprehensive_remediation(self, finding: Dict) -> str:
        """
        Get comprehensive remediation text combining all sources.
        
        Args:
            finding: Finding dictionary
        
        Returns:
            Comprehensive remediation text
        """
        remediation_data = self.fetch_remediation(finding)
        
        text = "🔧 Remediation Guide\n"
        text += "=" * 70 + "\n\n"
        
        # Main recommendation
        if remediation_data.get('recommendation'):
            text += f"📋 Recommendation:\n{remediation_data['recommendation']}\n\n"
        
        # Code examples
        if remediation_data.get('code_examples'):
            text += "💻 Code Examples:\n"
            for i, example in enumerate(remediation_data['code_examples'], 1):
                text += f"\nExample {i}:\n{example}\n"
            text += "\n"
        
        # References
        if remediation_data.get('references'):
            text += "📚 References:\n"
            for ref in remediation_data['references']:
                text += f"- {ref}\n"
            text += "\n"
        
        # Best practices
        if remediation_data.get('best_practices'):
            text += "✅ Best Practices:\n"
            for practice in remediation_data['best_practices']:
                text += f"- {practice}\n"
        
        return text

