"""
Real-time CVE fetcher from online sources.
Fetches actual vulnerability data from NVD, GitHub Advisory, etc.
"""
import requests
import json
import time
from typing import Dict, List, Optional
from pathlib import Path
import hashlib


class CVEFetcher:
    """Fetches CVE data from online sources."""
    
    # API endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GITHUB_ADVISORY_API = "https://api.github.com/advisories"
    
    # Rate limiting
    RATE_LIMIT_DELAY = 0.6  # NVD allows 5 requests per 30 seconds
    
    def __init__(self, cache_dir: str = ".cve_cache"):
        """
        Initialize CVE fetcher.
        
        Args:
            cache_dir: Directory to cache CVE data
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'OWASPGuard/1.0'
        })
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Enforce rate limiting."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.RATE_LIMIT_DELAY:
            time.sleep(self.RATE_LIMIT_DELAY - time_since_last)
        
        self.last_request_time = time.time()
    
    def _get_cache_key(self, package: str, version: str) -> str:
        """Generate cache key for package version."""
        key = f"{package}_{version}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _get_cached(self, cache_key: str) -> Optional[Dict]:
        """Get cached CVE data."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                return None
        return None
    
    def _cache_data(self, cache_key: str, data: Dict):
        """Cache CVE data."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except:
            pass
    
    def fetch_nvd_cve(self, package: str, version: str) -> List[Dict]:
        """
        Fetch CVE data from NVD API.
        
        Args:
            package: Package name
            version: Package version
        
        Returns:
            List of CVE dictionaries
        """
        # Check cache first
        cache_key = self._get_cache_key(package, version)
        cached = self._get_cached(cache_key)
        if cached:
            return cached.get('cves', [])
        
        self._rate_limit()
        
        try:
            # Search NVD for package vulnerabilities
            # Note: NVD API requires specific search terms
            search_term = f"{package}"
            
            params = {
                'keywordSearch': search_term,
                'resultsPerPage': 20
            }
            
            response = self.session.get(self.NVD_API_BASE, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                cves = []
                
                # Parse NVD response
                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    cve_item = vuln.get('cve', {})
                    cve_id = cve_item.get('id', '')
                    
                    # Get severity
                    metrics = cve_item.get('metrics', {})
                    severity = 'MEDIUM'
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0].get('cvssData', {})
                        base_score = cvss.get('baseScore', 0)
                        if base_score >= 9.0:
                            severity = 'CRITICAL'
                        elif base_score >= 7.0:
                            severity = 'HIGH'
                        elif base_score >= 4.0:
                            severity = 'MEDIUM'
                        else:
                            severity = 'LOW'
                    
                    # Check if version is affected (simplified)
                    descriptions = cve_item.get('descriptions', [])
                    description = descriptions[0].get('value', '') if descriptions else ''
                    
                    if package.lower() in description.lower():
                        cves.append({
                            'cve_id': cve_id,
                            'severity': severity,
                            'description': description[:200],
                            'package': package,
                            'version': version
                        })
                
                # Cache results
                self._cache_data(cache_key, {'cves': cves})
                return cves
            
        except Exception as e:
            print(f"[!] Error fetching from NVD: {e}")
        
        return []
    
    def fetch_github_advisory(self, package: str, ecosystem: str = 'pip') -> List[Dict]:
        """
        Fetch advisory data from GitHub Advisory API.
        
        Args:
            package: Package name
            ecosystem: Package ecosystem (pip, npm, maven)
        
        Returns:
            List of advisory dictionaries
        """
        cache_key = self._get_cache_key(f"{package}_gh", ecosystem)
        cached = self._get_cached(cache_key)
        if cached:
            return cached.get('advisories', [])
        
        self._rate_limit()
        
        try:
            # GitHub Advisory API search
            ecosystem_map = {
                'pip': 'PYPI',
                'npm': 'NPM',
                'maven': 'MAVEN'
            }
            
            gh_ecosystem = ecosystem_map.get(ecosystem.lower(), 'PYPI')
            
            # Search GitHub advisories
            search_url = f"https://api.github.com/search/advisories"
            params = {
                'q': f'{package} ecosystem:{gh_ecosystem}',
                'per_page': 20
            }
            
            response = self.session.get(search_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                advisories = []
                
                for item in data.get('items', []):
                    ghsa_id = item.get('ghsa_id', '')
                    severity = item.get('severity', 'MEDIUM').upper()
                    summary = item.get('summary', '')
                    
                    # Get affected versions
                    affected = item.get('vulnerabilities', [])
                    affected_versions = []
                    for vuln in affected:
                        ranges = vuln.get('vulnerable_version_range', '')
                        if ranges:
                            affected_versions.append(ranges)
                    
                    advisories.append({
                        'cve_id': ghsa_id,
                        'severity': severity,
                        'description': summary[:200],
                        'package': package,
                        'affected_versions': affected_versions
                    })
                
                self._cache_data(cache_key, {'advisories': advisories})
                return advisories
        
        except Exception as e:
            print(f"[!] Error fetching from GitHub Advisory: {e}")
        
        return []
    
    def fetch_vulnerabilities(self, package: str, version: str, 
                             ecosystem: str = 'pip') -> List[Dict]:
        """
        Fetch vulnerabilities from all sources.
        
        Args:
            package: Package name
            version: Package version
            ecosystem: Package ecosystem
        
        Returns:
            Combined list of vulnerabilities
        """
        vulnerabilities = []
        
        # Fetch from NVD
        nvd_cves = self.fetch_nvd_cve(package, version)
        vulnerabilities.extend(nvd_cves)
        
        # Fetch from GitHub Advisory
        gh_advisories = self.fetch_github_advisory(package, ecosystem)
        vulnerabilities.extend(gh_advisories)
        
        # Deduplicate by CVE ID
        seen = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                unique_vulns.append(vuln)
        
        return unique_vulns

