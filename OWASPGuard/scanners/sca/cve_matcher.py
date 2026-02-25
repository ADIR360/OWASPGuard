"""
CVE matcher for dependency vulnerabilities.
Uses local CVE database, OSV database, and online sources to match dependencies.
"""
import json
from pathlib import Path
from typing import List, Dict, Optional
from core.cve_fetcher import CVEFetcher
from scanners.sca.version_matcher import is_version_affected, Version

# Try to import OSV database
try:
    from scanners.sca.osv_database import OSVDatabase
    OSV_AVAILABLE = True
except ImportError:
    OSV_AVAILABLE = False
    OSVDatabase = None


class CVEMatcher:
    """Matches dependencies against local CVE database."""
    
    def __init__(self, cve_db_path: str = "scanners/sca/local_cve_db.json", use_online: bool = True):
        """
        Initialize CVE matcher.
        
        Args:
            cve_db_path: Path to local CVE database JSON file
            use_online: Whether to fetch CVE data from online sources
        """
        self.cve_db_path = Path(cve_db_path)
        self.cve_database: Dict = {}
        self.use_online = use_online
        self.cve_fetcher = CVEFetcher() if use_online else None
        
        # Initialize OSV database if available
        if OSV_AVAILABLE and OSVDatabase:
            try:
                self.osv_db = OSVDatabase()
            except:
                self.osv_db = None
        else:
            self.osv_db = None
        
        self._load_cve_database()
    
    def _load_cve_database(self):
        """Load CVE database from JSON file."""
        # Try relative path first
        if not self.cve_db_path.exists():
            # Try absolute path from project root
            self.cve_db_path = Path(__file__).parent.parent.parent / "scanners" / "sca" / "local_cve_db.json"
        
        if self.cve_db_path.exists():
            try:
                with open(self.cve_db_path, 'r', encoding='utf-8') as f:
                    self.cve_database = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[!] Warning: Could not load CVE database: {e}")
                self.cve_database = {}
        else:
            # Initialize with empty database
            self.cve_database = {}
            print("[!] Warning: CVE database not found. SCA scanning will be limited.")
    
    def match(self, dependencies: List[Dict]) -> List[Dict]:
        """
        Match dependencies against CVE database and online sources.
        
        Args:
            dependencies: List of dependency dictionaries
        
        Returns:
            List of vulnerability matches
        """
        vulnerabilities = []
        
        for dep in dependencies:
            # Ensure package is a string
            package_raw = dep.get('package', '')
            package = str(package_raw).lower() if package_raw else ''
            version = dep.get('version', '')
            source = dep.get('source', 'requirements.txt')
            
            # Determine ecosystem
            ecosystem = 'pip'
            if 'package.json' in source:
                ecosystem = 'npm'
            elif 'pom.xml' in source:
                ecosystem = 'maven'
            
            # First check local database
            if package in self.cve_database:
                package_vulns = self.cve_database[package]
                
                for vuln in package_vulns:
                    if self._is_version_vulnerable(version, vuln.get('affected_versions', [])):
                        vulnerabilities.append({
                            'package': package,
                            'version': version,
                            'cve_id': vuln.get('cve_id', 'UNKNOWN'),
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'description': vuln.get('description', ''),
                            'fixed_version': vuln.get('fixed_version', 'latest'),
                            'affected_versions': vuln.get('affected_versions', []),
                            'source': 'local_db'
                        })
            
            # Check OSV database first (fastest, offline)
            if self.osv_db:
                try:
                    # Map ecosystem names
                    osv_ecosystem = ecosystem.upper()
                    if ecosystem == 'pip':
                        osv_ecosystem = 'PyPI'
                    elif ecosystem == 'npm':
                        osv_ecosystem = 'npm'
                    elif ecosystem == 'maven':
                        osv_ecosystem = 'Maven'
                    
                    osv_vulns = self.osv_db.query_vulnerabilities(osv_ecosystem, package, version)
                    
                    for vuln in osv_vulns:
                        vulnerabilities.append({
                            'package': package,
                            'version': version,
                            'cve_id': vuln.get('cve_id', 'UNKNOWN'),
                            'severity': vuln.get('severity', 'MEDIUM'),
                            'description': vuln.get('description', ''),
                            'fixed_version': vuln.get('fixed_versions', ['latest'])[0] if vuln.get('fixed_versions') else 'latest',
                            'affected_versions': vuln.get('affected_ranges', []),
                            'source': 'osv_db'
                        })
                except Exception as e:
                    pass  # Fallback to other sources
            
            # Fetch from online sources if enabled (fallback)
            if self.use_online and self.cve_fetcher:
                try:
                    online_vulns = self.cve_fetcher.fetch_vulnerabilities(package, version, ecosystem)
                    
                    for vuln in online_vulns:
                        # Check if version is affected
                        if self._is_version_affected(version, vuln.get('affected_versions', [])):
                            vulnerabilities.append({
                                'package': package,
                                'version': version,
                                'cve_id': vuln.get('cve_id', 'UNKNOWN'),
                                'severity': vuln.get('severity', 'MEDIUM'),
                                'description': vuln.get('description', ''),
                                'fixed_version': vuln.get('fixed_version', 'latest'),
                                'affected_versions': vuln.get('affected_versions', []),
                                'source': 'online'
                            })
                except Exception as e:
                    print(f"[!] Error fetching online CVE data for {package}: {e}")
        
        # Deduplicate by CVE ID
        seen_cves = set()
        unique_vulns = []
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve_id', '')
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulns.append(vuln)
        
        return unique_vulns
    
    def _is_version_affected(self, version: str, affected_ranges: List[str]) -> bool:
        """Check if version is in affected ranges using semantic versioning."""
        if not version or version == 'latest':
            return False
        
        # Use semantic version matching
        for range_str in affected_ranges:
            if is_version_affected(version, range_str):
                return True
        
        return False
    
    def _is_version_vulnerable(self, version: str, affected_versions: List[str]) -> bool:
        """
        Check if a version is in the affected versions list using semantic versioning.
        
        Args:
            version: Version to check
            affected_versions: List of affected version patterns or ranges
        
        Returns:
            True if version is vulnerable
        """
        if not version or version == 'latest':
            return False
        
        # Use semantic version matching
        try:
            v = Version(version)
            for affected in affected_versions:
                # Check if it's a range or exact version
                if any(op in affected for op in ['>=', '<=', '<', '>', '^', '~', '*']):
                    if is_version_affected(version, affected):
                        return True
                else:
                    # Exact version match
                    try:
                        affected_v = Version(affected)
                        if v == affected_v:
                            return True
                    except:
                        # Fallback to string matching for non-semantic versions
                        if version in affected or affected in version:
                            return True
        except:
            # Fallback to string matching if version parsing fails
            for affected in affected_versions:
                if version in affected or affected in version:
                    return True
        
        return False

