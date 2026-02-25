"""
OSV (Open Source Vulnerabilities) database for offline CVE scanning.
Uses Google's OSV format for comprehensive vulnerability data.
"""
import json
import sqlite3
import gzip
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import requests

# Add project root to path for imports
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from scanners.sca.version_matcher import Version, is_version_affected


class OSVDatabase:
    """
    Lightweight CVE database using Google's OSV (Open Source Vulnerabilities) format
    
    Database schema optimized for fast lookups:
    - Indexes on package_name, ecosystem
    - Compressed JSON storage for full CVE details
    - Last-updated tracking for incremental updates
    """
    
    def __init__(self, db_path: str = "scanners/sca/osv.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._initialize_db()

        # Auto-populate OSV database on first use to improve SCA coverage.
        # This can take several minutes but greatly increases detection of
        # real-world CVEs across dependencies.
        try:
            stats = self.get_statistics()
            total = stats.get("total_vulnerabilities", 0)
            if total == 0:
                print("[*] OSV database empty – downloading vulnerability data (one-time, may take several minutes)...")
                # Default ecosystems: PyPI, npm, Maven
                self.update_from_osv(force=True)
        except Exception:
            # If OSV update fails for any reason, continue with an empty DB
            pass
    
    def _initialize_db(self):
        """Create database schema with indexes"""
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                severity TEXT,
                cvss_score REAL,
                affected_ranges TEXT,  -- JSON array
                fixed_versions TEXT,   -- JSON array
                published DATE,
                modified DATE,
                details_json TEXT,     -- Compressed full CVE data
                UNIQUE(ecosystem, package_name, id)
            )
        ''')
        
        # Critical indexes for performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_package 
            ON vulnerabilities(ecosystem, package_name)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_severity 
            ON vulnerabilities(severity)
        ''')
        
        # Metadata table for tracking updates
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def update_from_osv(self, ecosystems: List[str] = None, force: bool = False):
        """
        Download vulnerabilities from OSV database
        
        OSV provides pre-aggregated vulnerability data in ecosystem-specific files:
        https://osv-vulnerabilities.storage.googleapis.com/[ecosystem]/all.zip
        
        Args:
            ecosystems: List of ecosystems to update (default: PyPI, npm, Maven)
            force: Force update even if recently updated
        """
        if ecosystems is None:
            ecosystems = ['PyPI', 'npm', 'Maven']
        
        base_url = "https://osv-vulnerabilities.storage.googleapis.com"
        
        for ecosystem in ecosystems:
            # Check if update needed
            if not force and not self.needs_update(ecosystem):
                print(f"[*] {ecosystem} database is up to date, skipping...")
                continue
            
            print(f"[*] Updating {ecosystem} vulnerabilities...")
            
            try:
                # Download ecosystem-specific vulnerability bundle
                url = f"{base_url}/{ecosystem}/all.zip"
                response = requests.get(url, stream=True, timeout=60)
                
                if response.status_code == 200:
                    self._process_osv_bundle(ecosystem, response.content)
                    self._update_metadata(f"last_update_{ecosystem}", 
                                         datetime.now().isoformat())
                    print(f"[+] {ecosystem} update complete")
                else:
                    print(f"[!] Failed to download {ecosystem}: {response.status_code}")
            
            except Exception as e:
                print(f"[!] Error updating {ecosystem}: {e}")
    
    def _process_osv_bundle(self, ecosystem: str, zip_data: bytes):
        """Process downloaded OSV zip bundle"""
        import zipfile
        import io
        
        cursor = self.conn.cursor()
        count = 0
        
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for filename in zf.namelist():
                if not filename.endswith('.json'):
                    continue
                
                with zf.open(filename) as f:
                    try:
                        vuln = json.load(f)
                        self._insert_vulnerability(cursor, ecosystem, vuln)
                        count += 1
                        
                        if count % 100 == 0:
                            self.conn.commit()
                            print(f"  Processed {count} vulnerabilities...")
                    
                    except Exception as e:
                        pass  # Skip invalid entries
        
        self.conn.commit()
        print(f"  Inserted/updated {count} vulnerabilities")
    
    def _insert_vulnerability(self, cursor, ecosystem: str, vuln: Dict):
        """Insert or update vulnerability record"""
        vuln_id = vuln.get('id', '')
        if not vuln_id:
            return
        
        # Extract affected packages
        affected = vuln.get('affected', [])
        if not affected:
            return
        
        for pkg in affected:
            package_info = pkg.get('package', {})
            package_name = package_info.get('name', '')
            if not package_name:
                continue
            
            # Extract version ranges
            ranges = []
            for r in pkg.get('ranges', []):
                if r.get('type') == 'ECOSYSTEM':
                    events = []
                    for event in r.get('events', []):
                        events.append(event)
                    if events:
                        ranges.append(events)
            
            # Extract fixed versions
            fixed = pkg.get('versions', [])
            
            # Calculate severity
            severity, cvss_score = self._extract_severity(vuln)
            
            # Compress full details
            try:
                details_compressed = gzip.compress(json.dumps(vuln).encode())
            except:
                details_compressed = b''
            
            # Extract dates
            published = vuln.get('published', '')
            modified = vuln.get('modified', published)
            
            # Ensure package_name is a string
            package_name_str = str(package_name).lower() if package_name else ''
            
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities
                (id, ecosystem, package_name, severity, cvss_score, 
                 affected_ranges, fixed_versions, published, modified, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_id,
                ecosystem,
                package_name_str,  # Normalize to lowercase
                severity,
                cvss_score,
                json.dumps(ranges),
                json.dumps(fixed),
                published,
                modified,
                details_compressed
            ))
    
    def _extract_severity(self, vuln: Dict) -> tuple:
        """Extract severity rating and CVSS score"""
        # Try to get CVSS score
        cvss_score = None
        severity_items = vuln.get('severity', [])
        
        for item in severity_items:
            if item.get('type') == 'CVSS_V3':
                score_str = item.get('score', '')
                try:
                    cvss_score = float(score_str.split('/')[0])
                except:
                    pass
        
        # Map to severity levels
        if cvss_score:
            if cvss_score >= 9.0:
                severity = 'CRITICAL'
            elif cvss_score >= 7.0:
                severity = 'HIGH'
            elif cvss_score >= 4.0:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
        else:
            # Fallback to database-specific severity
            db_severity = vuln.get('database_specific', {}).get('severity', '')
            severity = db_severity.upper() if db_severity else 'MEDIUM'
        
        return severity, cvss_score
    
    def query_vulnerabilities(self, ecosystem: str, package_name: str, 
                            version: str) -> List[Dict]:
        """
        Query vulnerabilities for a specific package version
        
        Args:
            ecosystem: Package ecosystem (PyPI, npm, Maven, etc.)
            package_name: Package name
            version: Installed version
        
        Returns:
            List of matching vulnerabilities
        """
        # Ensure package_name is a string
        package_name_str = str(package_name).lower() if package_name else ''
        
        cursor = self.conn.cursor()
        
        cursor.execute('''
            SELECT id, severity, cvss_score, affected_ranges, 
                   fixed_versions, published, details_json
            FROM vulnerabilities
            WHERE ecosystem = ? AND package_name = ?
        ''', (ecosystem, package_name_str))
        
        results = []
        
        for row in cursor.fetchall():
            vuln_id = row['id']
            severity = row['severity']
            cvss_score = row['cvss_score']
            ranges_json = row['affected_ranges']
            fixed_json = row['fixed_versions']
            published = row['published']
            details_compressed = row['details_json']
            
            # Check if version is affected
            ranges = json.loads(ranges_json) if ranges_json else []
            if self._is_version_in_range(version, ranges):
                # Decompress full details if needed
                details = {}
                if details_compressed:
                    try:
                        details = json.loads(gzip.decompress(details_compressed))
                    except:
                        pass
                
                fixed_versions = json.loads(fixed_json) if fixed_json else []
                
                results.append({
                    'cve_id': vuln_id,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'fixed_versions': fixed_versions,
                    'published': published,
                    'description': details.get('summary', '') or details.get('details', ''),
                    'package': package_name,
                    'version': version,
                    'affected_ranges': ranges
                })
        
        return results
    
    def _is_version_in_range(self, version: str, ranges: List[List[Dict]]) -> bool:
        """Check if version falls within affected ranges"""
        if not ranges:
            return True  # If no ranges specified, assume all versions affected
        
        try:
            v = Version(version)
            
            for range_events in ranges:
                # Check if version is in any range
                introduced = None
                fixed = None
                
                for event in range_events:
                    if isinstance(event, dict):
                        if 'introduced' in event:
                            introduced = event['introduced']
                        if 'fixed' in event:
                            fixed = event['fixed']
                        if 'last_affected' in event:
                            fixed = event['last_affected']
                
                # Check if version is affected
                if introduced:
                    try:
                        intro_v = Version(introduced)
                        if v >= intro_v:
                            if fixed:
                                try:
                                    fixed_v = Version(fixed)
                                    if v < fixed_v:
                                        return True
                                except:
                                    pass
                            else:
                                return True
                    except:
                        pass
                elif fixed:
                    try:
                        fixed_v = Version(fixed)
                        if v < fixed_v:
                            return True
                    except:
                        pass
                else:
                    # No range info, assume affected
                    return True
            
            return False
        except:
            # Fallback: if we can't parse, assume not affected (conservative)
            return False
    
    def _update_metadata(self, key: str, value: str):
        """Update metadata table"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO metadata (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', (key, value, datetime.now()))
        self.conn.commit()
    
    def needs_update(self, ecosystem: str, max_age_days: int = 7) -> bool:
        """Check if ecosystem data needs updating"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT updated_at FROM metadata 
            WHERE key = ?
        ''', (f"last_update_{ecosystem}",))
        
        row = cursor.fetchone()
        if not row:
            return True
        
        try:
            last_update = datetime.fromisoformat(row['updated_at'])
            age = datetime.now() - last_update
            return age > timedelta(days=max_age_days)
        except:
            return True
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
        total = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT ecosystem, COUNT(*) 
            FROM vulnerabilities 
            GROUP BY ecosystem
        ''')
        by_ecosystem = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM vulnerabilities 
            GROUP BY severity
        ''')
        by_severity = dict(cursor.fetchall())
        
        return {
            'total_vulnerabilities': total,
            'by_ecosystem': by_ecosystem,
            'by_severity': by_severity
        }
    
    def close(self):
        """Close database connection"""
        self.conn.close()


# CLI for database management
if __name__ == '__main__':
    import sys
    
    db = OSVDatabase()
    
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        force = '--force' in sys.argv
        db.update_from_osv(force=force)
        print("\nDatabase Statistics:")
        stats = db.get_statistics()
        print(f"  Total vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"  By ecosystem: {stats['by_ecosystem']}")
        print(f"  By severity: {stats['by_severity']}")
    
    elif len(sys.argv) > 1 and sys.argv[1] == 'query':
        # Example: python osv_database.py query PyPI requests 2.25.0
        if len(sys.argv) < 5:
            print("Usage: python osv_database.py query <ecosystem> <package> <version>")
        else:
            ecosystem, package, version = sys.argv[2], sys.argv[3], sys.argv[4]
            vulns = db.query_vulnerabilities(ecosystem, package, version)
            print(f"\nFound {len(vulns)} vulnerabilities for {package} {version}")
            for v in vulns:
                print(f"  {v['cve_id']}: {v['severity']} (CVSS: {v.get('cvss_score', 'N/A')})")
    
    elif len(sys.argv) > 1 and sys.argv[1] == 'stats':
        stats = db.get_statistics()
        print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
        print(f"By ecosystem: {stats['by_ecosystem']}")
        print(f"By severity: {stats['by_severity']}")
    
    db.close()

