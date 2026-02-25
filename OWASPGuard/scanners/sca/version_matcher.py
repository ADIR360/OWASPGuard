"""
Semantic versioning parser and matcher for accurate CVE version matching.
Replaces simple string matching with proper semantic version comparison.
"""
import re
from typing import Tuple, Optional
from functools import total_ordering


@total_ordering
class Version:
    """Semantic version implementation supporting major.minor.patch[-prerelease][+build]"""
    
    def __init__(self, version_str: str):
        self.original = version_str
        self.major, self.minor, self.patch, self.prerelease, self.build = self._parse(version_str)
    
    def _parse(self, v: str) -> Tuple[int, int, int, str, str]:
        """Parse semantic version string"""
        # Remove leading 'v' if present
        v = v.lstrip('vV')
        
        # Split build metadata
        if '+' in v:
            v, build = v.split('+', 1)
        else:
            build = ''
        
        # Split prerelease
        if '-' in v:
            v, prerelease = v.split('-', 1)
        else:
            prerelease = ''
        
        # Parse major.minor.patch
        parts = v.split('.')
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        
        return major, minor, patch, prerelease, build
    
    def __eq__(self, other):
        if not isinstance(other, Version):
            return False
        return (self.major, self.minor, self.patch, self.prerelease) == \
               (other.major, other.minor, other.patch, other.prerelease)
    
    def __lt__(self, other):
        if not isinstance(other, Version):
            return NotImplemented
        
        # Compare major.minor.patch
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        
        # No prerelease > has prerelease
        if not self.prerelease and other.prerelease:
            return False
        if self.prerelease and not other.prerelease:
            return True
        
        # Both have prerelease - lexicographic comparison
        return self.prerelease < other.prerelease
    
    def __str__(self):
        return self.original
    
    def __repr__(self):
        return f"Version('{self.original}')"


class VersionRange:
    """Parse and evaluate version range specifications"""
    
    def __init__(self, range_str: str):
        self.range_str = range_str.strip()
        self.constraints = self._parse_constraints()
    
    def _parse_constraints(self):
        """Parse version range into constraints
        
        Supports formats:
        - >=1.2.3,<2.0.0 (comma-separated)
        - >=1.2.3 <2.0.0 (space-separated)
        - ^1.2.3 (caret - compatible with)
        - ~1.2.3 (tilde - approximately equivalent)
        - 1.2.* (wildcard)
        - ==1.2.3 (exact)
        """
        constraints = []
        
        # Split by comma or space
        parts = re.split(r'[,\s]+', self.range_str)
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            # Caret range (^1.2.3 = >=1.2.3 <2.0.0)
            if part.startswith('^'):
                try:
                    v = Version(part[1:])
                    constraints.append(('>=', v))
                    constraints.append(('<', Version(f"{v.major + 1}.0.0")))
                except:
                    pass
            
            # Tilde range (~1.2.3 = >=1.2.3 <1.3.0)
            elif part.startswith('~'):
                try:
                    v = Version(part[1:])
                    constraints.append(('>=', v))
                    constraints.append(('<', Version(f"{v.major}.{v.minor + 1}.0")))
                except:
                    pass
            
            # Wildcard (1.2.* = >=1.2.0 <1.3.0)
            elif '*' in part:
                base = part.replace('.*', '').replace('*', '')
                try:
                    v = Version(base + '.0.0')
                    constraints.append(('>=', v))
                    if base.count('.') == 0:
                        constraints.append(('<', Version(f"{v.major + 1}.0.0")))
                    elif base.count('.') == 1:
                        constraints.append(('<', Version(f"{v.major}.{v.minor + 1}.0")))
                except:
                    pass
            
            # Standard operators
            else:
                match = re.match(r'([><=!]+)(.+)', part)
                if match:
                    op, ver = match.groups()
                    try:
                        constraints.append((op, Version(ver)))
                    except:
                        pass
                else:
                    # Bare version = exact match
                    try:
                        constraints.append(('==', Version(part)))
                    except:
                        pass
        
        return constraints
    
    def contains(self, version: Version) -> bool:
        """Check if version satisfies all constraints"""
        for op, constraint_version in self.constraints:
            if op == '==':
                if version != constraint_version:
                    return False
            elif op == '!=':
                if version == constraint_version:
                    return False
            elif op == '>':
                if not (version > constraint_version):
                    return False
            elif op == '>=':
                if not (version >= constraint_version):
                    return False
            elif op == '<':
                if not (version < constraint_version):
                    return False
            elif op == '<=':
                if not (version <= constraint_version):
                    return False
        
        return True


def is_version_affected(installed_version: str, affected_range: str) -> bool:
    """
    Check if installed version is affected by vulnerability
    
    Args:
        installed_version: Version string (e.g., "1.2.3")
        affected_range: Range specification (e.g., ">=1.0.0,<1.2.4")
    
    Returns:
        True if version is affected, False otherwise
    """
    try:
        version = Version(installed_version)
        version_range = VersionRange(affected_range)
        return version_range.contains(version)
    except Exception as e:
        # Fallback to string matching if parsing fails
        return installed_version in affected_range or affected_range in installed_version


# Unit tests
def test_version_comparison():
    """Test version comparison logic"""
    assert Version("1.2.3") < Version("1.2.4")
    assert Version("1.2.3") < Version("1.3.0")
    assert Version("2.0.0") > Version("1.9.9")
    assert Version("1.0.0-alpha") < Version("1.0.0")
    assert Version("1.0.0") == Version("1.0.0")
    print("✅ Version comparison tests passed")


def test_version_ranges():
    """Test version range matching"""
    assert is_version_affected("1.2.3", ">=1.0.0,<2.0.0") == True
    assert is_version_affected("2.0.0", ">=1.0.0,<2.0.0") == False
    assert is_version_affected("1.5.0", "^1.2.0") == True
    assert is_version_affected("2.0.0", "^1.2.0") == False
    assert is_version_affected("1.2.5", "~1.2.3") == True
    assert is_version_affected("1.3.0", "~1.2.3") == False
    print("✅ Version range tests passed")


if __name__ == '__main__':
    test_version_comparison()
    test_version_ranges()
    print("\n✅ All version matching tests passed!")

