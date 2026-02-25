"""
Dependency file parser.
Parses requirements.txt, package.json, pom.xml to extract dependencies.
"""
import re
import json
from pathlib import Path
from typing import List, Dict


class DependencyParser:
    """Parses dependency files to extract package information."""
    
    def parse(self, file_path: Path) -> List[Dict]:
        """
        Parse a dependency file.
        
        Args:
            file_path: Path to dependency file
        
        Returns:
            List of dependency dictionaries with name and version
        """
        if not file_path.exists():
            return []
        
        file_name = file_path.name.lower()
        
        if file_name == 'requirements.txt':
            return self._parse_requirements_txt(file_path)
        elif file_name == 'package.json':
            return self._parse_package_json(file_path)
        elif file_name == 'pom.xml':
            return self._parse_pom_xml(file_path)
        
        return []
    
    def _parse_requirements_txt(self, file_path: Path) -> List[Dict]:
        """Parse Python requirements.txt file."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Parse package==version or package>=version, etc.
                    # Format: package==1.2.3 or package>=1.2.3 or package~=1.2.3
                    match = re.match(r'^([a-zA-Z0-9_-]+(?:\[[^\]]+\])?)([<>=!~]+)?([0-9.]+)?', line)
                    if match:
                        package = match.group(1).split('[')[0]  # Remove extras like package[extra]
                        version = match.group(3) if match.group(3) else 'latest'
                        
                        dependencies.append({
                            'package': package.lower(),
                            'version': version,
                            'source': 'requirements.txt'
                        })
        except Exception as e:
            print(f"[!] Error parsing requirements.txt: {e}")
        
        return dependencies
    
    def _parse_package_json(self, file_path: Path) -> List[Dict]:
        """Parse Node.js package.json file."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Check dependencies and devDependencies
                for dep_type in ['dependencies', 'devDependencies']:
                    if dep_type in data:
                        for package, version_spec in data[dep_type].items():
                            # Extract version from version spec (e.g., "^1.2.3" -> "1.2.3")
                            version = re.sub(r'[\^~<>=\s]', '', version_spec)
                            
                            dependencies.append({
                                'package': package.lower(),
                                'version': version if version else 'latest',
                                'source': 'package.json'
                            })
        except (json.JSONDecodeError, KeyError) as e:
            print(f"[!] Error parsing package.json: {e}")
        
        return dependencies
    
    def _parse_pom_xml(self, file_path: Path) -> List[Dict]:
        """Parse Maven pom.xml file."""
        dependencies = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
                # Simple regex-based parsing (for basic cases)
                # In production, use proper XML parser
                pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
                matches = re.finditer(pattern, content, re.DOTALL)
                
                for match in matches:
                    group_id = match.group(1).strip()
                    artifact_id = match.group(2).strip()
                    version = match.group(3).strip()
                    
                    # Maven coordinates: groupId:artifactId
                    package = f"{group_id}:{artifact_id}"
                    
                    dependencies.append({
                        'package': package.lower(),
                        'version': version,
                        'source': 'pom.xml'
                    })
        except Exception as e:
            print(f"[!] Error parsing pom.xml: {e}")
        
        return dependencies

