"""
Secure file loader for project scanning.
Handles file traversal, filtering, and memory-efficient reading.
"""
import os
import mimetypes
from pathlib import Path
from typing import List, Iterator, Set
from utils.file_filters import is_binary_file, is_ignored_file, get_allowed_extensions


class FileLoader:
    """Loads and filters project files for scanning."""
    
    # Maximum file size to scan (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024
    
    def __init__(self, project_path: str, languages: List[str] = None):
        """
        Initialize file loader.
        
        Args:
            project_path: Path to project directory
            languages: List of languages to scan (e.g., ['python', 'javascript'])
        """
        self.project_path = Path(project_path).resolve()
        self.languages = languages or ['python', 'javascript', 'java']
        self.allowed_extensions = get_allowed_extensions(self.languages)
    
    def get_files(self) -> Iterator[Path]:
        """
        Get all scannable files in the project.
        
        Yields:
            Path objects for each scannable file
        """
        if not self.project_path.exists():
            raise ValueError(f"Project path does not exist: {self.project_path}")
        
        if self.project_path.is_file():
            # Single file scan
            if self._is_scannable(self.project_path):
                yield self.project_path
            return
        
        # Directory scan
        for root, dirs, files in os.walk(self.project_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not is_ignored_file(d)]
            
            for file in files:
                file_path = Path(root) / file
                
                # Skip ignored files
                if is_ignored_file(file_path.name):
                    continue
                
                # Check if file is scannable
                if self._is_scannable(file_path):
                    yield file_path
    
    def _is_scannable(self, file_path: Path) -> bool:
        """
        Check if a file should be scanned.
        
        Args:
            file_path: Path to file
        
        Returns:
            True if file should be scanned
        """
        # Check file size
        try:
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return False
        except (OSError, PermissionError):
            return False
        
        # Check if binary
        if is_binary_file(file_path):
            return False
        
        # Check extension
        if file_path.suffix.lower() in self.allowed_extensions:
            return True
        
        # Check for specific config files
        config_files = {
            'requirements.txt', 'package.json', 'pom.xml',
            '.env', '.env.local', 'config.yaml', 'config.yml',
            'settings.py', 'config.py', 'docker-compose.yml'
        }
        
        if file_path.name.lower() in config_files:
            return True
        
        return False
    
    def read_file_lines(self, file_path: Path) -> Iterator[str]:
        """
        Read file line by line (memory efficient).
        
        Args:
            file_path: Path to file
        
        Yields:
            Lines from the file
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    yield line.rstrip('\n\r')
        except (UnicodeDecodeError, PermissionError, OSError):
            # Skip files that can't be read
            return
    
    def get_file_content(self, file_path: Path) -> str:
        """
        Read entire file content (use with caution for large files).
        
        Args:
            file_path: Path to file
        
        Returns:
            File content as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (UnicodeDecodeError, PermissionError, OSError):
            return ""

