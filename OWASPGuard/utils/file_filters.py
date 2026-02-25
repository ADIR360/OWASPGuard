"""
File filtering utilities for scanning.
"""
import mimetypes
from pathlib import Path


# Common binary file extensions
BINARY_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
    '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z',
    '.mp3', '.mp4', '.avi', '.mov', '.wmv',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
}

# Ignored directories
IGNORED_DIRS = {
    '.git', '.svn', '.hg', '.bzr',
    '__pycache__', 'node_modules', '.venv', 'venv', 'env',
    '.idea', '.vscode', '.vs', '.eclipse',
    'build', 'dist', 'target', 'bin', 'obj',
    '.pytest_cache', '.mypy_cache', '.tox'
}

# Ignored files
IGNORED_FILES = {
    '.DS_Store', 'Thumbs.db', '.gitignore', '.gitattributes'
}

# Allowed extensions by language
LANGUAGE_EXTENSIONS = {
    'python': {'.py', '.pyw', '.pyx'},
    'javascript': {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'},
    'java': {'.java', '.jsp', '.jspx'},
    'config': {'.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.env'}
}


def is_binary_file(file_path: Path) -> bool:
    """
    Check if a file is binary.
    
    Args:
        file_path: Path to file
    
    Returns:
        True if file appears to be binary
    """
    # Check extension
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    
    # Check MIME type
    mime_type, _ = mimetypes.guess_type(str(file_path))
    if mime_type and not mime_type.startswith('text'):
        return True
    
    # Try reading first bytes
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(512)
            # Check for null bytes (common in binary files)
            if b'\x00' in chunk:
                return True
            # Check for high percentage of non-text characters
            text_chars = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
            if len(chunk) > 0 and text_chars / len(chunk) < 0.7:
                return True
    except (IOError, PermissionError):
        return True
    
    return False


def is_ignored_file(file_name: str) -> bool:
    """
    Check if a file or directory should be ignored.
    
    Args:
        file_name: Name of file or directory
    
    Returns:
        True if file should be ignored
    """
    return file_name in IGNORED_FILES or file_name in IGNORED_DIRS


def get_allowed_extensions(languages: list) -> set:
    """
    Get allowed file extensions for given languages.
    
    Args:
        languages: List of language names
    
    Returns:
        Set of allowed file extensions
    """
    extensions = set()
    
    for lang in languages:
        if lang.lower() in LANGUAGE_EXTENSIONS:
            extensions.update(LANGUAGE_EXTENSIONS[lang.lower()])
    
    # Always include config files
    extensions.update(LANGUAGE_EXTENSIONS['config'])
    
    return extensions

