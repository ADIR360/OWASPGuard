"""
Centralized error handling and logging for OWASPGuard
"""
import traceback
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from functools import wraps

class ErrorHandler:
    """
    Centralized error handling and logging for OWASPGuard
    
    Features:
    - Structured logging
    - Error categorization
    - Recovery strategies
    - User-friendly error messages
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger('OWASPGuard')
        logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        logger.handlers = []
        
        # File handler
        log_file = self.log_dir / f"owaspguard_{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def handle_scan_error(self, error: Exception, file_path: str, 
                         scanner_name: str) -> Dict[str, Any]:
        """
        Handle scanning errors gracefully
        
        Returns:
            Error report dict
        """
        error_type = type(error).__name__
        
        self.logger.error(
            f"Error in {scanner_name} while scanning {file_path}: "
            f"{error_type}: {str(error)}"
        )
        
        # Log full traceback to file only
        self.logger.debug(traceback.format_exc())
        
        return {
            'error': True,
            'error_type': error_type,
            'error_message': str(error),
            'file': file_path,
            'scanner': scanner_name,
            'timestamp': datetime.now().isoformat(),
            'user_message': self._get_user_friendly_message(error_type)
        }
    
    def _get_user_friendly_message(self, error_type: str) -> str:
        """Get user-friendly error message"""
        messages = {
            'FileNotFoundError': 'File not found. Please check the path.',
            'PermissionError': 'Permission denied. Please check file permissions.',
            'UnicodeDecodeError': 'Unable to read file. File may be binary or use unsupported encoding.',
            'SyntaxError': 'Invalid Python syntax. Skipping file.',
            'MemoryError': 'Out of memory. Try scanning smaller files or directories.',
            'TimeoutError': 'Scan timed out. File may be too large.',
        }
        
        return messages.get(error_type, 'An unexpected error occurred.')
    
    def safe_scan(self, func):
        """
        Decorator for safe scanning with automatic error handling
        
        Usage:
            @error_handler.safe_scan
            def scan_file(file_path):
                # scanning code
        """
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Extract file path from args if available
                file_path = args[0] if args else 'unknown'
                
                error_report = self.handle_scan_error(
                    e, 
                    str(file_path), 
                    func.__name__
                )
                
                # Return empty findings list with error info
                return {'findings': [], 'error': error_report}
        
        return wrapper


# Global error handler instance
error_handler = ErrorHandler()

