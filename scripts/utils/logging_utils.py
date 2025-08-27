"""
Logging utilities for the SIEM system.

This module provides a centralized logging configuration and utilities for consistent
logging across all SIEM components.
"""
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any, Union
import json
import gzip
import time
from datetime import datetime

class GzipRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Rotating file handler that compresses log files with gzip."""
    
    def __init__(self, filename, **kwargs):
        """Initialize the handler."""
        self.compresslevel = kwargs.pop('compresslevel', 9)
        super().__init__(filename, **kwargs)
    
    def rotate(self, source, dest):
        ""
        Rotate the current log and compress it with gzip.
        
        Args:
            source: Source log file path
            dest: Destination path (without .gz extension)
        """
        super().rotate(source, dest)
        
        # Compress the rotated file
        with open(dest, 'rb') as f_in:
            with gzip.open(f"{dest}.gz", 'wb', compresslevel=self.compresslevel) as f_out:
                f_out.writelines(f_in)
        
        # Remove the uncompressed file
        try:
            os.remove(dest)
        except OSError:
            pass

def setup_logger(
    name: str,
    log_level: Union[int, str] = logging.INFO,
    log_file: Optional[Union[str, Path]] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    use_console: bool = True,
    json_format: bool = False
) -> logging.Logger:
    """
    Set up a logger with the specified configuration.
    
    Args:
        name: Logger name (usually __name__)
        log_level: Logging level (default: INFO)
        log_file: Path to the log file (optional)
        max_bytes: Maximum log file size before rotation (default: 10MB)
        backup_count: Number of backup logs to keep (default: 5)
        use_console: Whether to log to console (default: True)
        json_format: Whether to use JSON format for logs (default: False)
        
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Don't add handlers if they're already configured
    if logger.handlers:
        return logger
    
    logger.setLevel(log_level)
    
    # Create formatter
    if json_format:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    # Add console handler
    if use_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler if log file is specified
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = GzipRotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8',
            delay=True
        )
        
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

class JsonFormatter(logging.Formatter):
    """Log formatter that outputs logs in JSON format."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the specified record as JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',  # UTC time in ISO format
            'name': record.name,
            'level': record.levelname,
            'message': record.getMessage(),
            'process': record.process,
            'thread': record.thread,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields if present
        if hasattr(record, 'extra') and isinstance(record.extra, dict):
            log_entry.update(record.extra)
        
        return json.dumps(log_entry, ensure_ascii=False)

class RequestIdFilter(logging.Filter):
    """Log filter to add request ID to log records."""
    
    def __init__(self, request_id: str = None):
        """Initialize the filter with an optional request ID."""
        super().__init__()
        self.request_id = request_id
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add request_id to the log record if it exists."""
        if self.request_id:
            record.request_id = self.request_id
        return True

def log_execution_time(logger: logging.Logger, level: int = logging.DEBUG):
    ""
    Decorator to log the execution time of a function.
    
    Args:
        logger: Logger instance to use for logging
        level: Logging level to use (default: DEBUG)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            
            logger.log(
                level,
                f"Function {func.__name__} executed in {end_time - start_time:.4f} seconds",
                extra={
                    'function': func.__name__,
                    'execution_time': end_time - start_time,
                    'module': func.__module__
                }
            )
            return result
        return wrapper
    return decorator
