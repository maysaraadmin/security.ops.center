"""Centralized logging configuration for the SIEM system."""
import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

# Logging formats
SIMPLE_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
DETAILED_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]"

# Log levels as strings to level mapping
LOG_LEVELS = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

def setup_logging(
    log_level: str = 'INFO',
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    detailed: bool = True,  # Changed to True to get detailed logs by default
    force_single_log: bool = True  # Force all logs to a single file
) -> None:
    """Configure logging for the application.
    
    Args:
        log_level: Logging level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file. If None, logs only to console.
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup log files to keep
        detailed: Whether to include detailed information (filename, line number)
    
    Raises:
        ValueError: If log_level is invalid
        IOError: If log file cannot be created or written to
    """
    # Set default log file path if not provided
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'logs')
    os.makedirs(log_dir, exist_ok=True)
    
    # Always use siem.log as the main log file
    main_log_file = os.path.join(log_dir, 'siem.log')
    
    # If force_single_log is True, redirect all logs to the main log file
    if force_single_log:
        log_file = main_log_file
        
        # Clean up other log files
        for f in os.listdir(log_dir):
            if f.endswith('.log') and f != 'siem.log':
                try:
                    os.remove(os.path.join(log_dir, f))
                    print(f"Removed old log file: {f}", file=sys.stderr)
                except Exception as e:
                    print(f"Warning: Could not remove old log file {f}: {e}", file=sys.stderr)
    elif log_file is None:
        log_file = main_log_file
        
    try:
        # Convert string log level to logging constant
        level = LOG_LEVELS.get(log_level.upper())
        if level is None:
            raise ValueError(f"Invalid log level: {log_level}. Must be one of: {', '.join(LOG_LEVELS.keys())}")
            
        format_str = DETAILED_FORMAT if detailed else SIMPLE_FORMAT
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        
        # Clear any existing handlers
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
                root_logger.removeHandler(handler)
            except Exception as e:
                print(f"Error removing existing log handler: {e}", file=sys.stderr)
        
        # Create console handler with error handling (only in development)
        if os.environ.get('SIEM_DEV_MODE', '').lower() in ('1', 'true', 'yes'):
            try:
                console = logging.StreamHandler()
                console.setLevel(level)
                console.setFormatter(logging.Formatter(format_str))
                root_logger.addHandler(console)
            except Exception as e:
                print(f"Failed to set up console logging: {e}", file=sys.stderr)
        
        # Create file handler if log file is specified
        if log_file:
            try:
                # Ensure log directory exists
                log_dir = os.path.dirname(log_file)
                if log_dir:
                    os.makedirs(log_dir, exist_ok=True)
                
                # Create the log file if it doesn't exist
                if not os.path.exists(log_file):
                    with open(log_file, 'a'):
                        os.utime(log_file, None)
                else:
                    # Truncate existing log file to ensure we're starting fresh
                    with open(log_file, 'w'):
                        pass
                
                # Set up rotating file handler
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file, 
                    maxBytes=max_bytes, 
                    backupCount=backup_count, 
                    encoding='utf-8',
                    delay=True  # Don't open the file until it's actually needed
                )
                file_handler.setLevel(level)
                file_handler.setFormatter(logging.Formatter(format_str))
                root_logger.addHandler(file_handler)
                
                # Windows-specific: Add NT Event Log handler if running on Windows
                if sys.platform == 'win32':
                    try:
                        from logging.handlers import NTEventLogHandler
                        nt_handler = NTEventLogHandler('SIEM')
                        nt_handler.setLevel(logging.ERROR)  # Only log errors to Windows Event Log
                        nt_handler.setFormatter(logging.Formatter('%(name)s: %(message)s'))
                        root_logger.addHandler(nt_handler)
                    except ImportError:
                        root_logger.warning("NT Event Log handler not available")
                    except Exception as e:
                        root_logger.warning(f"Failed to set up Windows Event Log handler: {e}")
                
            except PermissionError as e:
                msg = f"Permission denied when setting up log file '{log_file}': {e}"
                if sys.platform == 'win32':
                    msg += "\nTry running the application as Administrator or choose a different log location."
                root_logger.error(msg)
                
            except Exception as e:
                root_logger.error(f"Failed to set up file logging: {e}")
        
        # If no handlers were set up, add a basic console handler as fallback
        if not root_logger.handlers:
            try:
                logging.basicConfig(level=level, format=format_str)
            except Exception as e:
                print(f"Critical: Failed to set up basic logging: {e}", file=sys.stderr)
        
        # Log the logging configuration
        root_logger.info(f"Logging initialized at level {logging.getLevelName(level)}")
        if log_file:
            root_logger.info(f"Log file: {os.path.abspath(log_file)}")
        
        # Add exception hook to log unhandled exceptions
        def handle_exception(exc_type, exc_value, exc_traceback):
            if issubclass(exc_type, KeyboardInterrupt):
                # Call the default handler for KeyboardInterrupt
                sys.__excepthook__(exc_type, exc_value, exc_traceback)
                return
                
            root_logger.critical(
                "Unhandled exception",
                exc_info=(exc_type, exc_value, exc_traceback)
            )
            
            # For critical errors, also log to stderr if no console handler is present
            if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
                print(f"CRITICAL: Unhandled exception: {exc_value}", file=sys.stderr)
        
        sys.excepthook = handle_exception
        
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('sqlalchemy').setLevel(logging.WARNING)
        logging.getLogger('matplotlib').setLevel(logging.WARNING)
        
        # Log configuration
        logger = logging.getLogger(__name__)
        logger.info("Logging configured with level: %s", log_level)
        if log_file:
            logger.info("Logging to file: %s", os.path.abspath(log_file))
    except Exception as e:
        print(f"Critical error setting up logging: {e}", file=sys.stderr)
        # Fall back to basic logging if all else fails
        logging.basicConfig(level=logging.INFO, format=SIMPLE_FORMAT)
        logging.error("Failed to set up custom logging: %s", str(e))


def get_logger(name: str) -> logging.Logger:
    """Get a logger with the given name.
    
    This is a convenience function that ensures consistent logger naming.
    """
    return logging.getLogger(f'siem.{name}')


class LoggingContext:
    """Context manager for temporary logging configuration."""
    def __init__(
        self,
        logger: logging.Logger,
        level: Optional[int] = None,
        handler: Optional[logging.Handler] = None,
        close: bool = True
    ):
        self.logger = logger
        self.level = level
        self.handler = handler
        self.close = close
        self.old_level = None

    def __enter__(self):
        if self.level is not None:
            self.old_level = self.logger.level
            self.logger.setLevel(self.level)
        if self.handler:
            self.logger.addHandler(self.handler)
        return self

    def __exit__(self, et, ev, tb):
        if self.level is not None and self.old_level is not None:
            self.logger.setLevel(self.old_level)
        if self.handler:
            self.logger.removeHandler(self.handler)
        if self.handler and self.close:
            self.handler.close()
        # implicit return of None => don't suppress exceptions
