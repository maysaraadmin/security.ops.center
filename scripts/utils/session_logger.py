import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from datetime import datetime

class SessionLogger:
    """
    A logging utility that creates a new log file for each session.
    The log file is automatically cleaned at the start of each session.
    """
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SessionLogger, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.log_dir = Path("logs")
            self.log_dir.mkdir(exist_ok=True)
            self.log_file = self.log_dir / "session.log"
            self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging with a rotating file handler."""
        # Clear the log file at the start of each session
        if self.log_file.exists():
            self.log_file.unlink()
        
        # Create a logger
        self.logger = logging.getLogger('siem.session')
        self.logger.setLevel(logging.DEBUG)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Create file handler which logs debug messages
        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=1,  # Keep only one backup file
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        
        # Create console handler with a higher log level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        
        # Add the handlers to the logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Log session start
        self.logger.info("=" * 80)
        self.logger.info(f"SIEM Session Started - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.logger.info("=" * 80)
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """Get a logger instance with the specified name."""
        if name:
            return self.logger.getChild(name)
        return self.logger

# Create a singleton instance
session_logger = SessionLogger()

def get_logger(name: str = None) -> logging.Logger:
    """Get a logger instance with the specified name."""
    return session_logger.get_logger(name)
