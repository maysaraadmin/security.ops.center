import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from datetime import datetime, timedelta


class LogSeverity(Enum):
    """Enumeration of log severity levels."""
    DEBUG = 0
    INFO = 1
    NOTICE = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5
    ALERT = 6
    EMERGENCY = 7

class SIEMAgent:
    def __init__(self, config_path='agent_config.json'):
        self.config = self._load_config(config_path)
        self.running = False
        self.start_time = None
        self.log_file = Path(self.config.get('log_file', 'siem_agent.log'))
        self._setup_logging()
        self.logger = logging.getLogger('SIEMAgent')
        
    def _setup_logging(self):
        """Configure logging to file."""
        try:
            # Ensure log directory exists
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create log file if it doesn't exist
            if not self.log_file.exists():
                self.log_file.touch()
            
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                filename=str(self.log_file),
                filemode='a'
            )
        except Exception as e:
            # Fallback to console logging if file logging fails
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s'
            )
            logging.error(f"Failed to setup file logging: {e}")
        
    def _load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                # Create default config file if it doesn't exist
                default_config = {
                    'log_file': 'siem_agent.log',
                    'log_level': 'INFO',
                    'heartbeat_interval': 60,
                    'siem_server': 'localhost',
                    'siem_port': 5000,
                    'agent_id': f"agent_{int(time.time())}"
                }
                
                # Ensure config directory exists
                config_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                
                return default_config
            
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Ensure required config keys exist with defaults
            config.setdefault('log_file', 'siem_agent.log')
            config.setdefault('log_level', 'INFO')
            config.setdefault('heartbeat_interval', 60)
            config.setdefault('siem_server', 'localhost')
            config.setdefault('siem_port', 5000)
            config.setdefault('agent_id', f"agent_{int(time.time())}")
            
            return config
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in config file: {e}")
            return self._get_default_config()
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return self._get_default_config()
    
    def _get_default_config(self):
        """Get default configuration values."""
        return {
            'log_file': 'siem_agent.log',
            'log_level': 'INFO',
            'heartbeat_interval': 60,
            'siem_server': 'localhost',
            'siem_port': 5000,
            'agent_id': f"agent_{int(time.time())}"
        }
            
    def start(self):
        """Start the agent and log the event."""
        self.running = True
        self.start_time = datetime.now()
        self.logger.info("SIEM Agent started")
        
    def stop(self):
        """Stop the agent and log the event."""
        if self.running:
            self.running = False
            self.logger.info("SIEM Agent stopped")
        
    def get_status(self):
        """Get current agent status and metrics."""
        try:
            uptime = str(datetime.now() - self.start_time).split('.')[0] if self.start_time else '0:00:00'
            
            # Safe access to logger with fallback
            try:
                log_level = logging.getLevelName(self.logger.getEffectiveLevel())
            except Exception:
                log_level = 'INFO'
            
            return {
                'status': 'running' if self.running else 'stopped',
                'version': '1.0.0',
                'uptime': uptime,
                'last_heartbeat': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'log_file': str(self.log_file.absolute()),
                'log_level': log_level
            }
        except Exception as e:
            # Return basic status if anything fails
            return {
                'status': 'error',
                'version': '1.0.0',
                'uptime': '0:00:00',
                'last_heartbeat': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'log_file': 'unknown',
                'log_level': 'ERROR',
                'error': str(e)
            }
        
    def log(self, level, message):
        """Log a message with the specified level."""
        try:
            level = level.upper()
            if hasattr(logging, level):
                log_level = getattr(logging, level)
                self.logger.log(log_level, message)
            else:
                self.logger.warning(f"Invalid log level: {level}. Message: {message}")
        except Exception as e:
            # Fallback to print if logging fails
            print(f"LOG ERROR: {e} - Original message: {level} - {message}")
            
    def get_logs(self, last_position=0, max_lines=100):
        """
        Get logs from the log file.
        
        Args:
            last_position: Position in the file to start reading from
            max_lines: Maximum number of lines to return
            
        Returns:
            tuple: (new_position, list of log entries)
        """
        # Validate inputs
        if last_position < 0:
            last_position = 0
        if max_lines <= 0:
            max_lines = 100
        
        try:
            if not self.log_file.exists():
                return 0, []
            
            # Check if file is readable
            if not os.access(self.log_file, os.R_OK):
                self.logger.error(f"Log file not readable: {self.log_file}")
                return 0, []
            
            # Get file size to validate position
            file_size = self.log_file.stat().st_size
            if last_position > file_size:
                last_position = 0  # Reset to beginning if position is beyond file size
            
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_position)
                lines = []
                for _ in range(max_lines):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line.strip())
                return f.tell(), lines
        except Exception as e:
            try:
                self.logger.error(f"Error reading log file: {e}")
            except Exception:
                print(f"LOG ERROR: Error reading log file: {e}")
            return last_position, []
