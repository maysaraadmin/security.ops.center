import json
import logging
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
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=str(self.log_file),
            filemode='a'
        )
        
    def _load_config(self, config_path):
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            # Ensure required config keys exist
            config.setdefault('log_file', 'siem_agent.log')
            config.setdefault('log_level', 'INFO')
            config.setdefault('heartbeat_interval', 60)
            return config
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {}
            
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
        uptime = str(datetime.now() - self.start_time).split('.')[0] if self.start_time else '0:00:00'
        
        return {
            'status': 'running' if self.running else 'stopped',
            'version': '1.0.0',
            'uptime': uptime,
            'last_heartbeat': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'log_file': str(self.log_file.absolute()),
            'log_level': logging.getLevelName(self.logger.getEffectiveLevel())
        }
        
    def log(self, level, message):
        """Log a message with the specified level."""
        level = level.upper()
        if hasattr(logging, level):
            log_level = getattr(logging, level)
            self.logger.log(log_level, message)
        else:
            self.logger.warning(f"Invalid log level: {level}. Message: {message}")
            
    def get_logs(self, last_position=0, max_lines=100):
        """
        Get logs from the log file.
        
        Args:
            last_position: Position in the file to start reading from
            max_lines: Maximum number of lines to return
            
        Returns:
            tuple: (new_position, list of log entries)
        """
        if not self.log_file.exists():
            return 0, []
            
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                f.seek(last_position)
                lines = []
                for _ in range(max_lines):
                    line = f.readline()
                    if not line:
                        break
                    lines.append(line.strip())
                return f.tell(), lines
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
            return last_position, []
