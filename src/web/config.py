"""
Web application configuration.
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional

from src.common.config import Config
from src.common.file_utils import fs

class WebConfig:
    """Web application configuration."""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize web configuration.
        
        Args:
            config: Optional Config instance. If not provided, a new one will be created.
        """
        self.config = config or Config()
        
        # Ensure required directories exist
        self._ensure_directories()
        
    def _ensure_directories(self) -> None:
        """Ensure required directories exist."""
        # Ensure log directory exists
        log_dir = Path(self.get('logging.file')).parent
        fs.ensure_dir(log_dir)
        
        # Ensure upload directory exists
        upload_dir = self.get('web.upload_dir', 'uploads')
        if upload_dir:
            fs.ensure_dir(upload_dir)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            key: Configuration key in dot notation (e.g., 'app.debug').
            default: Default value if key is not found.
            
        Returns:
            The configuration value or default if not found.
        """
        return self.config.get(key, default)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to a dictionary."""
        return {
            'app': {
                'env': self.get('app.env'),
                'debug': self.get('app.debug'),
                'secret_key': self.get('app.secret_key'),
                'host': self.get('app.host'),
                'port': self.get('app.port'),
            },
            'database': {
                'uri': self.get('database.uri'),
                'echo': self.get('database.echo'),
            },
            'security': {
                'password_hash_algorithm': self.get('security.password_hash_algorithm'),
                'password_salt_rounds': self.get('security.password_salt_rounds'),
                'jwt_secret_key': self.get('security.jwt_secret_key'),
                'jwt_access_token_expires': self.get('security.jwt_access_token_expires'),
                'cors_allowed_origins': self.get('security.cors_allowed_origins'),
                'rate_limit': self.get('security.rate_limit'),
            },
            'logging': {
                'level': self.get('logging.level'),
                'file': self.get('logging.file'),
                'format': self.get('logging.format'),
            },
            'web': {
                'upload_dir': self.get('web.upload_dir'),
                'session_lifetime': self.get('web.session_lifetime'),
                'max_upload_size': self.get('web.max_upload_size'),
            },
            'edr': {
                'enabled': self.get('edr.enabled'),
                'checkin_interval': self.get('edr.checkin_interval'),
                'max_offline_time': self.get('edr.max_offline_time'),
            },
        }

# Global configuration instance
web_config = WebConfig()

def get_web_config() -> WebConfig:
    """Get the global web configuration instance."""
    return web_config
