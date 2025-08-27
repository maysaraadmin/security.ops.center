"""
Configuration management for the EDR system.
Handles loading settings from environment variables and YAML config files.
"""
import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class Config:
    """Base configuration class that loads settings from environment variables and config files."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_path: Optional path to a YAML config file.
        """
        self._config: Dict[str, Any] = {}
        self._config_path = config_path or os.getenv('CONFIG_PATH', 'config/edr_config.yaml')
        self._load_config()
        
    def _load_config(self) -> None:
        """Load configuration from YAML file and environment variables."""
        # Default configuration
        self._config = {
            'app': {
                'env': os.getenv('FLASK_ENV', 'production'),
                'debug': self._str_to_bool(os.getenv('DEBUG', 'False')),
                'secret_key': os.getenv('SECRET_KEY', 'dev-secret-key'),
                'host': os.getenv('HOST', '0.0.0.0'),
                'port': int(os.getenv('PORT', '5000')),
            },
            'database': {
                'uri': os.getenv('DATABASE_URI', f'sqlite:///{BASE_DIR}/data/edr.db'),
                'echo': self._str_to_bool(os.getenv('SQL_ECHO', 'False')),
            },
            'paths': {
                'base': str(BASE_DIR),
                'data': os.getenv('DATA_DIR', str(BASE_DIR / 'data')),
                'logs': os.getenv('LOG_DIR', str(BASE_DIR / 'logs')),
                'rules': os.getenv('RULES_DIR', str(BASE_DIR / 'config' / 'rules')),
                'temp': os.getenv('TEMP_DIR', str(BASE_DIR / 'tmp')),
            },
            'edr': {
                'enabled': self._str_to_bool(os.getenv('ENABLE_EDR', 'True')),
                'checkin_interval': int(os.getenv('EDR_CHECKIN_INTERVAL', '300')),
                'max_offline_time': int(os.getenv('EDR_MAX_OFFLINE_TIME', '900')),
            },
            'logging': {
                'level': os.getenv('LOG_LEVEL', 'INFO'),
                'file': os.getenv('LOG_FILE', str(BASE_DIR / 'logs' / 'application.log')),
                'format': os.getenv('LOG_FORMAT', 
                                 '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            },
            'security': {
                'password_hash_method': os.getenv('PASSWORD_HASH_METHOD', 'sha256'),
                'password_salt_rounds': int(os.getenv('PASSWORD_SALT_ROUNDS', '10')),
                'jwt_secret_key': os.getenv('JWT_SECRET_KEY', 'change-this-in-production'),
                'jwt_access_token_expires': int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600')),
            },
            'email': {
                'server': os.getenv('MAIL_SERVER', ''),
                'port': int(os.getenv('MAIL_PORT', '587')),
                'use_tls': self._str_to_bool(os.getenv('MAIL_USE_TLS', 'True')),
                'username': os.getenv('MAIL_USERNAME', ''),
                'password': os.getenv('MAIL_PASSWORD', ''),
                'default_sender': os.getenv('MAIL_DEFAULT_SENDER', ''),
            },
            'api_keys': {
                'virustotal': os.getenv('VIRUS_TOTAL_API_KEY', ''),
                'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
            },
            'features': {
                'enable_siem': self._str_to_bool(os.getenv('ENABLE_SIEM', 'True')),
                'enable_nips': self._str_to_bool(os.getenv('ENABLE_NIPS', 'False')),
                'enable_compliance': self._str_to_bool(os.getenv('ENABLE_COMPLIANCE', 'False')),
            }
        }
        
        # Load YAML config if it exists
        if self._config_path and os.path.exists(self._config_path):
            with open(self._config_path, 'r') as f:
                yaml_config = yaml.safe_load(f) or {}
                self._deep_update(self._config, yaml_config)
    
    def _deep_update(self, original: Dict, update: Dict) -> None:
        """Recursively update a dictionary."""
        for key, value in update.items():
            if key in original and isinstance(original[key], dict) and isinstance(value, dict):
                self._deep_update(original[key], value)
            else:
                original[key] = value
    
    @staticmethod
    def _str_to_bool(value: str) -> bool:
        """Convert a string to a boolean."""
        return value.lower() in ('true', '1', 't', 'y', 'yes')
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot notation."""
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def __getitem__(self, key: str) -> Any:
        """Get a configuration value using bracket notation."""
        return self.get(key)
    
    def __contains__(self, key: str) -> bool:
        """Check if a configuration key exists."""
        try:
            self.get(key)
            return True
        except KeyError:
            return False

# Global configuration instance
config = Config()

def get_config() -> Config:
    """Get the global configuration instance."""
    return config
