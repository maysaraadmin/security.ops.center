"""
Environment variable utilities and validation.
"""
import os
import re
from typing import Any, Dict, List, Optional, Type, TypeVar, Union
from pathlib import Path
from pydantic import BaseModel, ValidationError, validator
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

# Load environment variables from .env file if it exists
load_dotenv()

class EnvConfig(BaseModel):
    """Base class for environment variable configurations."""
    
    class Config:
        extra = 'forbid'  # Forbid extra fields
        validate_assignment = True
    
    @classmethod
    def from_env(cls, prefix: str = '') -> 'EnvConfig':
        """Create an instance from environment variables with the given prefix."""
        prefix = prefix.upper()
        if prefix and not prefix.endswith('_'):
            prefix += '_'
            
        env_vars = {}
        for field in cls.__fields__.values():
            env_name = f"{prefix}{field.name.upper()}"
            if env_name in os.environ:
                env_vars[field.name] = os.environ[env_name]
                
        return cls(**env_vars)

# Example configuration classes
class DatabaseConfig(EnvConfig):
    """Database configuration."""
    host: str = 'localhost'
    port: int = 5432
    name: str = 'edr'
    user: str = 'postgres'
    password: str = ''
    
    @property
    def uri(self) -> str:
        """Get the database connection URI."""
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

class ServerConfig(EnvConfig):
    """Server configuration."""
    host: str = '0.0.0.0'
    port: int = 5000
    debug: bool = False
    secret_key: str = 'dev-secret-key'
    
    @validator('secret_key')
    def validate_secret_key(cls, v: str) -> str:
        """Validate that the secret key is not the default in production."""
        if v == 'dev-secret-key' and os.getenv('FLASK_ENV') == 'production':
            raise ValueError('SECRET_KEY must be set in production')
        return v

class LoggingConfig(EnvConfig):
    """Logging configuration."""
    level: str = 'INFO'
    format: str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    file: Optional[str] = None
    max_size: int = 10  # MB
    backup_count: int = 5

class SecurityConfig(EnvConfig):
    """Security configuration."""
    password_hash_algorithm: str = 'sha256'
    password_salt_rounds: int = 10
    jwt_secret_key: str = 'dev-jwt-secret'
    jwt_access_token_expires: int = 3600  # 1 hour
    cors_allowed_origins: List[str] = ['*']
    rate_limit: str = '1000 per day;100 per hour'

class EmailConfig(EnvConfig):
    """Email configuration."""
    server: str = ''
    port: int = 587
    use_tls: bool = True
    username: str = ''
    password: str = ''
    default_sender: str = ''
    
    @property
    def is_configured(self) -> bool:
        """Check if email is configured."""
        return all([self.server, self.port, self.default_sender])

class FeatureFlags(EnvConfig):
    """Feature flags."""
    enable_edr: bool = True
    enable_siem: bool = True
    enable_nips: bool = False
    enable_compliance: bool = False

class PathsConfig(EnvConfig):
    """Path configurations."""
    base: str = str(Path(__file__).parent.parent.parent)
    data: str = ''
    logs: str = ''
    rules: str = ''
    temp: str = ''
    
    def __init__(self, **data):
        """Initialize paths with default values relative to base if not set."""
        base = Path(data.get('base', self.base)).resolve()
        
        # Set default paths if not provided
        if 'data' not in data:
            data['data'] = str(base / 'data')
        if 'logs' not in data:
            data['logs'] = str(base / 'logs')
        if 'rules' not in data:
            data['rules'] = str(base / 'config' / 'rules')
        if 'temp' not in data:
            data['temp'] = str(base / 'tmp')
            
        super().__init__(**data)
        
        # Ensure all directories exist
        for path in [self.data, self.logs, self.rules, self.temp]:
            Path(path).mkdir(parents=True, exist_ok=True)

class AppConfig(EnvConfig):
    """Main application configuration."""
    env: str = 'production'
    debug: bool = False
    testing: bool = False
    secret_key: str = 'dev-secret-key'
    
    # Sub-configurations
    database: DatabaseConfig = DatabaseConfig()
    server: ServerConfig = ServerConfig()
    logging: LoggingConfig = LoggingConfig()
    security: SecurityConfig = SecurityConfig()
    email: EmailConfig = EmailConfig()
    features: FeatureFlags = FeatureFlags()
    paths: PathsConfig = PathsConfig()
    
    @classmethod
    def load(cls) -> 'AppConfig':
        """Load configuration from environment variables."""
        # Load sub-configurations
        config = {
            'database': DatabaseConfig.from_env('DB').dict(),
            'server': ServerConfig.from_env('SERVER').dict(),
            'logging': LoggingConfig.from_env('LOGGING').dict(),
            'security': SecurityConfig.from_env('SECURITY').dict(),
            'email': EmailConfig.from_env('EMAIL').dict(),
            'features': FeatureFlags.from_env('FEATURE').dict(),
        }
        
        # Load main config
        main_config = {}
        for field in cls.__fields__.values():
            if field.name.upper() in os.environ:
                main_config[field.name] = os.environ[field.name.upper()]
        
        # Update with environment variables
        config.update(main_config)
        
        # Handle boolean values
        for key, value in config.items():
            if isinstance(value, str):
                if value.lower() in ('true', 't', 'yes', 'y', '1'):
                    config[key] = True
                elif value.lower() in ('false', 'f', 'no', 'n', '0'):
                    config[key] = False
        
        return cls(**config)

# Global configuration instance
app_config = AppConfig.load()

def get_config() -> AppConfig:
    """Get the global configuration instance."""
    return app_config

def validate_environment() -> Dict[str, List[str]]:
    """Validate the environment configuration.
    
    Returns:
        Dict with 'warnings' and 'errors' lists.
    """
    result = {'warnings': [], 'errors': []}
    
    # Check secret key in production
    if app_config.env == 'production' and app_config.secret_key == 'dev-secret-key':
        result['errors'].append('SECRET_KEY must be set in production')
    
    # Check email configuration if needed
    if app_config.email.is_configured:
        if not app_config.email.password:
            result['warnings'].append('Email password is not set. Email sending may not work.')
    
    # Check required directories
    for name, path in [
        ('Data', app_config.paths.data),
        ('Logs', app_config.paths.logs),
        ('Rules', app_config.paths.rules),
        ('Temp', app_config.paths.temp),
    ]:
        if not os.path.exists(path):
            result['warnings'].append(f"{name} directory does not exist: {path}")
    
    return result
