"""
SIEM Configuration Module

This module handles the loading and validation of SIEM configuration.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, validator
from pydantic.types import FilePath, DirectoryPath

class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field("INFO", description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
    file: str = Field("siem.log", description="Log file path")
    max_size: int = Field(10, description="Maximum log file size in MB")
    backup_count: int = Field(5, description="Number of backup logs to keep")
    format: str = Field("%(asctime)s - %(name)s - %(levelname)s - %(message)s", 
                      description="Log message format")

class DatabaseConfig(BaseModel):
    """Database configuration."""
    url: str = Field(..., description="Database connection URL")
    pool_size: int = Field(5, description="Database connection pool size")
    max_overflow: int = Field(10, description="Maximum overflow for connection pool")
    echo: bool = Field(False, description="Enable SQL query logging")

class APIConfig(BaseModel):
    """API server configuration."""
    host: str = Field("0.0.0.0", description="Host to bind the API server to")
    port: int = Field(8000, description="Port to run the API server on")
    debug: bool = Field(False, description="Enable debug mode")
    secret_key: str = Field("your-secret-key-here", description="Secret key for session management")
    cors_origins: list[str] = Field(["*"], description="Allowed CORS origins")

class SIEMConfig(BaseModel):
    """Main SIEM configuration."""
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    database: DatabaseConfig
    api: APIConfig = Field(default_factory=APIConfig)
    plugins: list[str] = Field(default_factory=list, description="List of enabled plugins")
    
    @validator('plugins')
    def validate_plugins(cls, v):
        """Validate that all specified plugins exist."""
        for plugin in v:
            # Look for plugins in both the current directory and src/siem/plugins/
            plugin_paths = [
                os.path.join("plugins", f"{plugin}.py"),
                os.path.join("src", "siem", "plugins", f"{plugin}.py")
            ]
            
            if not any(os.path.exists(path) for path in plugin_paths):
                raise ValueError(f"Plugin {plugin} not found in plugins directories. Tried: {plugin_paths}")
                
            # Also ensure the plugin is importable
            try:
                __import__(f"src.siem.plugins.{plugin}")
            except ImportError as e:
                raise ValueError(f"Failed to import plugin {plugin}: {str(e)}")
        return v

def load_config(config_path: Optional[str] = None) -> SIEMConfig:
    """
    Load and validate configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file. If not provided, looks for 'config/siem.yaml'.
        
    Returns:
        SIEMConfig: Validated configuration object.
        
    Raises:
        FileNotFoundError: If the configuration file is not found.
        ValueError: If the configuration is invalid.
    """
    if config_path is None:
        config_path = "config/siem.yaml"
    
    # Convert to absolute path
    config_path = Path(config_path).absolute()
    
    if not config_path.exists():
        # Create default config if it doesn't exist
        default_config = SIEMConfig(
            database={"url": "sqlite:///siem.db"}
        )
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w') as f:
            yaml.dump(default_config.dict(exclude_unset=True), f, default_flow_style=False)
        print(f"Created default configuration at {config_path}")
        return default_config
    
    # Load and validate config
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f) or {}
    
    try:
        return SIEMConfig(**config_data)
    except Exception as e:
        raise ValueError(f"Invalid configuration: {str(e)}")
