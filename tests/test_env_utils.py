""
Tests for the env_utils module.
"""
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.common.env_utils import (
    DatabaseConfig,
    ServerConfig,
    LoggingConfig,
    SecurityConfig,
    EmailConfig,
    FeatureFlags,
    PathsConfig,
    AppConfig,
    validate_environment
)

class TestEnvConfigs:
    """Tests for environment configuration classes."""
    
    def test_database_config_defaults(self):
        ""Test DatabaseConfig default values."""
        config = DatabaseConfig()
        assert config.host == 'localhost'
        assert config.port == 5432
        assert config.name == 'edr'
        assert config.user == 'postgres'
        assert config.password == ''
        assert config.uri == 'postgresql://postgres:@localhost:5432/edr'
        
    def test_database_config_from_env(self):
        ""Test loading DatabaseConfig from environment variables."""
        env_vars = {
            'DB_HOST': 'db.example.com',
            'DB_PORT': '5433',
            'DB_NAME': 'testdb',
            'DB_USER': 'testuser',
            'DB_PASSWORD': 'testpass'
        }
        
        with patch.dict(os.environ, env_vars):
            config = DatabaseConfig.from_env('DB')
            
        assert config.host == 'db.example.com'
        assert config.port == 5433
        assert config.name == 'testdb'
        assert config.user == 'testuser'
        assert config.password == 'testpass'
        assert config.uri == 'postgresql://testuser:testpass@db.example.com:5433/testdb'
        
    def test_server_config_defaults(self):
        ""Test ServerConfig default values."""
        config = ServerConfig()
        assert config.host == '0.0.0.0'
        assert config.port == 5000
        assert config.debug is False
        assert config.secret_key == 'dev-secret-key'
        
    def test_server_config_secret_key_validation(self):
        ""Test secret key validation in production."""
        with patch.dict(os.environ, {'FLASK_ENV': 'production'}):
            with pytest.raises(ValueError):
                ServerConfig()  # Should raise because of default secret key
                
            # Should not raise with custom secret key
            config = ServerConfig(secret_key='custom-secret-key')
            assert config.secret_key == 'custom-secret-key'
            
    def test_logging_config_defaults(self):
        ""Test LoggingConfig default values."""
        config = LoggingConfig()
        assert config.level == 'INFO'
        assert config.format == '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        assert config.file is None
        assert config.max_size == 10
        assert config.backup_count == 5
        
    def test_security_config_defaults(self):
        ""Test SecurityConfig default values."""
        config = SecurityConfig()
        assert config.password_hash_algorithm == 'sha256'
        assert config.password_salt_rounds == 10
        assert config.jwt_secret_key == 'dev-jwt-secret'
        assert config.jwt_access_token_expires == 3600
        assert config.cors_allowed_origins == ['*']
        assert config.rate_limit == '1000 per day;100 per hour'
        
    def test_email_config_defaults(self):
        ""Test EmailConfig default values and methods."""
        config = EmailConfig()
        assert config.server == ''
        assert config.port == 587
        assert config.use_tls is True
        assert config.username == ''
        assert config.password == ''
        assert config.default_sender == ''
        assert config.is_configured is False
        
        # Test is_configured with required fields
        config.server = 'smtp.example.com'
        config.default_sender = 'noreply@example.com'
        assert config.is_configured is True
        
    def test_feature_flags_defaults(self):
        ""Test FeatureFlags default values."""
        config = FeatureFlags()
        assert config.enable_edr is True
        assert config.enable_siem is True
        assert config.enable_nips is False
        assert config.enable_compliance is False
        
    def test_paths_config_defaults(self, tmp_path):
        ""Test PathsConfig default values and directory creation."""
        with patch('pathlib.Path.home', return_value=tmp_path):
            config = PathsConfig()
            
            base = Path(__file__).parent.parent.parent
            assert config.base == str(base)
            assert config.data == str(base / 'data')
            assert config.logs == str(base / 'logs')
            assert config.rules == str(base / 'config' / 'rules')
            assert config.temp == str(base / 'tmp')
            
            # Check directories were created
            assert Path(config.data).exists()
            assert Path(config.logs).exists()
            assert Path(config.rules).exists()
            assert Path(config.temp).exists()

class TestAppConfig:
    """Tests for the main AppConfig class."""
    
    def test_app_config_defaults(self):
        ""Test AppConfig default values."""
        config = AppConfig()
        assert config.env == 'production'
        assert config.debug is False
        assert config.testing is False
        assert config.secret_key == 'dev-secret-key'
        
        # Check sub-configs
        assert isinstance(config.database, DatabaseConfig)
        assert isinstance(config.server, ServerConfig)
        assert isinstance(config.logging, LoggingConfig)
        assert isinstance(config.security, SecurityConfig)
        assert isinstance(config.email, EmailConfig)
        assert isinstance(config.features, FeatureFlags)
        assert isinstance(config.paths, PathsConfig)
        
    def test_app_config_load(self):
        ""Test loading AppConfig from environment variables."""
        env_vars = {
            'FLASK_ENV': 'development',
            'DEBUG': 'true',
            'SECRET_KEY': 'test-secret-key',
            'DB_HOST': 'localhost',
            'DB_PORT': '5432',
            'DB_NAME': 'testdb',
            'SERVER_HOST': '127.0.0.1',
            'SERVER_PORT': '5001',
            'LOGGING_LEVEL': 'DEBUG',
            'SECURITY_JWT_SECRET_KEY': 'jwt-secret',
            'EMAIL_SERVER': 'smtp.example.com',
            'FEATURE_ENABLE_NIPS': 'true'
        }
        
        with patch.dict(os.environ, env_vars):
            config = AppConfig.load()
            
        # Check top-level config
        assert config.env == 'development'
        assert config.debug is True
        assert config.secret_key == 'test-secret-key'
        
        # Check sub-configs
        assert config.database.host == 'localhost'
        assert config.database.port == 5432
        assert config.database.name == 'testdb'
        
        assert config.server.host == '127.0.0.1'
        assert config.server.port == 5001
        
        assert config.logging.level == 'DEBUG'
        assert config.security.jwt_secret_key == 'jwt-secret'
        assert config.email.server == 'smtp.example.com'
        assert config.features.enable_nips is True

def test_validate_environment():
    ""Test the validate_environment function."""
    # Test with default config (should have warnings/errors in production)
    with patch.dict(os.environ, {'FLASK_ENV': 'production'}):
        result = validate_environment()
        assert 'SECRET_KEY must be set in production' in result['errors']
    
    # Test with minimal valid config
    with patch.dict(os.environ, {
        'FLASK_ENV': 'production',
        'SECRET_KEY': 'custom-secret-key',
        'SECURITY_JWT_SECRET_KEY': 'custom-jwt-secret',
        'PATHS_BASE': str(Path(__file__).parent.parent.parent)
    }):
        result = validate_environment()
        assert not result['errors']  # No errors with valid config
        
    # Test with email config but no password
    with patch.dict(os.environ, {
        'EMAIL_SERVER': 'smtp.example.com',
        'EMAIL_DEFAULT_SENDER': 'noreply@example.com'
    }):
        result = validate_environment()
        assert 'Email password is not set' in result['warnings'][0]
        
    # Test with non-existent directories
    with patch.dict(os.environ, {
        'PATHS_DATA': '/nonexistent/data',
        'PATHS_LOGS': '/nonexistent/logs'
    }):
        result = validate_environment()
        assert 'Data directory does not exist' in '\n'.join(result['warnings'])
        assert 'Logs directory does not exist' in '\n'.join(result['warnings'])
