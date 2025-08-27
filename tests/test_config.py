""
Tests for the configuration module.
"""
import os
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open
import yaml

from src.common.config import Config, get_config

class TestConfig:
    """Tests for the Config class."""
    
    def test_default_config(self):
        ""Test that default config is loaded when no file is specified."""
        with patch('os.path.exists', return_value=False):
            config = Config()
            
        assert config.get('app.env') == 'production'
        assert config.get('app.debug') is False
        assert config.get('database.uri').startswith('sqlite:///')
        
    def test_load_from_env(self):
        ""Test loading configuration from environment variables."""
        env_vars = {
            'FLASK_ENV': 'test',
            'DEBUG': 'true',
            'DATABASE_URI': 'sqlite:///:memory:',
            'PORT': '8080'
        }
        
        with patch.dict(os.environ, env_vars):
            config = Config()
            
        assert config.get('app.env') == 'test'
        assert config.get('app.debug') is True
        assert config.get('database.uri') == 'sqlite:///:memory:'
        assert config.get('app.port') == 8080
        
    def test_load_from_yaml(self, tmp_path):
        ""Test loading configuration from a YAML file."""
        config_data = {
            'app': {
                'env': 'development',
                'debug': True,
                'port': 5001
            },
            'database': {
                'uri': 'postgresql://user:pass@localhost:5432/testdb',
                'echo': True
            }
        }
        
        config_file = tmp_path / 'test_config.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
            
        config = Config(config_path=str(config_file))
        
        assert config.get('app.env') == 'development'
        assert config.get('app.debug') is True
        assert config.get('database.uri') == 'postgresql://user:pass@localhost:5432/testdb'
        assert config.get('database.echo') is True
        
    def test_nonexistent_yaml_file(self):
        ""Test behavior when YAML file doesn't exist."""
        with patch('os.path.exists', return_value=False):
            config = Config(config_path='nonexistent.yaml')
            
        # Should still load with defaults
        assert config.get('app.env') == 'production'
        
    def test_invalid_yaml_file(self, tmp_path):
        ""Test behavior with invalid YAML file."""
        config_file = tmp_path / 'invalid.yaml'
        config_file.write_text('invalid: yaml: file')
        
        with pytest.raises(yaml.YAMLError):
            Config(config_path=str(config_file))
            
    def test_get_nonexistent_key(self):
        ""Test getting a non-existent key returns None."""
        config = Config()
        assert config.get('nonexistent.key') is None
        assert config.get('nonexistent.key', 'default') == 'default'
        
    def test_contains(self):
        ""Test the __contains__ method."""
        config = Config()
        assert 'app.env' in config
        assert 'nonexistent.key' not in config
        
    def test_getitem(self):
        ""Test the __getitem__ method."""
        config = Config()
        assert isinstance(config['app'], dict)
        assert config['app']['env'] == 'production'
        
        with pytest.raises(KeyError):
            _ = config['nonexistent.key']
            
    def test_deep_update(self):
        ""Test the _deep_update method."""
        config = Config()
        original = {'a': {'b': 1, 'c': 2}}
        update = {'a': {'b': 3, 'd': 4}, 'e': 5}
        
        config._deep_update(original, update)
        
        assert original == {'a': {'b': 3, 'c': 2, 'd': 4}, 'e': 5}
        
    def test_str_to_bool(self):
        ""Test the _str_to_bool method."""
        config = Config()
        assert config._str_to_bool('true') is True
        assert config._str_to_bool('True') is True
        assert config._str_to_bool('1') is True
        assert config._str_to_bool('yes') is True
        assert config._str_to_bool('false') is False
        assert config._str_to_bool('0') is False
        assert config._str_to_bool('no') is False
        assert config._str_to_bool('') is False
        
    def test_get_config_singleton(self):
        ""Test that get_config returns a singleton instance."""
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2
