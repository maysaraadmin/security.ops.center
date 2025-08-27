"""
Configuration validation script for the EDR Web Application.
Checks if all required configuration files and settings are in place.
"""
import os
import sys
import yaml
from pathlib import Path
from typing import Dict, Any, List, Tuple

# Required configuration files
REQUIRED_CONFIG_FILES = [
    'config/web_config.yaml',
    '.env.example',
]

# Required directories
REQUIRED_DIRS = [
    'logs',
    'data',
    'uploads',
    'tmp',
    'config/rules',
]

# Required environment variables (from .env.example)
REQUIRED_ENV_VARS = [
    'FLASK_ENV',
    'SECRET_KEY',
    'DATABASE_URI',
]

def check_required_files() -> Tuple[bool, List[str]]:
    """Check if all required configuration files exist."""
    missing = []
    for file_path in REQUIRED_CONFIG_FILES:
        if not os.path.exists(file_path):
            missing.append(file_path)
    return len(missing) == 0, missing

def check_required_dirs() -> Tuple[bool, List[str]]:
    """Check if all required directories exist."""
    missing = []
    for dir_path in REQUIRED_DIRS:
        if not os.path.isdir(dir_path):
            missing.append(dir_path)
    return len(missing) == 0, missing

def check_web_config() -> Tuple[bool, List[str]]:
    """Validate the web configuration file."""
    try:
        with open('config/web_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        errors = []
        
        # Check required top-level sections
        required_sections = ['app', 'database', 'security', 'logging', 'web', 'edr']
        for section in required_sections:
            if section not in config:
                errors.append(f"Missing required section: {section}")
        
        # Check app settings
        if 'app' in config:
            app_required = ['env', 'debug', 'secret_key', 'host', 'port']
            for setting in app_required:
                if setting not in config['app']:
                    errors.append(f"Missing required app setting: {setting}")
            
            # Validate debug mode in production
            if config['app'].get('env') == 'production' and config['app'].get('debug') is True:
                errors.append("Debug mode should be disabled in production")
        
        # Check security settings
        if 'security' in config:
            security = config['security']
            
            # Check JWT secret key
            jwt_key = security.get('jwt_secret_key', '')
            if not jwt_key or 'your-jwt-secret' in jwt_key:
                errors.append("Please set a secure JWT secret key in web_config.yaml")
            
            # Check password security
            if security.get('password_salt_rounds', 0) < 10:
                errors.append("Password salt rounds should be at least 10")
                
            if security.get('password_min_length', 0) < 8:
                errors.append("Minimum password length should be at least 8 characters")
        
        # Check database settings
        if 'database' in config:
            db_uri = config['database'].get('uri', '')
            if 'sqlite' in db_uri and 'memory' not in db_uri and not db_uri.startswith('sqlite:///'):
                errors.append("SQLite database path should be absolute (start with 'sqlite:///')")
        
        if errors:
            return False, errors
            
        return True, []
        
    except yaml.YAMLError as e:
        return False, [f"Invalid YAML in config file: {str(e)}"]
    except Exception as e:
        return False, [f"Error reading config file: {str(e)}"]

def check_env_file() -> Tuple[bool, List[str]]:
    """Check if .env file exists and contains required variables."""
    if not os.path.exists('.env'):
        return False, [".env file not found. Please create it from .env.example"]
    
    # Check if .env contains required variables
    try:
        with open('.env', 'r') as f:
            content = f.read()
            
        missing_vars = []
        for var in REQUIRED_ENV_VARS:
            if f"{var}=" not in content:
                missing_vars.append(var)
                
        if missing_vars:
            return False, [f"Missing required environment variables: {', '.join(missing_vars)}"]
            
        return True, []
    except Exception as e:
        return False, [f"Error reading .env file: {str(e)}"]

def check_security() -> List[str]:
    """Check for potential security issues."""
    warnings = []
    
    # Check for default secret key
    try:
        with open('config/web_config.yaml', 'r') as f:
            config = yaml.safe_load(f)
            if config.get('app', {}).get('secret_key') == 'your-secret-key-here':
                warnings.append("WARNING: Using default secret key in web_config.yaml - change this in production")
    except:
        pass
    
    # Check debug mode in production
    try:
        with open('.env', 'r') as f:
            content = f.read()
            if 'FLASK_ENV=production' in content and 'DEBUG=true' in content:
                warnings.append("WARNING: Debug mode is enabled in production environment")
    except:
        pass
        
    return warnings

def main() -> int:
    """Run all configuration checks."""
    print("\n=== EDR Web Application Configuration Validation ===\n")
    
    # Check required files
    files_ok, missing_files = check_required_files()
    if not files_ok:
        print("❌ Missing required configuration files:")
        for f in missing_files:
            print(f"  - {f}")
        print("\nPlease create these files from the example configurations.")
        return 1
    
    # Check required directories
    dirs_ok, missing_dirs = check_required_dirs()
    if not dirs_ok:
        print("⚠️  Missing required directories:")
        for d in missing_dirs:
            print(f"  - {d}")
        print("\nCreating missing directories...")
        for d in missing_dirs:
            os.makedirs(d, exist_ok=True)
            print(f"  - Created: {d}")
    
    # Validate web config
    config_ok, config_errors = check_web_config()
    if not config_ok:
        print("❌ Configuration validation failed:")
        for error in config_errors:
            print(f"  - {error}")
        return 1
    
    # Check .env file
    env_ok, env_errors = check_env_file()
    if not env_ok:
        print("❌ Environment configuration issues:")
        for error in env_errors:
            print(f"  - {error}")
        return 1
    
    # Check for security issues
    security_warnings = check_security()
    
    # Print results
    print("\n✅ Configuration validation completed successfully!")
    
    if security_warnings:
        print("\n⚠️  Security warnings:")
        for warning in security_warnings:
            print(f"  - {warning}")
    
    print("\nNext steps:")
    print("1. Review the configuration in config/web_config.yaml")
    print("2. Ensure all environment variables are set in .env")
    print("3. Run 'flask run' to start the development server\n")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
