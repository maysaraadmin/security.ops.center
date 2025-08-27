"""
Security utilities for the SIEM system.

This module provides security-related functionality including:
- Secure password hashing and verification
- Secure random string generation
- Input validation and sanitization
- Secure configuration handling
"""
import os
import re
import hashlib
import hmac
import secrets
import string
from typing import Optional, Union, Dict, Any, List, Tuple
from pathlib import Path
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
import bcrypt

# Constants for password policies
DEFAULT_PASSWORD_MIN_LENGTH = 12
DEFAULT_PASSWORD_REQUIREMENTS = {
    'min_length': DEFAULT_PASSWORD_MIN_LENGTH,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_digits': True,
    'require_special': True,
    'min_entropy': 3.0  # bits per character
}

class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass

class PasswordPolicyError(SecurityError):
    """Raised when a password doesn't meet the policy requirements."""
    pass

class EncryptionError(SecurityError):
    """Raised when there's an error during encryption/decryption."""
    pass

def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of the token in bytes (default: 32)
        
    Returns:
        A URL-safe base64-encoded random string
    """
    if length < 16:
        raise ValueError("Token length must be at least 16 bytes")
    
    return secrets.token_urlsafe(length)

def hash_password(password: Union[str, bytes], rounds: int = 14) -> bytes:
    """
    Hash a password using bcrypt.
    
    Args:
        password: The password to hash
        rounds: Number of hashing rounds (cost factor)
        
    Returns:
        Hashed password as bytes
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Generate a salt and hash the password
    salt = bcrypt.gensalt(rounds=rounds)
    return bcrypt.hashpw(password, salt)

def verify_password(password: Union[str, bytes], hashed_password: bytes) -> bool:
    """
    Verify a password against a hashed password.
    
    Args:
        password: The password to verify
        hashed_password: The hashed password to check against
        
    Returns:
        bool: True if the password matches, False otherwise
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return bcrypt.checkpw(password, hashed_password)

def validate_password_strength(
    password: str,
    min_length: int = DEFAULT_PASSWORD_MIN_LENGTH,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digits: bool = True,
    require_special: bool = True,
    min_entropy: float = 3.0
) -> Tuple[bool, List[str]]:
    """
    Validate password strength against specified requirements.
    
    Args:
        password: The password to validate
        min_length: Minimum password length
        require_uppercase: Whether to require uppercase letters
        require_lowercase: Whether to require lowercase letters
        require_digits: Whether to require digits
        require_special: Whether to require special characters
        min_entropy: Minimum entropy in bits per character
        
    Returns:
        Tuple of (is_valid, errors)
    """
    errors = []
    
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    
    if require_uppercase and not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_lowercase and not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_digits and not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    if require_special and not re.search(r'[^A-Za-z0-9]', password):
        errors.append("Password must contain at least one special character")
    
    # Calculate password entropy
    char_set = 0
    if re.search(r'[a-z]', password):
        char_set += 26
    if re.search(r'[A-Z]', password):
        char_set += 26
    if re.search(r'\d', password):
        char_set += 10
    if re.search(r'[^A-Za-z0-9]', password):
        # Common special characters
        char_set += 32
    
    entropy = len(password) * (char_set ** 0.5)
    
    if entropy < min_entropy * len(password):
        errors.append("Password is not complex enough")
    
    return (len(errors) == 0, errors)

class SecureConfig:
    """Secure configuration management with encryption support."""
    
    def __init__(self, key: Optional[bytes] = None, config_file: Optional[Union[str, Path]] = None):
        """
        Initialize the secure config manager.
        
        Args:
            key: Encryption key (32 bytes, URL-safe base64-encoded)
            config_file: Path to the config file
        """
        self.key = key or os.getenv('SIEM_CONFIG_KEY')
        if self.key and isinstance(self.key, str):
            # Pad the key if needed
            self.key = self.key.ljust(32, '=')[:32].encode('utf-8')
        
        self.config_file = Path(config_file) if config_file else None
        self.config: Dict[str, Any] = {}
        self.fernet = Fernet(Fernet.generate_key())  # Dummy key, will be replaced if key is provided
        
        if self.key:
            try:
                self.fernet = Fernet(base64.urlsafe_b64encode(self.key))
            except Exception as e:
                raise EncryptionError(f"Invalid encryption key: {e}")
    
    def load_config(self) -> Dict[str, Any]:
        """Load and decrypt the configuration."""
        if not self.config_file or not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                encrypted_data = f.read()
            
            if not self.key:
                # Try to parse as plain JSON if no key is provided
                return json.loads(encrypted_data)
            
            decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
            return json.loads(decrypted_data)
        except (json.JSONDecodeError, InvalidToken) as e:
            raise EncryptionError(f"Failed to decrypt configuration: {e}")
    
    def save_config(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Encrypt and save the configuration."""
        if config is not None:
            self.config = config
        
        if not self.config_file:
            raise ValueError("No config file specified")
        
        # Create parent directories if they don't exist
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            config_json = json.dumps(self.config, indent=2)
            
            if self.key:
                encrypted_data = self.fernet.encrypt(config_json.encode())
                with open(self.config_file, 'wb') as f:
                    f.write(encrypted_data)
            else:
                with open(self.config_file, 'w') as f:
                    f.write(config_json)
        except Exception as e:
            raise EncryptionError(f"Failed to save configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any, save: bool = False) -> None:
        """Set a configuration value."""
        self.config[key] = value
        if save:
            self.save_config()
    
    def delete(self, key: str, save: bool = False) -> None:
        """Delete a configuration value."""
        if key in self.config:
            del self.config[key]
            if save:
                self.save_config()

def sanitize_input(input_str: str, allowed_chars: str = None) -> str:
    """
    Sanitize user input to prevent injection attacks.
    
    Args:
        input_str: The input string to sanitize
        allowed_chars: String of allowed characters (regex pattern)
        
    Returns:
        Sanitized string
    """
    if not input_str:
        return ""
    
    # Default allowed: alphanumeric, space, basic punctuation
    if allowed_chars is None:
        allowed_chars = r'A-Za-z0-9 .,!?@#$%^&*()_+-=[]{}|;:<>/\\'
    
    # Escape special regex characters
    allowed_chars = re.escape(allowed_chars)
    
    # Remove any characters not in the allowed set
    return re.sub(f'[^{allowed_chars}]', '', input_str)

def generate_api_key(length: int = 32) -> str:
    """
    Generate a secure API key.
    
    Args:
        length: Length of the API key in bytes (default: 32)
        
    Returns:
        A secure random string
    """
    if length < 16:
        raise ValueError("API key length must be at least 16 bytes")
    
    # Generate a secure random string
    alphabet = string.ascii_letters + string.digits + '_-'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def constant_time_compare(val1: Union[str, bytes], val2: Union[str, bytes]) -> bool:
    """
    Compare two strings/bytes in constant time to prevent timing attacks.
    
    Args:
        val1: First value to compare
        val2: Second value to compare
        
    Returns:
        bool: True if the values are equal, False otherwise
    """
    if isinstance(val1, str):
        val1 = val1.encode('utf-8')
    if isinstance(val2, str):
        val2 = val2.encode('utf-8')
    
    return hmac.compare_digest(val1, val2)
