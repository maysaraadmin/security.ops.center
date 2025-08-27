"""
File Integrity Monitoring - Utilities

This module contains utility functions for the FIM system.
"""
import os
import hashlib
import logging
import fnmatch
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Union, Pattern, Set, Tuple

logger = logging.getLogger(__name__)

def calculate_checksum(file_path: str, algorithm: str = 'sha256', 
                     chunk_size: int = 8192) -> Optional[str]:
    """
    Calculate the checksum of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use (default: sha256)
        chunk_size: Size of chunks to read from the file (default: 8KB)
        
    Returns:
        Hex digest of the file's checksum, or None if the file couldn't be read
    """
    if not os.path.isfile(file_path):
        return None
    
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except (IOError, OSError) as e:
        logger.warning(f"Could not calculate checksum for {file_path}: {e}")
        return None

def normalize_path(path: str) -> str:
    """
    Normalize a file system path for consistent comparison.
    
    Args:
        path: Path to normalize
        
    Returns:
        Normalized path
    """
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))

def should_ignore_path(path: str, ignore_patterns: List[str]) -> bool:
    """
    Check if a path matches any of the ignore patterns.
    
    Args:
        path: Path to check
        ignore_patterns: List of glob patterns to match against
        
    Returns:
        True if the path should be ignored, False otherwise
    """
    path = normalize_path(path)
    
    for pattern in ignore_patterns:
        # Handle directory patterns (ending with /* or /**)
        if pattern.endswith('/**'):
            dir_pattern = pattern[:-3]  # Remove /**
            if path.startswith(normalize_path(dir_pattern)):
                return True
        elif pattern.endswith('/*'):
            dir_pattern = pattern[:-2]  # Remove /*
            if os.path.dirname(path) == normalize_path(dir_pattern):
                return True
        # Handle exact matches
        elif fnmatch.fnmatch(path, pattern):
            return True
        # Handle basename-only patterns
        elif fnmatch.fnmatch(os.path.basename(path), pattern):
            return True
    
    return False

def get_file_metadata(file_path: str) -> Dict[str, Any]:
    """
    Get metadata for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary containing file metadata
    """
    try:
        stat = os.stat(file_path)
        return {
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'mode': stat.st_mode,
            'inode': stat.st_ino,
            'device': stat.st_dev,
            'n_links': stat.st_nlink,
            'uid': stat.st_uid,
            'gid': stat.st_gid
        }
    except (OSError, AttributeError) as e:
        logger.warning(f"Could not get metadata for {file_path}: {e}")
        return {}

def is_binary_file(file_path: str, chunk_size: int = 8192) -> bool:
    """
    Check if a file is binary.
    
    Args:
        file_path: Path to the file
        chunk_size: Number of bytes to read (default: 8KB)
        
    Returns:
        True if the file is binary, False otherwise
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(chunk_size)
            # Check for null bytes or non-printable characters
            return b'\x00' in chunk or not all(32 <= byte < 127 or byte in {9, 10, 13} for byte in chunk)
    except (IOError, OSError):
        return False

def get_file_type(file_path: str) -> str:
    """
    Get the type of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        File type as a string (e.g., 'text/plain', 'application/octet-stream')
    """
    import mimetypes
    
    # Add some common mimetypes that might be missing
    mimetypes.add_type('application/xml', '.xml')
    mimetypes.add_type('application/json', '.json')
    mimetypes.add_type('application/yaml', '.yaml')
    mimetypes.add_type('application/yml', '.yml')
    
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type or 'application/octet-stream'

def is_sensitive_file(file_path: str) -> bool:
    """
    Check if a file is likely to contain sensitive information.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file is likely to contain sensitive information
    """
    sensitive_keywords = [
        'password', 'secret', 'key', 'credential', 'token', 
        'api[_-]?key', 'auth', 'private', 'confidential'
    ]
    
    # Check if the filename contains any sensitive keywords
    filename = os.path.basename(file_path).lower()
    if any(keyword in filename for keyword in sensitive_keywords):
        return True
    
    # Check file extension
    _, ext = os.path.splitext(file_path)
    sensitive_extensions = [
        '.pem', '.key', '.p12', '.pfx', '.cer', '.crt', '.p7b', '.p7c',
        '.p7s', '.p8', '.der', '.csr', '.jks', '.keystore', '.jceks',
        '.bks', '.p7m', '.p7r', '.p7s', '.p8', '.p8e', '.spc', '.p7',
        '.env', '.properties', '.conf', '.config', '.cfg', '.ini',
        '.sh', '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.ps1xml',
        '.pssc', '.psrc', '.cdxml', '.sql', '.db', '.sqlite', '.sqlite3',
        '.mdb', '.accdb', '.dbf', '.myd', '.mdf', '.ndf', '.ldf', '.bak',
        '.tmp', '.temp', '.swp', '.swo', '.swn', '.swo', '.swp', '.swn'
    ]
    
    if ext.lower() in sensitive_extensions:
        return True
    
    return False

def get_directory_size(path: str) -> Tuple[int, int]:
    """
    Calculate the total size and file count of a directory.
    
    Args:
        path: Path to the directory
        
    Returns:
        A tuple of (total_size_in_bytes, file_count)
    """
    total_size = 0
    file_count = 0
    
    try:
        for dirpath, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    total_size += os.path.getsize(file_path)
                    file_count += 1
                except (OSError, IOError):
                    continue
    except (OSError, IOError):
        pass
    
    return total_size, file_count

def get_file_permissions_octal(file_path: str) -> str:
    """
    Get file permissions in octal format (e.g., '0644').
    
    Args:
        file_path: Path to the file
        
    Returns:
        File permissions as an octal string
    """
    try:
        return oct(os.stat(file_path).st_mode & 0o777)[2:].zfill(3)
    except (OSError, AttributeError):
        return '000'

def get_file_owner(file_path: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Get the owner of a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        A tuple of (username, groupname) or (None, None) if not available
    """
    try:
        if os.name == 'nt':  # Windows
            import win32security
            import win32api
            
            sd = win32security.GetFileSecurity(
                file_path, 
                win32security.OWNER_SECURITY_INFORMATION
            )
            owner_sid = sd.GetSecurityDescriptorOwner()
            
            # Get the account and domain names
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            
            # Get the primary group
            group_sid = sd.GetSecurityDescriptorGroup()
            group_name, group_domain, _ = win32security.LookupAccountSid(None, group_sid)
            
            return (f"{domain}\\{name}" if domain else name, 
                    f"{group_domain}\\{group_name}" if group_domain else group_name)
        else:  # Unix-like
            import pwd
            import grp
            
            stat_info = os.stat(file_path)
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            
            try:
                user = pwd.getpwuid(uid).pw_name
            except KeyError:
                user = str(uid)
                
            try:
                group = grp.getgrgid(gid).gr_name
            except KeyError:
                group = str(gid)
                
            return (user, group)
    except Exception as e:
        logger.debug(f"Could not get owner for {file_path}: {e}")
        return (None, None)

def is_hidden(file_path: str) -> bool:
    """
    Check if a file or directory is hidden.
    
    Args:
        file_path: Path to the file or directory
        
    Returns:
        True if the file or directory is hidden, False otherwise
    """
    name = os.path.basename(file_path)
    
    # Check for dot files on Unix-like systems
    if name.startswith('.'):
        return True
    
    # Check for hidden attribute on Windows
    if os.name == 'nt':
        try:
            import win32api, win32con
            
            # Get file attributes
            attrs = win32api.GetFileAttributes(file_path)
            
            # Check for hidden or system attribute
            if attrs & (win32con.FILE_ATTRIBUTE_HIDDEN | 
                       win32con.FILE_ATTRIBUTE_SYSTEM):
                return True
        except:
            pass
    
    return False

def get_file_hashes(file_path: str) -> Dict[str, str]:
    """
    Calculate multiple hash values for a file.
    
    Args:
        file_path: Path to the file
        
    Returns:
        Dictionary of hash algorithms and their values
    """
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
        'sha512': hashlib.sha512()
    }
    
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        
        # Return hex digests
        return {algo: h.hexdigest() for algo, h in hashes.items()}
    except (IOError, OSError) as e:
        logger.warning(f"Could not calculate hashes for {file_path}: {e}")
        return {}

def is_file_locked(file_path: str) -> bool:
    """
    Check if a file is locked by another process.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if the file is locked, False otherwise
    """
    if not os.path.exists(file_path):
        return False
    
    try:
        if os.name == 'nt':  # Windows
            import msvcrt
            
            # Try to open the file in exclusive mode
            try:
                with open(file_path, 'a+', 0):  # No buffering
                    pass
                return False
            except IOError:
                return True
        else:  # Unix-like
            import fcntl
            
            with open(file_path, 'a') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False
                except (IOError, BlockingIOError):
                    return True
    except Exception as e:
        logger.debug(f"Could not check if file is locked: {e}")
        return False


def get_file_encoding(file_path: str, default: str = 'utf-8') -> str:
    """
    Detect the encoding of a text file.
    
    Args:
        file_path: Path to the file
        default: Default encoding to return if detection fails
        
    Returns:
        Detected encoding or the default if detection fails
    """
    try:
        import chardet
        
        with open(file_path, 'rb') as f:
            raw_data = f.read(1024)  # Read first 1KB for detection
            
        result = chardet.detect(raw_data)
        return result['encoding'] or default
    except Exception:
        return default
