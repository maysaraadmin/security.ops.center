import os
import stat
import logging
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('permission_check.log')
    ]
)
logger = logging.getLogger('siem.permissions')

class PermissionChecker:
    # Define required permissions for different file types
    REQUIRED_PERMISSIONS = {
        'executable': 0o750,  # rwxr-x---
        'config': 0o640,      # rw-r-----
        'log': 0o640,         # rw-r-----
        'data': 0o660,        # rw-rw----
        'default': 0o640      # rw-r-----
    }
    
    # Sensitive files that should have strict permissions
    SENSITIVE_FILES = [
        '*.yaml', '*.yml', '*.conf', '*.cfg', '*.ini',
        '*.key', '*.pem', '*.crt', '*.cert', '*.p12',
        '*.db', '*.sqlite', '*.db-wal', '*.db-shm',
        '.env', '*.env', 'secrets.*', 'config.*'
    ]
    
    # Directories to check
    CHECK_DIRS = [
        'config', 'logs', 'core', 'models', 'api',
        'integrations', 'scripts', 'utils'
    ]
    
    def __init__(self, base_path: str):
        self.base_path = Path(base_path).resolve()
        self.issues: List[Dict] = []
    
    def get_file_type(self, filepath: Path) -> str:
        """Determine the type of file for permission checking."""
        # Check if file is executable
        if os.access(filepath, os.X_OK):
            return 'executable'
            
        # Check file extension
        ext = filepath.suffix.lower()
        
        if ext in ('.py', '.sh', '.bat', '.cmd', '.exe'):
            return 'executable'
        elif ext in ('.yaml', '.yml', '.conf', '.cfg', '.ini'):
            return 'config'
        elif ext in ('.log', '.txt'):
            return 'log'
        elif ext in ('.db', '.sqlite', '.db-wal', '.db-shm'):
            return 'data'
        
        return 'default'
    
    def check_permissions(self, fix: bool = False) -> bool:
        """Check and optionally fix file permissions."""
        logger.info(f"Checking permissions in {self.base_path}")
        
        # Check directories
        for dir_name in self.CHECK_DIRS:
            dir_path = self.base_path / dir_name
            if not dir_path.exists():
                logger.warning(f"Directory not found: {dir_path}")
                continue
                
            # Check directory permissions
            self._check_path(dir_path, is_dir=True, fix=fix)
            
            # Check files in directory
            for pattern in ['*']:
                for file_path in dir_path.glob(pattern):
                    if file_path.is_file():
                        self._check_path(file_path, is_dir=False, fix=fix)
        
        # Check root directory files
        for pattern in self.SENSITIVE_FILES + ['*.py', '*.sh', '*.bat']:
            for file_path in self.base_path.glob(pattern):
                if file_path.is_file():
                    self._check_path(file_path, is_dir=False, fix=fix)
        
        # Report issues
        if self.issues:
            self._report_issues()
            return False
            
        logger.info("All permissions are correctly set")
        return True
    
    def _check_path(self, path: Path, is_dir: bool, fix: bool = False):
        """Check and optionally fix permissions for a single path."""
        try:
            # Skip symlinks
            if path.is_symlink():
                return
                
            # Get current permissions
            mode = path.stat().st_mode
            
            # Determine required permissions
            if is_dir:
                required_mode = self.REQUIRED_PERMISSIONS['executable']
            else:
                file_type = self.get_file_type(path)
                required_mode = self.REQUIRED_PERMISSIONS.get(file_type, self.REQUIRED_PERMISSIONS['default'])
            
            # Check if permissions match
            if (mode & 0o777) != required_mode:
                issue = {
                    'path': str(path.relative_to(self.base_path)),
                    'current': oct(mode & 0o777),
                    'required': oct(required_mode),
                    'fixed': False
                }
                
                if fix:
                    try:
                        path.chmod(required_mode)
                        issue['fixed'] = True
                        logger.info(f"Fixed permissions for {path}: {oct(required_mode)}")
                    except Exception as e:
                        issue['error'] = str(e)
                        logger.error(f"Failed to fix permissions for {path}: {e}")
                
                if not issue.get('fixed', False):
                    self.issues.append(issue)
        
        except Exception as e:
            logger.error(f"Error checking {path}: {e}")
    
    def _report_issues(self):
        """Print a report of permission issues."""
        if not self.issues:
            return
        
        logger.warning("\n=== Permission Issues ===\n")
        
        for i, issue in enumerate(self.issues, 1):
            print(f"{i}. {issue['path']}")
            print(f"   Current: {issue['current']}")
            print(f"   Required: {issue['required']}")
            
            if 'error' in issue:
                print(f"   Error: {issue['error']}")
            elif issue.get('fixed', False):
                print("   Status: Fixed")
            else:
                print("   Status: Not fixed (use --fix to fix permissions)")
            
            print()
        
        print(f"\nTotal issues found: {len(self.issues)}")

def main():
    parser = argparse.ArgumentParser(description='Check and fix file permissions for SIEM')
    parser.add_argument('--fix', action='store_true', help='Fix permission issues')
    parser.add_argument('--path', default='.', help='Path to SIEM installation directory')
    
    args = parser.parse_args()
    
    checker = PermissionChecker(args.path)
    success = checker.check_permissions(fix=args.fix)
    
    return 0 if success else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
