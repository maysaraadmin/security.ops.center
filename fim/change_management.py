"""
Change Management and Whitelisting for File Integrity Monitoring

This module provides functionality for managing approved changes and whitelists
to reduce false positives in file integrity monitoring.
"""
import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Union, Pattern
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
import fnmatch
import re

logger = logging.getLogger(__name__)

@dataclass
class ApprovedChange:
    """Represents an approved change to a file or directory."""
    path: str
    change_type: str  # 'create', 'modify', 'delete', 'rename', 'permission_change'
    approved_by: str
    approved_at: datetime
    reason: str
    expires_at: Optional[datetime] = None
    checksum: Optional[str] = None
    new_path: Optional[str] = None  # For rename operations
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if this approval has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def matches(self, event_type: str, path: str, new_path: Optional[str] = None) -> bool:
        """Check if this approval matches the given event."""
        # Check if the change type matches
        if self.change_type != event_type.lower():
            return False
            
        # Check if the path matches
        if not fnmatch.fnmatch(path, self.path):
            return False
            
        # For renames, check the new path if provided
        if event_type.lower() == 'rename' and new_path and self.new_path:
            return fnmatch.fnmatch(new_path, self.new_path)
            
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        result = asdict(self)
        # Convert datetime objects to ISO format strings
        for time_field in ['approved_at', 'expires_at']:
            if time_field in result and result[time_field] is not None:
                result[time_field] = result[time_field].isoformat()
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ApprovedChange':
        """Create an ApprovedChange from a dictionary."""
        # Convert ISO format strings back to datetime objects
        time_fields = ['approved_at', 'expires_at']
        for field in time_fields:
            if field in data and data[field] is not None:
                if isinstance(data[field], str):
                    data[field] = datetime.fromisoformat(data[field])
        return cls(**data)

class ChangeManager:
    """Manages approved changes and whitelists for file integrity monitoring."""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the ChangeManager.
        
        Args:
            config: Configuration dictionary with the following optional keys:
                - whitelist_file: Path to the whitelist file (default: 'fim_whitelist.json')
                - auto_save: Whether to automatically save changes to the whitelist file (default: True)
                - default_approval_duration_hours: Default duration for approvals in hours (default: 24)
        """
        self.config = config or {}
        self.whitelist_file = Path(self.config.get('whitelist_file', 'fim_whitelist.json'))
        self.auto_save = self.config.get('auto_save', True)
        self.default_approval_duration = timedelta(
            hours=self.config.get('default_approval_duration_hours', 24)
        )
        self._whitelist: Dict[str, List[Dict[str, Any]]] = {
            'patterns': [],
            'approved_changes': []
        }
        self._load_whitelist()
    
    def _load_whitelist(self) -> None:
        """Load the whitelist from the configured file."""
        if not self.whitelist_file.exists():
            self._whitelist = {'patterns': [], 'approved_changes': []}
            return
            
        try:
            with open(self.whitelist_file, 'r') as f:
                data = json.load(f)
                
            # Convert dictionary representations back to ApprovedChange objects
            approved_changes = []
            for change_data in data.get('approved_changes', []):
                try:
                    approved_changes.append(ApprovedChange.from_dict(change_data))
                except Exception as e:
                    logger.error(f"Failed to load approved change: {e}")
            
            self._whitelist = {
                'patterns': data.get('patterns', []),
                'approved_changes': approved_changes
            }
            
            # Clean up expired approvals
            self._cleanup_expired_approvals()
            
        except Exception as e:
            logger.error(f"Failed to load whitelist: {e}")
            self._whitelist = {'patterns': [], 'approved_changes': []}
    
    def _save_whitelist(self) -> None:
        """Save the current whitelist to the configured file."""
        if not self.auto_save:
            return
            
        try:
            # Ensure the directory exists
            self.whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert ApprovedChange objects to dictionaries
            approved_changes = [
                change.to_dict() 
                for change in self._whitelist['approved_changes']
            ]
            
            data = {
                'patterns': self._whitelist['patterns'],
                'approved_changes': approved_changes
            }
            
            # Write to a temporary file first, then rename to be atomic
            temp_file = self.whitelist_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            # On Windows, we need to remove the destination file first
            if self.whitelist_file.exists():
                self.whitelist_file.unlink()
            
            temp_file.rename(self.whitelist_file)
            
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
    
    def _cleanup_expired_approvals(self) -> None:
        """Remove expired approvals from the whitelist."""
        initial_count = len(self._whitelist['approved_changes'])
        self._whitelist['approved_changes'] = [
            change for change in self._whitelist['approved_changes']
            if not change.is_expired()
        ]
        
        removed = initial_count - len(self._whitelist['approved_changes'])
        if removed > 0:
            logger.info(f"Cleaned up {removed} expired approvals")
            self._save_whitelist()
    
    def add_whitelist_pattern(self, pattern: str, reason: str, user: str) -> None:
        """
        Add a pattern to the whitelist.
        
        Args:
            pattern: Glob pattern to whitelist (e.g., 'C:\\Windows\\Temp\\*')
            reason: Reason for whitelisting
            user: User who requested the whitelist
        """
        self._whitelist['patterns'].append({
            'pattern': pattern,
            'added_by': user,
            'added_at': datetime.utcnow().isoformat(),
            'reason': reason
        })
        self._save_whitelist()
    
    def remove_whitelist_pattern(self, pattern: str) -> bool:
        """
        Remove a pattern from the whitelist.
        
        Args:
            pattern: Pattern to remove
            
        Returns:
            bool: True if the pattern was found and removed, False otherwise
        """
        initial_count = len(self._whitelist['patterns'])
        self._whitelist['patterns'] = [
            p for p in self._whitelist['patterns']
            if p['pattern'] != pattern
        ]
        
        if len(self._whitelist['patterns']) < initial_count:
            self._save_whitelist()
            return True
        return False
    
    def approve_change(
        self,
        path: str,
        change_type: str,
        approved_by: str,
        reason: str,
        duration_hours: Optional[int] = None,
        checksum: Optional[str] = None,
        new_path: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ApprovedChange:
        """
        Approve a specific change.
        
        Args:
            path: Path to the file or directory being changed
            change_type: Type of change ('create', 'modify', 'delete', 'rename', 'permission_change')
            approved_by: User who approved the change
            reason: Reason for approval
            duration_hours: How long this approval is valid (in hours)
            checksum: Expected file checksum (for modification approvals)
            new_path: New path (for rename operations)
            metadata: Additional metadata about the approval
            
        Returns:
            The created ApprovedChange
        """
        duration = timedelta(
            hours=duration_hours if duration_hours is not None 
            else self.default_approval_duration.total_seconds() / 3600
        )
        
        change = ApprovedChange(
            path=path,
            change_type=change_type.lower(),
            approved_by=approved_by,
            approved_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + duration,
            reason=reason,
            checksum=checksum,
            new_path=new_path,
            metadata=metadata or {}
        )
        
        self._whitelist['approved_changes'].append(change)
        self._save_whitelist()
        return change
    
    def is_whitelisted(self, path: str) -> bool:
        """
        Check if a path matches any whitelist pattern.
        
        Args:
            path: Path to check
            
        Returns:
            bool: True if the path is whitelisted, False otherwise
        """
        # Always normalize paths to use forward slashes for consistent matching
        normalized_path = path.replace('\\', '/')
        
        for pattern in self._whitelist['patterns']:
            # Convert Windows path separators to forward slashes for glob matching
            pattern_str = pattern['pattern'].replace('\\', '/')
            
            # Handle directory patterns (e.g., 'C:/Windows/Temp/*' should match 'C:/Windows/Temp/foo.txt')
            if pattern_str.endswith('/*') and os.path.isdir(pattern_str[:-2]):
                if normalized_path.startswith(pattern_str[:-1]) or \
                   normalized_path == pattern_str[:-2]:
                    return True
            
            # Standard glob matching
            if fnmatch.fnmatch(normalized_path, pattern_str):
                return True
                
            # Handle case-insensitive matching on Windows
            if os.name == 'nt' and fnmatch.fnmatch(normalized_path.lower(), pattern_str.lower()):
                return True
                
        return False
    
    def is_approved(
        self, 
        path: str, 
        change_type: str, 
        checksum: Optional[str] = None,
        new_path: Optional[str] = None
    ) -> bool:
        """
        Check if a change is approved.
        
        Args:
            path: Path to the file or directory being changed
            change_type: Type of change ('create', 'modify', 'delete', 'rename', 'permission_change')
            checksum: File checksum (for modification checks)
            new_path: New path (for rename operations)
            
        Returns:
            bool: True if the change is approved, False otherwise
        """
        # First check if the path is whitelisted
        if self.is_whitelisted(path):
            return True
        
        # Then check for specific approvals
        for approval in self._whitelist['approved_changes']:
            if approval.is_expired():
                continue
                
            if approval.matches(change_type, path, new_path):
                # For modifications, verify the checksum if provided
                if change_type.lower() == 'modify' and approval.checksum and checksum:
                    return approval.checksum == checksum
                return True
                
        return False
    
    def get_approvals(
        self, 
        path: Optional[str] = None, 
        change_type: Optional[str] = None,
        include_expired: bool = False
    ) -> List[ApprovedChange]:
        """
        Get all approvals matching the given criteria.
        
        Args:
            path: Filter by path (supports glob patterns)
            change_type: Filter by change type
            include_expired: Whether to include expired approvals
            
        Returns:
            List of matching ApprovedChange objects
        """
        result = []
        
        for approval in self._whitelist['approved_changes']:
            if not include_expired and approval.is_expired():
                continue
                
            if path and not fnmatch.fnmatch(approval.path, path):
                continue
                
            if change_type and approval.change_type != change_type.lower():
                continue
                
            result.append(approval)
            
        return result
    
    def revoke_approval(self, path: str, change_type: Optional[str] = None) -> int:
        """
        Revoke approvals for a path.
        
        Args:
            path: Path to revoke approvals for
            change_type: Only revoke approvals of this type
            
        Returns:
            int: Number of approvals revoked
        """
        initial_count = len(self._whitelist['approved_changes'])
        
        self._whitelist['approved_changes'] = [
            a for a in self._whitelist['approved_changes']
            if not (a.path == path and (change_type is None or a.change_type == change_type.lower()))
        ]
        
        removed = initial_count - len(self._whitelist['approved_changes'])
        if removed > 0:
            self._save_whitelist()
            
        return removed
