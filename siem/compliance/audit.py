"""
Audit Logging Module for SIEM.

This module handles the recording and management of audit logs for compliance and security.
"""
import os
import json
import logging
import hashlib
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict, field
from pathlib import Path
import threading
from queue import Queue, Empty

logger = logging.getLogger(__name__)

class AuditAction(Enum):
    """Standard audit actions."""
    # Authentication
    LOGIN = "login"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session_expired"
    
    # User Management
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    USER_PASSWORD_CHANGE = "user_password_change"
    USER_ROLE_CHANGE = "user_role_change"
    
    # Configuration Changes
    CONFIG_UPDATE = "config_update"
    SETTINGS_UPDATE = "settings_update"
    
    # Data Access
    DATA_ACCESS = "data_access"
    DATA_EXPORT = "data_export"
    REPORT_GENERATE = "report_generate"
    
    # System Operations
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    BACKUP_CREATE = "backup_create"
    BACKUP_RESTORE = "backup_restore"
    
    # Security Events
    ROLE_PERMISSION_CHANGE = "role_permission_change"
    POLICY_UPDATE = "policy_update"
    RULE_UPDATE = "rule_update"
    
    # Custom actions
    CUSTOM = "custom"

class AuditLogLevel(Enum):
    """Audit log severity levels."""
    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    ALERT = "alert"
    EMERGENCY = "emergency"

@dataclass
class AuditLogEntry:
    """Represents an audit log entry."""
    timestamp: datetime
    action: Union[str, AuditAction]
    level: Union[str, AuditLogLevel] = AuditLogLevel.INFO
    user_id: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    status: str = "success"
    details: Dict[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the audit log entry to a dictionary."""
        result = {
            'timestamp': self.timestamp.isoformat(),
            'action': self.action.value if isinstance(self.action, Enum) else self.action,
            'level': self.level.value if isinstance(self.level, Enum) else self.level,
            'status': self.status,
            'details': self.details
        }
        
        # Add optional fields if they exist
        if self.user_id:
            result['user_id'] = self.user_id
        if self.username:
            result['username'] = self.username
        if self.source_ip:
            result['source_ip'] = self.source_ip
        if self.user_agent:
            result['user_agent'] = self.user_agent
        if self.resource_type:
            result['resource_type'] = self.resource_type
        if self.resource_id:
            result['resource_id'] = self.resource_id
        if self.resource_name:
            result['resource_name'] = self.resource_name
        if self.request_id:
            result['request_id'] = self.request_id
        if self.session_id:
            result['session_id'] = self.session_id
            
        return result
    
    def to_json(self) -> str:
        """Convert the audit log entry to a JSON string."""
        return json.dumps(self.to_dict(), default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLogEntry':
        """Create an AuditLogEntry from a dictionary."""
        # Convert string timestamps back to datetime objects
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        
        return cls(**data)

class AuditLogger:
    """Handles audit logging with buffering and async writing."""
    
    def __init__(
        self,
        log_dir: str = "./audit_logs",
        max_file_size: int = 10 * 1024 * 1024,  # 10 MB
        max_backups: int = 30,  # Keep up to 30 days of logs
        buffer_size: int = 100,  # Number of entries to buffer before writing
        flush_interval: float = 5.0,  # Seconds between flushes
        compress_backups: bool = True
    ):
        """Initialize the audit logger.
        
        Args:
            log_dir: Directory to store audit logs
            max_file_size: Maximum size of a log file before rotation (bytes)
            max_backups: Maximum number of backup files to keep
            buffer_size: Number of log entries to buffer before writing to disk
            flush_interval: Time in seconds between automatic flushes
            compress_backups: Whether to compress rotated log files
        """
        self.log_dir = Path(log_dir)
        self.max_file_size = max_file_size
        self.max_backups = max_backups
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        self.compress_backups = compress_backups
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Current log file
        self.current_date = datetime.now(timezone.utc).date()
        self.current_file = self._get_current_log_file()
        self.file_handle = None
        self.file_size = 0
        
        # Buffer for log entries
        self.buffer = []
        self.buffer_lock = threading.Lock()
        
        # Background thread for writing logs
        self._shutdown = False
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()
        
        logger.info(f"Audit logger initialized. Logging to {self.current_file}")
    
    def _get_current_log_file(self) -> Path:
        """Get the path to the current log file based on the current date."""
        date_str = self.current_date.strftime("%Y-%m-%d")
        return self.log_dir / f"audit_{date_str}.log"
    
    def _open_log_file(self) -> None:
        """Open the current log file for appending."""
        if self.file_handle is not None:
            self.file_handle.close()
        
        # Create the file if it doesn't exist
        self.current_file.parent.mkdir(parents=True, exist_ok=True)
        self.file_handle = open(self.current_file, 'a', encoding='utf-8')
        self.file_size = self.current_file.stat().st_size if self.current_file.exists() else 0
    
    def _rotate_log_file(self) -> None:
        """Rotate the log file if necessary."""
        if self.file_handle is None:
            self._open_log_file()
        
        # Check if we need to rotate based on date
        today = datetime.now(timezone.utc).date()
        if today != self.current_date:
            self.current_date = today
            old_file = self.current_file
            self.current_file = self._get_current_log_file()
            
            # Close the old file and open the new one
            if self.file_handle:
                self.file_handle.close()
                self.file_handle = None
            
            self._open_log_file()
            self._cleanup_old_logs()
            return
        
        # Check if we need to rotate based on file size
        if self.file_size >= self.max_file_size:
            # Close the current file
            if self.file_handle:
                self.file_handle.close()
                self.file_handle = None
            
            # Rename the current file with a timestamp
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            rotated_file = self.current_file.with_name(f"{self.current_file.stem}_{timestamp}{self.current_file.suffix}")
            self.current_file.rename(rotated_file)
            
            # Compress the rotated file if enabled
            if self.compress_backups:
                import gzip
                with open(rotated_file, 'rb') as f_in:
                    with gzip.open(f"{rotated_file}.gz", 'wb') as f_out:
                        f_out.writelines(f_in)
                rotated_file.unlink()  # Remove the uncompressed file
            
            # Open a new log file
            self._open_log_file()
    
    def _cleanup_old_logs(self) -> None:
        """Remove old log files beyond the maximum number of backups."""
        # Get all log files, sorted by modification time (oldest first)
        log_files = sorted(
            [f for f in self.log_dir.glob("audit_*.log*")],
            key=lambda f: f.stat().st_mtime
        )
        
        # Remove the oldest files if we have too many
        while len(log_files) > self.max_backups:
            file_to_remove = log_files.pop(0)
            try:
                file_to_remove.unlink()
                logger.debug(f"Removed old log file: {file_to_remove}")
            except Exception as e:
                logger.error(f"Failed to remove old log file {file_to_remove}: {e}")
    
    def _write_entry(self, entry: AuditLogEntry) -> None:
        """Write a single log entry to the current log file."""
        if self.file_handle is None:
            self._open_log_file()
        
        # Convert the entry to JSON and write it to the file
        entry_data = entry.to_json() + "\n"
        self.file_handle.write(entry_data)
        self.file_handle.flush()
        self.file_size += len(entry_data.encode('utf-8'))
        
        # Rotate the log file if necessary
        self._rotate_log_file()
    
    def _worker(self) -> None:
        """Background worker that processes the log queue."""
        while not self._shutdown:
            try:
                # Get all buffered entries
                with self.buffer_lock:
                    if not self.buffer:
                        # No entries, wait for the flush interval
                        time.sleep(self.flush_interval)
                        continue
                    
                    # Take all buffered entries
                    entries = self.buffer[:]
                    self.buffer = []
                
                # Write the entries to the log file
                for entry in entries:
                    try:
                        self._write_entry(entry)
                    except Exception as e:
                        logger.error(f"Failed to write audit log entry: {e}", exc_info=True)
                
                # Small sleep to prevent busy-waiting
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in audit log worker: {e}", exc_info=True)
                time.sleep(1)  # Prevent tight loop on errors
    
    def log(
        self,
        action: Union[str, AuditAction],
        level: Union[str, AuditLogLevel] = AuditLogLevel.INFO,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        status: str = "success",
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> None:
        """Log an audit event.
        
        Args:
            action: The action that was performed (e.g., 'login', 'user_update')
            level: Severity level of the event
            user_id: ID of the user who performed the action
            username: Username of the user who performed the action
            source_ip: Source IP address of the request
            user_agent: User agent string from the request
            resource_type: Type of resource that was accessed/modified
            resource_id: ID of the resource that was accessed/modified
            resource_name: Name of the resource that was accessed/modified
            status: Status of the action ('success', 'failed', etc.)
            details: Additional details about the event
            request_id: ID of the HTTP request that triggered this event
            session_id: ID of the user's session
        """
        # Create the log entry
        entry = AuditLogEntry(
            timestamp=datetime.now(timezone.utc),
            action=action,
            level=level,
            user_id=user_id,
            username=username,
            source_ip=source_ip,
            user_agent=user_agent,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            status=status,
            details=details or {},
            request_id=request_id,
            session_id=session_id
        )
        
        # Add to buffer
        with self.buffer_lock:
            self.buffer.append(entry)
            
            # Flush if buffer is full
            if len(self.buffer) >= self.buffer_size:
                self.flush()
    
    def flush(self) -> None:
        """Flush any buffered log entries to disk."""
        with self.buffer_lock:
            if not self.buffer:
                return
            
            entries = self.buffer[:]
            self.buffer = []
        
        # Write the entries
        for entry in entries:
            try:
                self._write_entry(entry)
            except Exception as e:
                logger.error(f"Failed to write audit log entry: {e}", exc_info=True)
    
    def search(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        action: Optional[Union[str, AuditAction]] = None,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        source_ip: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 1000
    ) -> List[AuditLogEntry]:
        """Search audit logs based on criteria.
        
        Note: This is a simple implementation that reads log files sequentially.
        For production use, consider using a dedicated log search system.
        """
        results = []
        
        # Convert action to string if it's an enum
        if isinstance(action, AuditAction):
            action = action.value
        
        # Get all log files that might contain the requested time range
        log_files = sorted(self.log_dir.glob("audit_*.log*"))
        
        for log_file in log_files:
            # Check if we've reached the limit
            if len(results) >= limit:
                break
                
            # Skip files outside the time range if possible
            if start_time or end_time:
                # Extract date from filename (audit_YYYY-MM-DD.log or audit_YYYY-MM-DD.log.N.gz)
                date_str = log_file.stem.split('_')[-1].split('.')[0]
                try:
                    file_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    if start_time and file_date < start_time.date():
                        continue
                    if end_time and file_date > end_time.date():
                        continue
                except (ValueError, IndexError):
                    # If we can't parse the date, include the file to be safe
                    pass
            
            # Read the log file
            try:
                if log_file.suffix == '.gz':
                    import gzip
                    with gzip.open(log_file, 'rt', encoding='utf-8') as f:
                        self._process_log_file(f, results, start_time, end_time, action, 
                                            user_id, username, source_ip, resource_type, 
                                            resource_id, status, limit)
                else:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        self._process_log_file(f, results, start_time, end_time, action, 
                                            user_id, username, source_ip, resource_type, 
                                            resource_id, status, limit)
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")
                continue
            
            # Stop if we've reached the limit
            if len(results) >= limit:
                break
        
        return results
    
    def _process_log_file(
        self,
        file_handle,
        results: List[AuditLogEntry],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        action: Optional[str],
        user_id: Optional[str],
        username: Optional[str],
        source_ip: Optional[str],
        resource_type: Optional[str],
        resource_id: Optional[str],
        status: Optional[str],
        limit: int
    ) -> None:
        """Process a log file and add matching entries to results."""
        for line in file_handle:
            try:
                # Parse the log entry
                entry_data = json.loads(line.strip())
                entry = AuditLogEntry.from_dict(entry_data)
                
                # Apply filters
                if start_time and entry.timestamp < start_time:
                    continue
                if end_time and entry.timestamp > end_time:
                    continue
                if action and entry.action != action:
                    continue
                if user_id and entry.user_id != user_id:
                    continue
                if username and entry.username != username:
                    continue
                if source_ip and entry.source_ip != source_ip:
                    continue
                if resource_type and entry.resource_type != resource_type:
                    continue
                if resource_id and entry.resource_id != resource_id:
                    continue
                if status and entry.status != status:
                    continue
                
                # Add the entry to results
                results.append(entry)
                
                # Stop if we've reached the limit
                if len(results) >= limit:
                    return
                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON in log file: {line.strip()}")
                continue
            except Exception as e:
                logger.error(f"Error processing log entry: {e}", exc_info=True)
                continue
    
    def close(self) -> None:
        """Close the audit logger and flush any pending logs."""
        self._shutdown = True
        
        # Wait for the worker thread to finish
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=5.0)
        
        # Flush any remaining logs
        self.flush()
        
        # Close the file handle
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

# Global audit logger instance
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Get the global audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        # Default configuration - should be overridden with configure_audit_logger()
        _audit_logger = AuditLogger()
    return _audit_logger

def configure_audit_logger(**kwargs) -> None:
    """Configure the global audit logger."""
    global _audit_logger
    if _audit_logger is not None:
        _audit_logger.close()
    _audit_logger = AuditLogger(**kwargs)

def log_audit_event(
    action: Union[str, AuditAction],
    **kwargs
) -> None:
    """Log an audit event using the global audit logger."""
    logger = get_audit_logger()
    logger.log(action=action, **kwargs)

# Example usage
if __name__ == "__main__":
    import logging
    import random
    from datetime import timedelta
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Configure the audit logger
    configure_audit_logger(
        log_dir="./audit_logs",
        max_file_size=1 * 1024 * 1024,  # 1 MB
        max_backups=7,  # Keep 7 days of logs
        buffer_size=10,  # Small buffer for testing
        flush_interval=1.0  # Flush every second
    )
    
    # Get the audit logger
    audit_logger = get_audit_logger()
    
    # Log some sample events
    users = ["alice", "bob", "charlie", "dave"]
    actions = [
        (AuditAction.LOGIN, "success"),
        (AuditAction.LOGIN, "failed"),
        (AuditAction.USER_UPDATE, "success"),
        (AuditAction.CONFIG_UPDATE, "success"),
        (AuditAction.DATA_ACCESS, "success")
    ]
    
    print("Generating sample audit events...")
    for i in range(20):
        action, status = random.choice(actions)
        user = random.choice(users)
        
        audit_logger.log(
            action=action,
            level=AuditLogLevel.INFO if status == "success" else AuditLogLevel.WARNING,
            username=user,
            user_id=f"user_{users.index(user) + 1}",
            source_ip=f"192.168.1.{random.randint(1, 255)}",
            user_agent=f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            status=status,
            details={
                "attempts": random.randint(1, 3) if status == "failed" else 1,
                "reason": "invalid_credentials" if status == "failed" else None
            },
            request_id=f"req_{random.randint(1000, 9999)}",
            session_id=f"sess_{random.randint(10000, 99999)}"
        )
        
        # Add some delay between events
        time.sleep(0.1)
    
    # Flush any remaining logs
    audit_logger.flush()
    
    # Search for specific events
    print("\nSearching for failed login attempts...")
    failed_logins = audit_logger.search(
        action=AuditAction.LOGIN,
        status="failed",
        limit=5
    )
    
    for entry in failed_logins:
        print(f"{entry.timestamp.isoformat()} - {entry.username} - {entry.action} - {entry.status}")
    
    # Close the audit logger
    audit_logger.close()
    print("\nDone!")
