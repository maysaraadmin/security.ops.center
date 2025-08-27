"""
Base classes for compliance reporting and auditing in SIEM.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Type, TypeVar, Union
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path
import csv
import os

class ComplianceReport(ABC):
    """Abstract base class for all compliance reports."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the compliance report."""
        self.config = config or {}
        self.report_id = self.config.get('id', self.__class__.__name__)
        self.name = self.config.get('name', self.report_id)
        self.description = self.config.get('description', '')
        self.retention_days = self.config.get('retention_days', 365)
        self.output_dir = Path(self.config.get('output_dir', 'reports'))
        self.logger = logging.getLogger(f"siem.compliance.{self.report_id}")
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self._setup()
    
    @abstractmethod
    def _setup(self) -> None:
        """Perform any necessary setup for the report."""
        pass
    
    @abstractmethod
    def generate(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Generate the compliance report.
        
        Args:
            start_time: Start of the reporting period
            end_time: End of the reporting period
            
        Returns:
            Dictionary containing the report data
        """
        pass
    
    def save_report(self, report_data: Dict[str, Any], format: str = 'json') -> str:
        """Save the report to a file.
        
        Args:
            report_data: The report data to save
            format: Output format ('json' or 'csv')
            
        Returns:
            Path to the saved report file
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.report_id}_{timestamp}.{format}"
        filepath = self.output_dir / filename
        
        try:
            if format == 'json':
                with open(filepath, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
            elif format == 'csv':
                self._save_as_csv(report_data, filepath)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            self.logger.info(f"Saved report to {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            raise
    
    def _save_as_csv(self, data: Dict[str, Any], filepath: Path) -> None:
        """Save report data as CSV."""
        if not data.get('results') or not isinstance(data['results'], list):
            raise ValueError("Report data must contain a 'results' list")
        
        with open(filepath, 'w', newline='') as f:
            if data['results']:
                writer = csv.DictWriter(f, fieldnames=data['results'][0].keys())
                writer.writeheader()
                writer.writerows(data['results'])
    
    def cleanup_old_reports(self) -> int:
        """Remove reports older than the retention period.
        
        Returns:
            Number of reports removed
        """
        if not self.output_dir.exists():
            return 0
            
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        removed = 0
        
        for file in self.output_dir.glob(f"{self.report_id}_*"):
            try:
                # Extract timestamp from filename
                timestamp_str = file.stem.split('_')[-1]
                file_time = datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
                
                if file_time < cutoff_time:
                    file.unlink()
                    removed += 1
                    
            except (ValueError, IndexError):
                continue
        
        if removed > 0:
            self.logger.info(f"Removed {removed} old reports")
            
        return removed


class AuditLogger:
    """Manages audit logging for compliance and forensics."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the audit logger."""
        self.config = config or {}
        self.log_dir = Path(self.config.get('log_dir', 'audit_logs'))
        self.retention_days = self.config.get('retention_days', 365)
        self.logger = logging.getLogger("siem.compliance.audit")
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure file handler for audit logs
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Set up file-based audit logging."""
        # Create a separate logger for audit events
        self.audit_logger = logging.getLogger('siem.audit')
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.propagate = False
        
        # Add file handler if not already configured
        if not self.audit_logger.handlers:
            log_file = self.log_dir / 'audit.log'
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))
            self.audit_logger.addHandler(file_handler)
    
    def log_event(
        self,
        event_type: str,
        actor: str,
        action: str,
        target: str,
        details: Dict[str, Any] = None,
        status: str = 'success'
    ) -> None:
        """Log an audit event.
        
        Args:
            event_type: Type of event (e.g., 'user_login', 'config_change')
            actor: Who performed the action (username, system, etc.)
            action: What action was performed
            target: What was the target of the action
            details: Additional details about the event
            status: Event status ('success', 'failure', etc.)
        """
        event = {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'event': {
                'kind': 'event',
                'category': 'audit',
                'type': [event_type],
                'action': action,
                'outcome': status
            },
            'actor': {
                'name': actor,
                'type': 'user' if actor != 'system' else 'system'
            },
            'target': target,
            'details': details or {}
        }
        
        # Log the event
        self.audit_logger.info(
            f"{event_type.upper()} - {actor} {action} {target} - {status}",
            extra={'audit_event': event}
        )
    
    def query_events(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        event_type: str = None,
        actor: str = None,
        status: str = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Query audit events.
        
        Args:
            start_time: Earliest event time
            end_time: Latest event time
            event_type: Filter by event type
            actor: Filter by actor
            status: Filter by status
            limit: Maximum number of events to return
            
        Returns:
            List of matching audit events
        """
        # This is a simplified implementation
        # In production, you'd want to use a proper database
        events = []
        
        # Default to last 24 hours if no time range specified
        if not start_time:
            start_time = datetime.utcnow() - timedelta(days=1)
        if not end_time:
            end_time = datetime.utcnow()
        
        # Search all log files in the audit log directory
        for log_file in self.log_dir.glob('*.log'):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            # Parse the log line (simplified)
                            # In a real implementation, you'd use proper log parsing
                            if 'audit_event' in line:
                                event = json.loads(line.split('audit_event=')[1])
                                
                                # Apply filters
                                event_time = datetime.fromisoformat(
                                    event['@timestamp'].replace('Z', '+00:00')
                                )
                                
                                if (event_time >= start_time and 
                                    event_time <= end_time and
                                    (not event_type or event['event']['type'] == event_type) and
                                    (not actor or event['actor']['name'] == actor) and
                                    (not status or event['event']['outcome'] == status)):
                                    
                                    events.append(event)
                                    
                                    if len(events) >= limit:
                                        return events
                                        
                        except (json.JSONDecodeError, KeyError, ValueError):
                            continue
                            
            except IOError as e:
                self.logger.error(f"Error reading log file {log_file}: {e}")
        
        return events
    
    def cleanup_old_logs(self) -> int:
        """Remove log files older than the retention period.
        
        Returns:
            Number of log files removed
        """
        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        removed = 0
        
        for log_file in self.log_dir.glob('*.log'):
            try:
                if log_file.stat().st_mtime < cutoff_time.timestamp():
                    log_file.unlink()
                    removed += 1
            except OSError as e:
                self.logger.error(f"Error removing log file {log_file}: {e}")
        
        if removed > 0:
            self.logger.info(f"Removed {removed} old log files")
            
        return removed
