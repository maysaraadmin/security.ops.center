"""
File Integrity Monitoring - Event Handlers

This module contains event handlers for processing file system events
detected by the FIM system.
"""
import os
import logging
import smtplib
import json
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from .core import FileEvent, EventType

logger = logging.getLogger(__name__)

class EventHandler:
    """Base class for all event handlers."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the event handler.
        
        Args:
            config: Configuration dictionary for the handler
        """
        self.config = config or {}
        self.name = self.__class__.__name__
    
    def handle(self, event: FileEvent) -> None:
        """
        Handle a file system event.
        
        Args:
            event: The file system event to handle
        """
        raise NotImplementedError("Subclasses must implement handle()")
    
    def __call__(self, event: FileEvent) -> None:
        """Allow the handler to be called as a function."""
        try:
            self.handle(event)
        except Exception as e:
            logger.error(f"Error in {self.name} handler: {e}", exc_info=True)


class LoggingHandler(EventHandler):
    """Logs file system events to a log file or console."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the logging handler.
        
        Args:
            config: Configuration dictionary with the following optional keys:
                - log_file: Path to the log file (default: None, logs to console)
                - log_level: Logging level (default: INFO)
                - format: Log message format string
        """
        super().__init__(config)
        self.log_file = self.config.get('log_file')
        self.log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        self.format_str = self.config.get(
            'format',
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Set up the logger
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Set up the logger with the specified configuration."""
        self.logger = logging.getLogger('fim.handler.logging')
        self.logger.setLevel(self.log_level)
        
        # Create formatter
        formatter = logging.Formatter(self.format_str)
        
        # Add file handler if log file is specified
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        else:
            # Default to console handler
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    def handle(self, event: FileEvent) -> None:
        """Log the file system event."""
        # Skip certain events if configured to do so
        if self.config.get('ignore_temp_files', True) and self._is_temp_file(event.src_path):
            return
        
        # Format the log message
        message = self._format_message(event)
        
        # Log the message at the appropriate level
        if event.event_type == EventType.DELETED:
            self.logger.warning(message)
        elif event.event_type in (EventType.MODIFIED, EventType.RENAMED):
            self.logger.info(message)
        else:
            self.logger.debug(message)
    
    def _format_message(self, event: FileEvent) -> str:
        """Format the log message for a file system event."""
        if event.event_type == EventType.RENAMED:
            return (f"File renamed: {event.src_path} -> {event.dest_path} "
                   f"(Size: {event.file_size or 'N/A'})")
        
        action = {
            EventType.CREATED: "created",
            EventType.MODIFIED: "modified",
            EventType.DELETED: "deleted"
        }.get(event.event_type, "changed")
        
        return (f"File {action}: {event.src_path} "
               f"(Size: {event.file_size or 'N/A'}, "
               f"Modified: {self._format_timestamp(event.last_modified)})")
    
    def _format_timestamp(self, timestamp: Optional[float]) -> str:
        """Format a timestamp for display."""
        if not timestamp:
            return "N/A"
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    
    def _is_temp_file(self, path: str) -> bool:
        """Check if a file is a temporary file."""
        temp_extensions = {'.tmp', '.temp', '~', '.swp', '.swx'}
        return any(path.lower().endswith(ext) for ext in temp_extensions)


class AlertHandler(EventHandler):
    """Handles alerts for file system events that match certain criteria."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the alert handler.
        
        Args:
            config: Configuration dictionary with the following optional keys:
                - alert_on: List of event types to alert on (default: all)
                - severity: Default severity for alerts
                - rules: List of alert rules
        """
        super().__init__(config)
        self.alert_on = set(
            getattr(EventType, t.upper()) 
            for t in self.config.get('alert_on', [t.name.lower() for t in EventType])
        )
        self.default_severity = self.config.get('severity', 'medium')
        self.rules = self.config.get('rules', [])
    
    def handle(self, event: FileEvent) -> None:
        """Process a file system event and generate alerts if needed."""
        # Skip if this event type shouldn't trigger an alert
        if event.event_type not in self.alert_on:
            return
        
        # Check if any rules match this event
        matched_rule = self._match_rule(event)
        if not matched_rule:
            return
        
        # Create the alert
        alert = self._create_alert(event, matched_rule)
        
        # Process the alert
        self._process_alert(alert, event)
    
    def _match_rule(self, event: FileEvent) -> Optional[Dict[str, Any]]:
        """Check if the event matches any alert rules."""
        for rule in self.rules:
            # Check if the event type matches
            if 'event_type' in rule:
                rule_event_type = getattr(EventType, rule['event_type'].upper(), None)
                if rule_event_type and event.event_type != rule_event_type:
                    continue
            
            # Check path patterns
            if 'path_patterns' in rule:
                if not any(event.src_path.startswith(p) for p in rule['path_patterns']):
                    continue
            
            # Check file extensions
            if 'extensions' in rule:
                _, ext = os.path.splitext(event.src_path)
                if ext.lower() not in rule['extensions']:
                    continue
            
            # All conditions matched
            return rule
        
        return None
    
    def _create_alert(self, event: FileEvent, rule: Dict[str, Any]) -> Dict[str, Any]:
        """Create an alert dictionary from an event and matching rule."""
        return {
            'id': f"fim_{int(event.timestamp * 1000)}_{hash(event.src_path)}",
            'timestamp': event.timestamp,
            'event': event.to_dict(),
            'severity': rule.get('severity', self.default_severity),
            'message': rule.get('message', f"File {event.event_type.name.lower()} detected"),
            'source': 'fim',
            'metadata': {
                'rule_id': rule.get('id', 'unknown'),
                'rule_name': rule.get('name', 'Unnamed Rule'),
                'event_type': event.event_type.name,
                'file_path': event.src_path,
                'file_size': event.file_size,
                'last_modified': event.last_modified,
                'is_directory': event.is_directory
            }
        }
    
    def _process_alert(self, alert: Dict[str, Any], event: FileEvent) -> None:
        """Process an alert (to be implemented by subclasses)."""
        # This is a placeholder - actual implementation would send the alert
        # to a monitoring system, SIEM, or other alerting mechanism
        logger.warning(
            "[ALERT %s] %s - %s",
            alert['severity'].upper(),
            alert['message'],
            event.src_path
        )


class EmailNotificationHandler(EventHandler):
    """Sends email notifications for file system events."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the email notification handler.
        
        Args:
            config: Configuration dictionary with the following required keys:
                - smtp_server: SMTP server address
                - smtp_port: SMTP server port (default: 587)
                - username: SMTP username
                - password: SMTP password
                - from_addr: Email address to send from
                - to_addrs: List of email addresses to send to
                - subject: Email subject template
                - template: Email body template (can use {event} for event data)
        """
        super().__init__(config)
        self.smtp_server = self.config.get('smtp_server')
        self.smtp_port = self.config.get('smtp_port', 587)
        self.username = self.config.get('username')
        self.password = self.config.get('password')
        self.from_addr = self.config.get('from_addr')
        self.to_addrs = self.config.get('to_addrs', [])
        self.subject_template = self.config.get(
            'subject',
            'File Integrity Alert: {event_type} - {path}'
        )
        self.template = self.config.get(
            'template',
            """A file system event has been detected:
            
            Type: {event_type}
            Path: {path}
            Time: {time}
            
            Details:
            {details}
            """
        )
        
        # Validate required configuration
        if not all([self.smtp_server, self.username, self.password, self.from_addr, self.to_addrs]):
            raise ValueError("Missing required email configuration")
    
    def handle(self, event: FileEvent) -> None:
        """Send an email notification for the file system event."""
        try:
            # Skip if this event type shouldn't trigger an email
            if not self._should_notify(event):
                return
            
            # Create the email message
            msg = self._create_email(event)
            
            # Send the email
            self._send_email(msg)
            
            logger.info(f"Sent email notification for {event.event_type.name} event: {event.src_path}")
            
        except Exception as e:
            logger.error(f"Failed to send email notification: {e}", exc_info=True)
    
    def _should_notify(self, event: FileEvent) -> bool:
        """Determine if a notification should be sent for this event."""
        # Skip temporary files if configured to do so
        if self.config.get('ignore_temp_files', True) and self._is_temp_file(event.src_path):
            return False
        
        # Check if this event type should trigger a notification
        notify_on = self.config.get('notify_on', ['created', 'modified', 'deleted'])
        notify_types = {
            'created': EventType.CREATED,
            'modified': EventType.MODIFIED,
            'deleted': EventType.DELETED,
            'renamed': EventType.RENAMED
        }
        
        for notify_type in notify_on:
            if notify_type in notify_types and event.event_type == notify_types[notify_type]:
                return True
        
        return False
    
    def _create_email(self, event: FileEvent) -> MIMEMultipart:
        """Create an email message for the file system event."""
        # Format the subject
        subject = self.subject_template.format(
            event_type=event.event_type.name,
            path=os.path.basename(event.src_path),
            full_path=event.src_path,
            time=datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Format the body
        details = [
            f"Event Type: {event.event_type.name}",
            f"Path: {event.src_path}",
            f"Time: {datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
            f"Size: {self._format_size(event.file_size) if event.file_size is not None else 'N/A'}",
            f"Modified: {datetime.fromtimestamp(event.last_modified).strftime('%Y-%m-%d %H:%M:%S') if event.last_modified else 'N/A'}",
            f"Checksum: {event.checksum or 'N/A'}",
            f"Is Directory: {'Yes' if event.is_directory else 'No'}"
        ]
        
        if event.event_type == EventType.RENAMED and event.dest_path:
            details.insert(2, f"New Path: {event.dest_path}")
        
        body = self.template.format(
            event_type=event.event_type.name,
            path=event.src_path,
            dest_path=event.dest_path or '',
            time=datetime.fromtimestamp(event.timestamp).strftime('%Y-%m-%d %H:%M:%S'),
            details='\n'.join(f"- {line}" for line in details)
        )
        
        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = self.from_addr
        msg['To'] = ', '.join(self.to_addrs)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        return msg
    
    def _send_email(self, msg: MIMEMultipart) -> None:
        """Send an email message using the configured SMTP server."""
        with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
    
    def _is_temp_file(self, path: str) -> bool:
        """Check if a file is a temporary file."""
        temp_extensions = {'.tmp', '.temp', '~', '.swp', '.swx'}
        return any(path.lower().endswith(ext) for ext in temp_extensions)
    
    def _format_size(self, size: int) -> str:
        """Format a file size in a human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


class WebhookHandler(EventHandler):
    """Sends file system events to a webhook URL."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the webhook handler.
        
        Args:
            config: Configuration dictionary with the following required keys:
                - url: Webhook URL
                - method: HTTP method (default: POST)
                - headers: Dictionary of HTTP headers
                - template: Template for the request body (can use {event} for event data)
        """
        super().__init__(config)
        self.url = self.config.get('url')
        self.method = self.config.get('method', 'POST').upper()
        self.headers = self.config.get('headers', {'Content-Type': 'application/json'})
        self.template = self.config.get('template', json.dumps({
            'event_type': '{event_type}',
            'path': '{path}',
            'timestamp': '{timestamp}',
            'details': {
                'file_size': {file_size},
                'last_modified': {last_modified},
                'is_directory': {is_directory},
                'checksum': '{checksum}'
            }
        }))
        
        # Validate required configuration
        if not self.url:
            raise ValueError("Webhook URL is required")
    
    def handle(self, event: FileEvent) -> None:
        """Send the file system event to the webhook URL."""
        try:
            # Skip if this event type shouldn't trigger a webhook
            if not self._should_send(event):
                return
            
            # Prepare the request data
            data = self._prepare_data(event)
            
            # Send the request
            self._send_webhook(data)
            
            logger.info(f"Sent webhook for {event.event_type.name} event: {event.src_path}")
            
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}", exc_info=True)
    
    def _should_send(self, event: FileEvent) -> bool:
        """Determine if a webhook should be sent for this event."""
        # Skip temporary files if configured to do so
        if self.config.get('ignore_temp_files', True) and self._is_temp_file(event.src_path):
            return False
        
        # Check if this event type should trigger a webhook
        send_on = self.config.get('send_on', ['created', 'modified', 'deleted'])
        send_types = {
            'created': EventType.CREATED,
            'modified': EventType.MODIFIED,
            'deleted': EventType.DELETED,
            'renamed': EventType.RENAMED
        }
        
        for send_type in send_on:
            if send_type in send_types and event.event_type == send_types[send_type]:
                return True
        
        return False
    
    def _prepare_data(self, event: FileEvent) -> Dict[str, Any]:
        """Prepare the data to send in the webhook request."""
        # Format the template with event data
        formatted_template = self.template.format(
            event_type=event.event_type.name,
            path=event.src_path,
            dest_path=event.dest_path or '',
            timestamp=event.timestamp,
            file_size=event.file_size,
            last_modified=event.last_modified or 0,
            is_directory='true' if event.is_directory else 'false',
            checksum=event.checksum or '',
            metadata=json.dumps(event.metadata or {})
        )
        
        # Try to parse the result as JSON
        try:
            return json.loads(formatted_template)
        except json.JSONDecodeError:
            # If it's not valid JSON, use it as a string
            return {'message': formatted_template}
    
    def _send_webhook(self, data: Dict[str, Any]) -> None:
        """Send a request to the webhook URL."""
        import requests
        
        response = requests.request(
            method=self.method,
            url=self.url,
            json=data,
            headers=self.headers,
            timeout=10  # 10 second timeout
        )
        
        # Raise an exception for HTTP errors
        response.raise_for_status()
    
    def _is_temp_file(self, path: str) -> bool:
        """Check if a file is a temporary file."""
        temp_extensions = {'.tmp', '.temp', '~', '.swp', '.swx'}
        return any(path.lower().endswith(ext) for ext in temp_extensions)
