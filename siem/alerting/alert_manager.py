"""
Alert Manager for SIEM.

This module handles the generation, management, and notification of security alerts.
"""
import logging
import time
from typing import Dict, List, Any, Optional, Set, Union, Callable
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Severity levels for alerts."""
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

class AlertStatus(Enum):
    """Status of an alert."""
    NEW = 'new'
    IN_PROGRESS = 'in_progress'
    RESOLVED = 'resolved'
    SUPPRESSED = 'suppressed'
    FALSE_POSITIVE = 'false_positive'

class Alert:
    """Represents a security alert."""
    
    def __init__(self, 
                alert_id: str,
                title: str, 
                description: str,
                severity: Union[str, AlertSeverity],
                source: str,
                event: Dict[str, Any],
                rule_id: Optional[str] = None,
                category: Optional[str] = None,
                status: Union[str, AlertStatus] = AlertStatus.NEW,
                tags: Optional[List[str]] = None,
                metadata: Optional[Dict[str, Any]] = None):
        """Initialize an alert.
        
        Args:
            alert_id: Unique identifier for the alert
            title: Short description of the alert
            description: Detailed description of the alert
            severity: Alert severity (info, low, medium, high, critical)
            source: Source system that generated the alert
            event: The original event that triggered the alert
            rule_id: ID of the rule that generated the alert
            category: Category of the alert (e.g., 'brute_force', 'malware')
            status: Current status of the alert
            tags: List of tags for categorization
            metadata: Additional metadata for the alert
        """
        self.id = alert_id
        self.title = title
        self.description = description
        self.severity = AlertSeverity(severity.lower()) if isinstance(severity, str) else severity
        self.source = source
        self.event = event
        self.rule_id = rule_id
        self.category = category
        self.status = AlertStatus(status) if isinstance(status, str) else status
        self.tags = set(tags or [])
        self.metadata = metadata or {}
        
        # Timestamps
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at
        self.closed_at = None
        
        # Alert metrics
        self.occurrences = 1
        self.first_seen = self.created_at
        self.last_seen = self.created_at
    
    def update(self, event: Dict[str, Any]) -> None:
        """Update the alert with a new occurrence."""
        self.occurrences += 1
        self.last_seen = datetime.utcnow()
        self.updated_at = self.last_seen
        
        # Update event data (keep the original event but add new data)
        if isinstance(event, dict):
            if 'related_events' not in self.event:
                self.event['related_events'] = []
            self.event['related_events'].append(event)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert to a dictionary."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'source': self.source,
            'rule_id': self.rule_id,
            'category': self.category,
            'status': self.status.value,
            'tags': list(self.tags),
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'occurrences': self.occurrences,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }
    
    def __str__(self) -> str:
        """String representation of the alert."""
        return f"{self.severity.value.upper()} Alert: {self.title} (ID: {self.id})"


class Notification:
    """Represents a notification for an alert."""
    
    def __init__(self, 
                alert: Alert,
                recipients: List[str],
                channel: str = 'email',
                template: Optional[str] = None):
        """Initialize a notification.
        
        Args:
            alert: The alert to notify about
            recipients: List of recipient addresses
            channel: Notification channel (email, slack, sms, etc.)
            template: Optional template for the notification
        """
        self.alert = alert
        self.recipients = recipients
        self.channel = channel
        self.template = template
        self.sent_at = None
        self.status = 'pending'  # pending, sent, failed
        self.retry_count = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the notification to a dictionary."""
        return {
            'alert_id': self.alert.id,
            'recipients': self.recipients,
            'channel': self.channel,
            'template': self.template,
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'status': self.status,
            'retry_count': self.retry_count
        }


class AlertManager:
    """Manages the lifecycle of alerts and notifications."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the alert manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.alerts: Dict[str, Alert] = {}
        self.notification_handlers = {
            'email': self._send_email_notification,
            'slack': self._send_slack_notification,
            'webhook': self._send_webhook_notification
        }
        self.alert_storage = {}
        self.notification_queue = []
        self.suppressions = set()
        
        # Configuration
        self.max_alert_age = timedelta(days=7)  # Default max age for alerts
        self.alert_aggregation_window = timedelta(minutes=5)
        self.notification_retry_attempts = 3
        self.notification_retry_delay = 60  # seconds
    
    def create_alert(self, 
                    title: str,
                    description: str,
                    severity: Union[str, AlertSeverity],
                    source: str,
                    event: Dict[str, Any],
                    rule_id: Optional[str] = None,
                    category: Optional[str] = None,
                    status: Union[str, AlertStatus] = AlertStatus.NEW,
                    tags: Optional[List[str]] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> Alert:
        """Create a new alert or update an existing one.
        
        Returns:
            The created or updated Alert object
        """
        # Generate a unique ID for the alert based on its properties
        alert_key = self._generate_alert_key(title, source, event, rule_id)
        
        # Check if this is a duplicate alert
        if alert_key in self.alerts:
            alert = self.alerts[alert_key]
            alert.update(event)
            return alert
        
        # Create a new alert
        alert_id = hashlib.sha256(
            f"{title}:{source}:{rule_id or ''}:{time.time()}"
            .encode('utf-8')
        ).hexdigest()
        
        alert = Alert(
            alert_id=alert_id,
            title=title,
            description=description,
            severity=severity,
            source=source,
            event=event,
            rule_id=rule_id,
            category=category,
            status=status,
            tags=tags,
            metadata=metadata or {}
        )
        
        self.alerts[alert_key] = alert
        
        # Queue notifications
        self._queue_notifications(alert)
        
        return alert
    
    def _generate_alert_key(self, 
                          title: str, 
                          source: str, 
                          event: Dict[str, Any], 
                          rule_id: Optional[str] = None) -> str:
        """Generate a unique key for an alert to detect duplicates."""
        # Create a stable string representation of relevant event data
        event_fingerprint = json.dumps({
            'title': title,
            'source': source,
            'rule_id': rule_id,
            # Include identifying fields from the event
            'src_ip': event.get('src_ip'),
            'dest_ip': event.get('dest_ip'),
            'user': event.get('user'),
            'process': event.get('process')
        }, sort_keys=True)
        
        return hashlib.md5(event_fingerprint.encode('utf-8')).hexdigest()
    
    def _queue_notifications(self, alert: Alert) -> None:
        """Queue notifications for an alert."""
        # Skip if alert is suppressed or not new
        if alert.status == AlertStatus.SUPPRESSED or alert.occurrences > 1:
            return
        
        # Get notification configuration
        notification_configs = self.config.get('notifications', [])
        
        for config in notification_configs:
            # Check if this notification applies to this alert
            if not self._should_notify(config, alert):
                continue
            
            # Create and queue the notification
            notification = Notification(
                alert=alert,
                recipients=config.get('recipients', []),
                channel=config.get('channel', 'email'),
                template=config.get('template')
            )
            
            self.notification_queue.append(notification)
    
    def _should_notify(self, config: Dict[str, Any], alert: Alert) -> bool:
        """Determine if a notification should be sent for an alert."""
        # Check severity threshold
        min_severity = config.get('min_severity', 'info')
        if self._get_severity_level(alert.severity) < self._get_severity_level(min_severity):
            return False
        
        # Check alert category
        if 'categories' in config and alert.category not in config['categories']:
            return False
        
        # Check alert tags
        if 'tags' in config and not any(tag in alert.tags for tag in config['tags']):
            return False
        
        # Check time-based rules (e.g., business hours)
        if not self._check_notification_timing(config):
            return False
        
        return True
    
    def _get_severity_level(self, severity: Union[str, AlertSeverity]) -> int:
        """Convert severity to a numeric level for comparison."""
        severity_map = {
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        if isinstance(severity, AlertSeverity):
            severity = severity.value
            
        return severity_map.get(severity.lower(), 0)
    
    def _check_notification_timing(self, config: Dict[str, Any]) -> bool:
        """Check if the current time is within the notification window."""
        # If no time restrictions, always notify
        if 'schedule' not in config:
            return True
        
        # Check time-based rules (e.g., business hours, weekdays)
        now = datetime.utcnow()
        schedule = config['schedule']
        
        # Check day of week
        if 'days' in schedule and now.strftime('%A').lower() not in schedule['days']:
            return False
        
        # Check time window
        if 'time_window' in schedule:
            start_time = datetime.strptime(schedule['time_window']['start'], '%H:%M').time()
            end_time = datetime.strptime(schedule['time_window']['end'], '%H:%M').time()
            
            current_time = now.time()
            if current_time < start_time or current_time > end_time:
                return False
        
        return True
    
    def process_notifications(self) -> None:
        """Process all queued notifications."""
        failed_notifications = []
        
        for notification in self.notification_queue:
            try:
                handler = self.notification_handlers.get(notification.channel)
                if handler:
                    handler(notification)
                    notification.status = 'sent'
                    notification.sent_at = datetime.utcnow()
                else:
                    logger.warning(f"No handler for notification channel: {notification.channel}")
                    notification.status = 'failed'
            except Exception as e:
                logger.error(f"Failed to send notification: {e}", exc_info=True)
                notification.retry_count += 1
                
                if notification.retry_count >= self.notification_retry_attempts:
                    notification.status = 'failed'
                    logger.error(f"Notification failed after {self.notification_retry_attempts} attempts")
                else:
                    # Requeue for retry
                    failed_notifications.append(notification)
        
        # Update the queue with failed notifications for retry
        self.notification_queue = failed_notifications
    
    def _send_email_notification(self, notification: Notification) -> bool:
        """Send an email notification."""
        # Implementation would use an email library to send the notification
        logger.info(f"Sending email to {', '.join(notification.recipients)}: {notification.alert.title}")
        return True
    
    def _send_slack_notification(self, notification: Notification) -> bool:
        """Send a Slack notification."""
        # Implementation would use the Slack API to send the notification
        logger.info(f"Sending Slack notification: {notification.alert.title}")
        return True
    
    def _send_webhook_notification(self, notification: Notification) -> bool:
        """Send a webhook notification."""
        # Implementation would make an HTTP request to the webhook URL
        logger.info(f"Sending webhook notification: {notification.alert.title}")
        return True
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        for alert in self.alerts.values():
            if alert.id == alert_id:
                return alert
        return None
    
    def update_alert_status(self, alert_id: str, status: Union[str, AlertStatus], 
                          comment: Optional[str] = None) -> bool:
        """Update the status of an alert."""
        for alert in self.alerts.values():
            if alert.id == alert_id:
                alert.status = AlertStatus(status) if isinstance(status, str) else status
                alert.updated_at = datetime.utcnow()
                
                if status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]:
                    alert.closed_at = datetime.utcnow()
                
                # Add comment to metadata if provided
                if comment:
                    if 'comments' not in alert.metadata:
                        alert.metadata['comments'] = []
                    alert.metadata['comments'].append({
                        'timestamp': datetime.utcnow().isoformat(),
                        'status': alert.status.value,
                        'comment': comment
                    })
                
                return True
        
        return False
    
    def get_alerts(self, 
                  status: Optional[Union[str, AlertStatus]] = None,
                  severity: Optional[Union[str, AlertSeverity]] = None,
                  source: Optional[str] = None,
                  rule_id: Optional[str] = None,
                  time_range: Optional[tuple] = None) -> List[Alert]:
        """Get alerts matching the specified filters."""
        results = []
        
        for alert in self.alerts.values():
            # Apply filters
            if status is not None and alert.status != status:
                continue
            if severity is not None and alert.severity != severity:
                continue
            if source is not None and alert.source != source:
                continue
            if rule_id is not None and alert.rule_id != rule_id:
                continue
            if time_range is not None:
                start_time, end_time = time_range
                if not (start_time <= alert.created_at <= end_time):
                    continue
            
            results.append(alert)
        
        return results
    
    def cleanup_old_alerts(self, max_age_days: Optional[int] = None) -> int:
        """Remove alerts older than the specified number of days.
        
        Returns:
            Number of alerts removed
        """
        if max_age_days is None:
            max_age_days = self.max_alert_age.days
        
        cutoff_time = datetime.utcnow() - timedelta(days=max_age_days)
        removed_count = 0
        
        # Create a new dict with only recent alerts
        recent_alerts = {}
        for key, alert in self.alerts.items():
            if alert.created_at >= cutoff_time:
                recent_alerts[key] = alert
            else:
                removed_count += 1
        
        self.alerts = recent_alerts
        return removed_count
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics about the alert manager."""
        return {
            'total_alerts': len(self.alerts),
            'active_alerts': sum(1 for a in self.alerts.values() 
                               if a.status not in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE]),
            'alerts_by_severity': {
                'critical': sum(1 for a in self.alerts.values() 
                              if a.severity == AlertSeverity.CRITICAL),
                'high': sum(1 for a in self.alerts.values() 
                           if a.severity == AlertSeverity.HIGH),
                'medium': sum(1 for a in self.alerts.values() 
                            if a.severity == AlertSeverity.MEDIUM),
                'low': sum(1 for a in self.alerts.values() 
                          if a.severity == AlertSeverity.LOW),
                'info': sum(1 for a in self.alerts.values() 
                           if a.severity == AlertSeverity.INFO),
            },
            'alerts_by_status': {
                'new': sum(1 for a in self.alerts.values() 
                          if a.status == AlertStatus.NEW),
                'in_progress': sum(1 for a in self.alerts.values() 
                                 if a.status == AlertStatus.IN_PROGRESS),
                'resolved': sum(1 for a in self.alerts.values() 
                              if a.status == AlertStatus.RESOLVED),
                'suppressed': sum(1 for a in self.alerts.values() 
                                if a.status == AlertStatus.SUPPRESSED),
                'false_positive': sum(1 for a in self.alerts.values() 
                                    if a.status == AlertStatus.FALSE_POSITIVE),
            },
            'pending_notifications': len(self.notification_queue),
            'last_updated': datetime.utcnow().isoformat()
        }
