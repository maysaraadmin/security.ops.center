"""
Alerting system for the SIEM.
"""

import json
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Callable, Union
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from threading import Lock, Thread
from queue import Queue, Empty
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Import metrics for alerting on metrics
from .metrics import metrics_collector

class AlertSeverity(Enum):
    """Severity levels for alerts."""
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class AlertStatus(Enum):
    """Status of an alert."""
    TRIGGERED = auto()
    ACKNOWLEDGED = auto()
    RESOLVED = auto()
    SUPPRESSED = auto()

@dataclass
class Alert:
    """Represents an alert in the SIEM system."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    status: AlertStatus = AlertStatus.TRIGGERED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = 'siem'
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the alert to a dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.name,
            'status': self.status.name,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'source': self.source,
            'labels': self.labels,
            'annotations': self.annotations,
            'details': self.details
        }
    
    def update(self, **kwargs) -> None:
        """Update alert fields."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.updated_at = datetime.now(timezone.utc)

class AlertRule:
    """Defines a rule for generating alerts."""
    
    def __init__(self, 
                 name: str,
                 description: str,
                 condition: Callable[[Dict[str, Any]], bool],
                 severity: AlertSeverity = AlertSeverity.MEDIUM,
                 source: str = 'siem',
                 labels: Optional[Dict[str, str]] = None,
                 annotations: Optional[Dict[str, str]] = None,
                 throttle_seconds: int = 300):
        """Initialize the alert rule.
        
        Args:
            name: Name of the alert rule
            description: Description of the alert rule
            condition: Function that takes an event and returns True if an alert should be triggered
            severity: Severity of the alert
            source: Source of the alert
            labels: Labels to attach to the alert
            annotations: Annotations to attach to the alert
            throttle_seconds: Minimum time between alerts for the same rule (to prevent alert storms)
        """
        self.name = name
        self.description = description
        self.condition = condition
        self.severity = severity
        self.source = source
        self.labels = labels or {}
        self.annotations = annotations or {}
        self.throttle_seconds = throttle_seconds
        self.last_triggered: Dict[str, float] = {}
        self.lock = Lock()
    
    def evaluate(self, event: Dict[str, Any]) -> Optional[Alert]:
        """Evaluate the rule against an event.
        
        Args:
            event: The event to evaluate
            
        Returns:
            An Alert if the rule matches, None otherwise
        """
        try:
            # Check if the condition is met
            if not self.condition(event):
                return None
            
            # Check if we're in the throttle period
            with self.lock:
                now = time.time()
                last_triggered = self.last_triggered.get(self.name, 0)
                
                if now - last_triggered < self.throttle_seconds:
                    return None
                
                # Update the last triggered time
                self.last_triggered[self.name] = now
            
            # Create the alert
            alert_id = f"{self.source}:{self.name}:{int(time.time())}"
            
            return Alert(
                id=alert_id,
                name=self.name,
                description=self.description,
                severity=self.severity,
                source=self.source,
                labels=self.labels.copy(),
                annotations=self.annotations.copy(),
                details={
                    'event': event,
                    'rule': {
                        'name': self.name,
                        'description': self.description,
                        'severity': self.severity.name,
                        'source': self.source
                    }
                }
            )
            
        except Exception as e:
            logging.error(f"Error evaluating alert rule {self.name}: {e}")
            return None

class AlertManager:
    """Manages alerts and alert rules."""
    
    def __init__(self):
        """Initialize the alert manager."""
        self.rules: List[AlertRule] = []
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.max_history: int = 1000
        self.lock = Lock()
        self.logger = logging.getLogger('siem.alerts')
        self.alert_queue = Queue()
        self._stop_event = threading.Event()
        self._processor_thread = None
    
    def add_rule(self, rule: AlertRule) -> None:
        """Add an alert rule."""
        with self.lock:
            self.rules.append(rule)
    
    def remove_rule(self, name: str) -> bool:
        """Remove an alert rule by name."""
        with self.lock:
            for i, rule in enumerate(self.rules):
                if rule.name == name:
                    self.rules.pop(i)
                    return True
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Alert]:
        """Process an event and return any generated alerts.
        
        Args:
            event: The event to process
            
        Returns:
            List of generated alerts
        """
        alerts = []
        
        # Evaluate all rules
        with self.lock:
            for rule in self.rules:
                try:
                    alert = rule.evaluate(event)
                    if alert:
                        alerts.append(alert)
                except Exception as e:
                    self.logger.error(f"Error processing event with rule {rule.name}: {e}")
        
        # Add alerts to the queue for processing
        for alert in alerts:
            self.alert_queue.put(alert)
        
        return alerts
    
    def start_processing(self) -> None:
        """Start the alert processing thread."""
        if self._processor_thread is not None and self._processor_thread.is_alive():
            self.logger.warning("Alert processor is already running")
            return
            
        self._stop_event.clear()
        self._processor_thread = threading.Thread(
            target=self._process_alerts,
            name='alert_processor',
            daemon=True
        )
        self._processor_thread.start()
        self.logger.info("Started alert processor")
    
    def stop_processing(self) -> None:
        """Stop the alert processing thread."""
        self._stop_event.set()
        if self._processor_thread is not None:
            self._processor_thread.join(timeout=5.0)
        self.logger.info("Stopped alert processor")
    
    def _process_alerts(self) -> None:
        """Process alerts from the queue."""
        while not self._stop_event.is_set():
            try:
                # Get an alert from the queue with a timeout
                try:
                    alert = self.alert_queue.get(timeout=1.0)
                except Empty:
                    continue
                
                # Process the alert
                try:
                    self._handle_alert(alert)
                except Exception as e:
                    self.logger.error(f"Error processing alert {alert.id}: {e}")
                
                # Mark the alert as done
                self.alert_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in alert processor: {e}")
                time.sleep(1)  # Prevent tight loop on error
    
    def _handle_alert(self, alert: Alert) -> None:
        """Handle a new alert."""
        with self.lock:
            # Add to active alerts
            self.active_alerts[alert.id] = alert
            
            # Add to history
            self.alert_history.append(alert)
            
            # Trim history if needed
            if len(self.alert_history) > self.max_history:
                self.alert_history = self.alert_history[-self.max_history:]
            
            self.logger.info(f"New alert: {alert.name} (severity: {alert.severity.name})")
            
            # TODO: Notify configured alert destinations
            # This would be implemented with a plugin system for different notification channels
            self._notify_alert(alert)
    
    def _notify_alert(self, alert: Alert) -> None:
        """Send alert notifications."""
        # This is a placeholder for notification logic
        # In a real implementation, this would support multiple notification channels
        # like email, Slack, PagerDuty, etc.
        
        # Log the alert
        self.logger.warning(
            f"ALERT: {alert.name} - {alert.description} "
            f"(severity: {alert.severity.name}, id: {alert.id})"
        )
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts."""
        with self.lock:
            return [alert.to_dict() for alert in self.active_alerts.values()]
    
    def get_alert_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alert history."""
        with self.lock:
            return [alert.to_dict() for alert in self.alert_history[-limit:]]
    
    def acknowledge_alert(self, alert_id: str, user: str = 'system', 
                         comment: Optional[str] = None) -> bool:
        """Acknowledge an alert."""
        with self.lock:
            if alert_id not in self.active_alerts:
                return False
                
            alert = self.active_alerts[alert_id]
            alert.update(
                status=AlertStatus.ACKNOWLEDGED,
                annotations={
                    **alert.annotations,
                    'acknowledged_by': user,
                    'acknowledged_at': datetime.now(timezone.utc).isoformat(),
                    'acknowledgement_comment': comment or ''
                }
            )
            
            self.logger.info(f"Alert {alert_id} acknowledged by {user}")
            return True
    
    def resolve_alert(self, alert_id: str, user: str = 'system', 
                      comment: Optional[str] = None) -> bool:
        """Resolve an alert."""
        with self.lock:
            if alert_id not in self.active_alerts:
                return False
                
            alert = self.active_alerts[alert_id]
            alert.update(
                status=AlertStatus.RESOLVED,
                annotations={
                    **alert.annotations,
                    'resolved_by': user,
                    'resolved_at': datetime.now(timezone.utc).isoformat(),
                    'resolution_comment': comment or ''
                }
            )
            
            # Move to history and remove from active
            self.alert_history.append(alert)
            del self.active_alerts[alert_id]
            
            self.logger.info(f"Alert {alert_id} resolved by {user}")
            return True

# Global alert manager instance
alert_manager = AlertManager()

# Common alert rules
class CommonAlertRules:
    """Commonly used alert rules."""
    
    @staticmethod
    def high_error_rate(error_threshold: float = 0.1, 
                       window_minutes: int = 5) -> AlertRule:
        """Alert when the error rate exceeds a threshold."""
        def condition(metrics):
            # This is a simplified example - in practice, you'd want to track
            # request counts and error counts over time
            error_count = metrics.get('siem.errors.count', 0)
            request_count = metrics.get('siem.requests.count', 1)  # Avoid division by zero
            
            error_rate = error_count / request_count
            return error_rate > error_threshold
        
        return AlertRule(
            name="high_error_rate",
            description=f"Error rate exceeds {error_threshold*100:.0f}%",
            condition=condition,
            severity=AlertSeverity.HIGH,
            labels={"type": "performance", "component": "siem"},
            annotations={
                "summary": "High error rate detected",
                "runbook": "Check the SIEM logs for error messages and review system health"
            }
        )
    
    @staticmethod
    def failed_login_attempts(threshold: int = 5, 
                             window_minutes: int = 1) -> AlertRule:
        """Alert on multiple failed login attempts."""
        # This would be implemented with a time window tracker
        # For simplicity, this is a placeholder
        def condition(event):
            return (
                event.get('event_type') == 'authentication' and 
                event.get('outcome') == 'failure' and
                event.get('attempts', 0) >= threshold
            )
        
        return AlertRule(
            name="failed_login_attempts",
            description=f"More than {threshold} failed login attempts in {window_minutes} minutes",
            condition=condition,
            severity=AlertSeverity.MEDIUM,
            labels={"type": "security", "component": "authentication"},
            annotations={
                "summary": "Multiple failed login attempts detected",
                "runbook": "Review authentication logs for suspicious activity"
            }
        )
    
    @staticmethod
    def high_cpu_usage(threshold: float = 90.0) -> AlertRule:
        """Alert when CPU usage exceeds a threshold."""
        def condition(metrics):
            return metrics.get('system.cpu.percent', 0) > threshold
        
        return AlertRule(
            name="high_cpu_usage",
            description=f"CPU usage exceeds {threshold}%",
            condition=condition,
            severity=AlertSeverity.MEDIUM,
            labels={"type": "system", "component": "cpu"},
            annotations={
                "summary": "High CPU usage detected",
                "runbook": "Check system processes and resource utilization"
            }
        )
    
    @staticmethod
    def high_memory_usage(threshold: float = 90.0) -> AlertRule:
        """Alert when memory usage exceeds a threshold."""
        def condition(metrics):
            return metrics.get('system.memory.percent', 0) > threshold
        
        return AlertRule(
            name="high_memory_usage",
            description=f"Memory usage exceeds {threshold}%",
            condition=condition,
            severity=AlertSeverity.MEDIUM,
            labels={"type": "system", "component": "memory"},
            annotations={
                "summary": "High memory usage detected",
                "runbook": "Check for memory leaks and review system resource allocation"
            }
        )

# Example usage
if __name__ == "__main__":
    import logging
    import random
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Create an alert manager
    manager = AlertManager()
    
    # Add some common alert rules
    manager.add_rule(CommonAlertRules.high_error_rate())
    manager.add_rule(CommonAlertRules.failed_login_attempts())
    manager.add_rule(CommonAlertRules.high_cpu_usage())
    manager.add_rule(CommonAlertRules.high_memory_usage())
    
    # Start the alert processor
    manager.start_processing()
    
    # Simulate some events
    try:
        while True:
            # Simulate a random event
            event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': random.choice(['authentication', 'api_request', 'system']),
                'outcome': random.choice(['success', 'failure']),
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'user': f"user{random.randint(1, 10)}",
                'attempts': random.randint(1, 10)
            }
            
            # Process the event
            manager.process_event(event)
            
            # Simulate some metrics
            metrics = {
                'siem.requests.count': random.randint(1, 1000),
                'siem.errors.count': random.randint(0, 100),
                'system.cpu.percent': random.uniform(0, 100),
                'system.memory.percent': random.uniform(0, 100)
            }
            
            # Process metrics as an event
            metrics_event = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'event_type': 'metrics',
                'metrics': metrics
            }
            manager.process_event(metrics_event)
            
            # Sleep for a bit
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping alert processor...")
        manager.stop_processing()
