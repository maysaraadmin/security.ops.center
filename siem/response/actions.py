"""
Common response actions for SIEM incident response.
"""
import subprocess
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
import socket
import platform
import os

from .base import ResponseAction

class BlockIPAction(ResponseAction):
    """Blocks an IP address using the system firewall."""
    
    def _setup(self) -> None:
        """Set up the IP blocking action."""
        self.block_duration = timedelta(
            minutes=self.config.get('block_duration_minutes', 60)
        )
        self.blocked_ips: Dict[str, datetime] = {}
        self.platform = platform.system().lower()
        self.logger = logging.getLogger("siem.response.block_ip")
        
        # Platform-specific commands
        self._init_platform_commands()
    
    def _init_platform_commands(self) -> None:
        """Initialize platform-specific firewall commands."""
        if self.platform == 'windows':
            self.add_rule_cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                'name="SIEM Blocked IP {ip}"',
                'dir=out',
                'action=block',
                'enable=yes',
                'remoteip={ip}'
            ]
            self.delete_rule_cmd = [
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name="SIEM Blocked IP {ip}"'
            ]
        elif self.platform == 'linux':
            # Using iptables for Linux
            self.add_rule_cmd = [
                'iptables', '-A', 'INPUT',
                '-s', '{ip}',
                '-j', 'DROP'
            ]
            self.delete_rule_cmd = [
                'iptables', '-D', 'INPUT',
                '-s', '{ip}',
                '-j', 'DROP'
            ]
        else:
            self.logger.warning(f"Unsupported platform for IP blocking: {self.platform}")
            self.add_rule_cmd = None
            self.delete_rule_cmd = None
    
    def _block_ip_windows(self, ip: str) -> bool:
        """Block an IP address on Windows."""
        try:
            cmd = [part.format(ip=ip) for part in self.add_rule_cmd]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            self.logger.info(f"Blocked IP {ip} on Windows: {result.stdout}")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip} on Windows: {e.stderr}")
            return False
    
    def _block_ip_linux(self, ip: str) -> bool:
        """Block an IP address on Linux."""
        try:
            cmd = [part.format(ip=ip) for part in self.add_rule_cmd]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            self.logger.info(f"Blocked IP {ip} on Linux")
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip} on Linux: {e.stderr}")
            return False
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the IP blocking action."""
        # Extract IPs from the alert
        ips = set()
        
        # Get IPs from related.ips if available
        for ip in alert.get('related', {}).get('ips', []):
            if self._is_valid_ip(ip):
                ips.add(ip)
        
        # Also check source.ip if available
        if 'source' in alert and 'ip' in alert['source']:
            ip = alert['source']['ip']
            if self._is_valid_ip(ip):
                ips.add(ip)
        
        if not ips:
            return self._log_action('block_ip', {
                'success': False,
                'message': 'No valid IP addresses found in alert',
                'target': {}
            })
        
        results = {}
        for ip in ips:
            # Skip if already blocked
            if ip in self.blocked_ips:
                self.logger.debug(f"IP {ip} is already blocked")
                results[ip] = 'already_blocked'
                continue
            
            # Block the IP
            success = False
            if self.platform == 'windows':
                success = self._block_ip_windows(ip)
            elif self.platform == 'linux':
                success = self._block_ip_linux(ip)
            
            if success:
                self.blocked_ips[ip] = datetime.utcnow()
                results[ip] = 'blocked'
            else:
                results[ip] = 'failed'
        
        return self._log_action('block_ip', {
            'success': any(v == 'blocked' for v in results.values()),
            'message': f"Blocked IPs: {', '.join(ip for ip, status in results.items() if status == 'blocked')}",
            'target': {'ips': list(ips), 'results': results}
        })
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if an IP address is valid."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False


class QuarantineFileAction(ResponseAction):
    """Quarantines a suspicious file."""
    
    def _setup(self) -> None:
        """Set up the quarantine action."""
        self.quarantine_dir = self.config.get(
            'quarantine_dir',
            os.path.join(os.path.expanduser('~'), 'quarantine')
        )
        
        # Create quarantine directory if it doesn't exist
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        self.logger = logging.getLogger("siem.response.quarantine_file")
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the file quarantine action."""
        if 'file' not in alert or 'path' not in alert['file']:
            return self._log_action('quarantine_file', {
                'success': False,
                'message': 'No file path in alert',
                'target': {}
            })
        
        file_path = alert['file']['path']
        
        if not os.path.exists(file_path):
            return self._log_action('quarantine_file', {
                'success': False,
                'message': f'File not found: {file_path}',
                'target': {'path': file_path}
            })
        
        try:
            # Generate a unique quarantine filename
            file_name = os.path.basename(file_path)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            quarantined_name = f"{timestamp}_{file_name}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantined_name)
            
            # Move the file to quarantine
            os.rename(file_path, quarantine_path)
            
            # Optionally, log the quarantine action
            self.logger.info(f"Quarantined file: {file_path} -> {quarantine_path}")
            
            return self._log_action('quarantine_file', {
                'success': True,
                'message': f'Successfully quarantined {file_path}',
                'target': {
                    'original_path': file_path,
                    'quarantine_path': quarantine_path
                }
            })
            
        except Exception as e:
            self.logger.error(f"Failed to quarantine file {file_path}: {str(e)}")
            return self._log_action('quarantine_file', {
                'success': False,
                'message': f'Failed to quarantine file: {str(e)}',
                'target': {'path': file_path}
            })


class NotifyAction(ResponseAction):
    """Sends a notification about an alert."""
    
    def _setup(self) -> None:
        """Set up the notification action."""
        self.recipients = self.config.get('recipients', [])
        self.notification_method = self.config.get('method', 'log')
        self.logger = logging.getLogger("siem.response.notify")
    
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Send a notification about the alert."""
        if not self.recipients:
            self.logger.warning("No recipients configured for notification")
            return self._log_action('notify', {
                'success': False,
                'message': 'No recipients configured',
                'target': {}
            })
        
        # Format the notification
        notification = self._format_notification(alert)
        
        # Send the notification using the configured method
        success = False
        if self.notification_method == 'log':
            self.logger.info(f"[NOTIFICATION] {notification}")
            success = True
        elif self.notification_method == 'email':
            success = self._send_email(notification)
        elif self.notification_method == 'slack':
            success = self._send_slack(notification)
        else:
            self.logger.warning(f"Unsupported notification method: {self.notification_method}")
        
        return self._log_action('notify', {
            'success': success,
            'message': f'Sent {self.notification_method} notification',
            'target': {
                'recipients': self.recipients,
                'method': self.notification_method,
                'content': notification
            }
        })
    
    def _format_notification(self, alert: Dict[str, Any]) -> str:
        """Format the notification message."""
        return (
            f"[ALERT] {alert.get('event', {}).get('signature', 'Unknown threat')}\n"
            f"Severity: {alert.get('event', {}).get('severity', 'unknown')}\n"
            f"Time: {alert.get('@timestamp', 'unknown')}\n"
            f"Description: {alert.get('message', 'No description')}"
        )
    
    def _send_email(self, message: str) -> bool:
        """Send an email notification."""
        # This is a placeholder - implement actual email sending logic
        self.logger.info(f"Would send email to {self.recipients}: {message}")
        return True
    
    def _send_slack(self, message: str) -> bool:
        """Send a Slack notification."""
        # This is a placeholder - implement actual Slack integration
        self.logger.info(f"Would send Slack message: {message}")
        return True
