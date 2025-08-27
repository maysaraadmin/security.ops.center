"""
Common correlation rules for SIEM.
"""
from datetime import timedelta
from typing import Dict, Any, List
from .base import CorrelationRule

class FailedLoginsFollowedBySuccess(CorrelationRule):
    """Detect multiple failed login attempts followed by a successful login."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the rule."""
        config = config or {}
        config.setdefault('description', 
                        'Multiple failed login attempts followed by a successful login')
        config.setdefault('severity', 'high')
        config.setdefault('failed_threshold', 3)
        config.setdefault('window_seconds', 300)  # 5 minutes
        super().__init__(config)
        
        # Track failed logins by source IP
        self.failed_logins: Dict[str, List[Dict[str, Any]]] = {}
    
    def _matches_condition(self, event: Dict[str, Any]) -> bool:
        """Check if the event is a login attempt."""
        # Check if this is an authentication event
        if event.get('event', {}).get('category') != 'authentication':
            return False
            
        # Get source IP
        src_ip = event.get('source', {}).get('ip')
        if not src_ip:
            return False
            
        # Track both success and failed logins
        outcome = event.get('event', {}).get('outcome')
        return outcome in ('success', 'failure')
    
    def _check_conditions(self) -> bool:
        """Check if correlation conditions are met."""
        # This rule processes events in add_event directly
        return False
    
    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process an authentication event."""
        # Clean up old events first
        self._cleanup_old_events()
        
        src_ip = event['source']['ip']
        outcome = event['event']['outcome']
        
        # Initialize IP tracking if needed
        if src_ip not in self.failed_logins:
            self.failed_logins[src_ip] = []
        
        # Handle failed login
        if outcome == 'failure':
            self.failed_logins[src_ip].append(event)
            return None
            
        # Handle successful login
        if outcome == 'success' and len(self.failed_logins.get(src_ip, [])) >= self.config['failed_threshold']:
            # Generate alert
            alert = self._generate_alert()
            alert['related']['ips'] = [src_ip]
            alert['related']['users'] = [event.get('user', {}).get('name')]
            
            # Include the failed login attempts in the alert
            alert['event']['original'] = json.dumps([
                {k: v for k, v in e.items() if k != 'event'} 
                for e in self.failed_logins[src_ip] + [event]
            ])
            
            # Clear the failed logins for this IP
            self.failed_logins[src_ip] = []
            
            return alert
            
        return None
    
    def _cleanup_old_events(self) -> None:
        """Remove old events from tracking."""
        now = datetime.utcnow()
        window_ago = now - self.window
        
        for ip in list(self.failed_logins.keys()):
            # Filter out old events
            self.failed_logins[ip] = [
                e for e in self.failed_logins[ip]
                if datetime.fromisoformat(e['@timestamp'].replace('Z', '+00:00')) >= window_ago
            ]
            
            # Remove IP if no more events
            if not self.failed_logins[ip]:
                del self.failed_logins[ip]


class PortScanDetection(CorrelationRule):
    """Detect potential port scanning activity."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the rule."""
        config = config or {}
        config.setdefault('description', 'Potential port scanning detected')
        config.setdefault('severity', 'medium')
        config.setdefault('port_threshold', 10)  # Number of unique ports to trigger
        config.setdefault('window_seconds', 60)  # 1 minute window
        super().__init__(config)
        
        # Track ports per source IP
        self.port_scans: Dict[str, Dict[str, Any]] = {}
    
    def _matches_condition(self, event: Dict[str, Any]) -> bool:
        """Check if the event is a network connection attempt."""
        return (
            event.get('event', {}).get('category') == 'network' and
            event.get('network', {}).get('type') == 'connection_attempt' and
            event.get('destination', {}).get('port') is not None and
            event.get('source', {}).get('ip') is not None
        )
    
    def _check_conditions(self) -> bool:
        """Check if correlation conditions are met."""
        # This rule processes events in add_event directly
        return False
    
    def add_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a network connection event."""
        # Clean up old events first
        self._cleanup_old_events()
        
        src_ip = event['source']['ip']
        dst_port = event['destination']['port']
        
        # Initialize tracking for this IP if needed
        if src_ip not in self.port_scans:
            self.port_scans[src_ip] = {
                'ports': set(),
                'first_seen': datetime.utcnow(),
                'events': []
            }
        
        # Add port to the set and track the event
        self.port_scans[src_ip]['ports'].add(dst_port)
        self.port_scans[src_ip]['events'].append(event)
        
        # Check if threshold is reached
        if len(self.port_scans[src_ip]['ports']) >= self.config['port_threshold']:
            alert = self._generate_alert()
            alert['related']['ips'] = [src_ip]
            alert['related']['ports'] = list(self.port_scans[src_ip]['ports'])
            alert['event']['original'] = json.dumps([
                {k: v for k, v in e.items() if k != 'event'} 
                for e in self.port_scans[src_ip]['events']
            ])
            
            # Reset tracking for this IP
            del self.port_scans[src_ip]
            
            return alert
            
        return None
    
    def _cleanup_old_events(self) -> None:
        """Remove old port scan tracking data."""
        now = datetime.utcnow()
        window_ago = now - self.window
        
        for ip in list(self.port_scans.keys()):
            if self.port_scans[ip]['first_seen'] < window_ago:
                del self.port_scans[ip]


class SuspiciousCommandExecution(CorrelationRule):
    """Detect suspicious command execution patterns."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the rule."""
        config = config or {}
        config.setdefault('description', 'Suspicious command execution detected')
        config.setdefault('severity', 'high')
        config.setdefault('suspicious_commands', [
            'rm -rf', 'chmod', 'chown', 'wget', 'curl', 'nc ', 'netcat',
            'ncat', 'bash -c', 'sh -c', 'powershell', 'certutil', 'bitsadmin'
        ])
        super().__init__(config)
    
    def _matches_condition(self, event: Dict[str, Any]) -> bool:
        """Check if the event contains a suspicious command."""
        if event.get('event', {}).get('category') != 'process':
            return False
            
        command = event.get('process', {}).get('command_line', '').lower()
        return any(cmd in command for cmd in self.config['suspicious_commands'])
    
    def _check_conditions(self) -> bool:
        """Check if correlation conditions are met."""
        # For this rule, any matching event triggers an alert
        return bool(self.events)
    
    def _generate_alert(self) -> Dict[str, Any]:
        """Generate an alert with command details."""
        if not self.events:
            return None
            
        event = self.events[-1]  # Get the most recent event
        
        alert = super()._generate_alert()
        alert['process'] = event.get('process', {})
        
        return alert
