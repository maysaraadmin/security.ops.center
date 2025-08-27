"""
Network Detection Engine for NDR.
Analyzes network traffic and identifies potential security threats.
"""
import re
import ipaddress
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
import logging

class DetectionRule:
    """Represents a detection rule for network traffic."""
    
    def __init__(self, 
                 rule_id: str, 
                 name: str, 
                 description: str, 
                 severity: str,
                 condition: Callable[[Dict], bool],
                 tags: List[str] = None):
        """
        Initialize a detection rule.
        
        Args:
            rule_id: Unique identifier for the rule
            name: Human-readable name
            description: Description of what the rule detects
            severity: Severity level (info, low, medium, high, critical)
            condition: Function that takes a packet_info dict and returns True if the rule matches
            tags: List of tags for categorization
        """
        self.id = rule_id
        self.name = name
        self.description = description
        self.severity = severity.lower()
        self.condition = condition
        self.tags = tags or []
        self.enabled = True


class DetectionEngine:
    """Analyzes network traffic and detects potential threats."""
    
    def __init__(self):
        """Initialize the detection engine with default rules."""
        self.rules: Dict[str, DetectionRule] = {}
        self.alert_callbacks = []
        self.logger = logging.getLogger(__name__)
        self._setup_default_rules()
    
    def add_rule(self, rule: DetectionRule):
        """Add a detection rule to the engine."""
        self.rules[rule.id] = rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a detection rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            return True
        return False
    
    def add_alert_callback(self, callback: Callable[[Dict], None]):
        """Add a callback function to be called when an alert is generated."""
        self.alert_callbacks.append(callback)
    
    def analyze_packet(self, packet_info: Dict) -> List[Dict]:
        """
        Analyze a network packet against all enabled rules.
        
        Returns:
            List of alerts generated for this packet
        """
        alerts = []
        
        for rule in self.rules.values():
            if not rule.enabled:
                continue
                
            try:
                if rule.condition(packet_info):
                    alert = {
                        'rule_id': rule.id,
                        'name': rule.name,
                        'description': rule.description,
                        'severity': rule.severity,
                        'timestamp': packet_info.get('timestamp', datetime.utcnow().isoformat()),
                        'source_ip': packet_info.get('src_ip'),
                        'destination_ip': packet_info.get('dst_ip'),
                        'protocol': packet_info.get('protocol'),
                        'source_port': packet_info.get('src_port'),
                        'destination_port': packet_info.get('dst_port'),
                        'payload_preview': str(packet_info.get('payload', ''))[:200],
                        'tags': rule.tags
                    }
                    alerts.append(alert)
                    
                    # Notify callbacks
                    for callback in self.alert_callbacks:
                        try:
                            callback(alert)
                        except Exception as e:
                            self.logger.error(f"Error in alert callback: {e}")
                            
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.id}: {e}")
        
        return alerts
    
    def _setup_default_rules(self):
        """Initialize the detection engine with default rules."""
        # Port scanning detection
        self.add_rule(DetectionRule(
            rule_id="ndr-1001",
            name="Port Scanning Detected",
            description="Multiple connection attempts to different ports from the same source",
            severity="high",
            condition=self._detect_port_scan,
            tags=["reconnaissance", "scanning"]
        ))
        
        # Suspicious DNS queries
        self.add_rule(DetectionRule(
            rule_id="ndr-1002",
            name="Suspicious DNS Query",
            description="DNS query to known malicious domain",
            severity="medium",
            condition=self._detect_malicious_dns,
            tags=["dns", "malware"]
        ))
        
        # Large data exfiltration
        self.add_rule(DetectionRule(
            rule_id="ndr-1003",
            name="Possible Data Exfiltration",
            description="Large amount of data being sent to external IP",
            severity="high",
            condition=self._detect_data_exfiltration,
            tags=["exfiltration", "data_leak"]
        ))
        
        # Unusual protocol usage
        self.add_rule(DetectionRule(
            rule_id="ndr-1004",
            name="Unusual Protocol Usage",
            description="Unusual protocol or port usage detected",
            severity="medium",
            condition=self._detect_unusual_protocol,
            tags=["anomaly"]
        ))
    
    # Rule condition functions
    def _detect_port_scan(self, packet_info: Dict) -> bool:
        """Detect potential port scanning activity."""
        # This is a simplified example - in a real implementation, you would track
        # connection attempts over time to detect scanning patterns
        if packet_info.get('protocol') in ['tcp', 'udp']:
            # Check for connection attempts to multiple ports
            # In a real implementation, this would track state across packets
            return False
        return False
    
    def _detect_malicious_dns(self, packet_info: Dict) -> bool:
        """Detect DNS queries to known malicious domains."""
        if packet_info.get('protocol') == 'udp' and packet_info.get('dst_port') == 53:
            # In a real implementation, check against a threat intelligence feed
            # This is a simplified example
            suspicious_domains = [
                r"malware\.com$",
                r"command-and-control\.cc$",
                r"\.onion$"
            ]
            
            payload = packet_info.get('payload', '').lower()
            for domain in suspicious_domains:
                if re.search(domain, payload):
                    return True
        return False
    
    def _detect_data_exfiltration(self, packet_info: Dict) -> bool:
        """Detect potential data exfiltration attempts."""
        # Check for large outbound transfers to external IPs
        if packet_info.get('length', 0) > 10000:  # Example threshold: 10KB
            try:
                # Check if destination is a private IP
                dst_ip = ipaddress.ip_address(packet_info.get('dst_ip', ''))
                if not dst_ip.is_private:
                    return True
            except (ValueError, AttributeError):
                pass
        return False
    
    def _detect_unusual_protocol(self, packet_info: Dict) -> bool:
        """Detect unusual protocol usage."""
        # Example: Detect non-standard ports for common protocols
        protocol_ports = {
            'http': [80, 8080, 443, 8443],
            'https': [443, 8443],
            'ssh': [22],
            'rdp': [3389],
            'dns': [53],
            'smb': [139, 445]
        }
        
        protocol = packet_info.get('protocol', '').lower()
        dst_port = packet_info.get('dst_port')
        
        if protocol in protocol_ports and dst_port:
            if dst_port not in protocol_ports[protocol]:
                return True
                
        return False
