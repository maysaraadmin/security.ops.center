"""
Detection Engine for NIPS - Analyzes network packets for potential threats.
"""
import logging
import re
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime

class DetectionEngine:
    """
    Analyzes network packets against a set of rules to detect potential threats.
    """
    
    def __init__(self):
        """Initialize the detection engine with default rules."""
        self.logger = logging.getLogger(__name__)
        self.rules = []
        self.alert_callbacks = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default detection rules."""
        default_rules = [
            {
                'id': 'nips-001',
                'name': 'Port Scan Detection',
                'description': 'Detects potential port scanning activity',
                'severity': 'high',
                'condition': {
                    'type': 'port_scan',
                    'threshold': 10,  # Number of ports
                    'time_window': 30  # seconds
                },
                'action': 'alert_and_block'
            },
            {
                'id': 'nips-002',
                'name': 'Suspicious HTTP Request',
                'description': 'Detects suspicious HTTP requests (SQLi, XSS, etc.)',
                'severity': 'high',
                'condition': {
                    'type': 'http_request',
                    'patterns': [
                        r'(?i)(union\s+select|select\s+\*|1=1|sleep\s*\(|waitfor\s+delay)',  # SQLi
                        r'(?i)(<script>|javascript:)|(document\.|window\.|eval\(|alert\()'  # XSS
                    ]
                },
                'action': 'block'
            },
            {
                'id': 'nips-003',
                'name': 'Known Malicious IP',
                'description': 'Traffic to/from known malicious IP addresses',
                'severity': 'critical',
                'condition': {
                    'type': 'ip_address',
                    'blacklist': [
                        # This would be loaded from a threat intelligence feed in production
                        '192.168.1.100',  # Example malicious IP
                        '10.0.0.5'        # Example malicious IP
                    ]
                },
                'action': 'block'
            },
            {
                'id': 'nips-004',
                'name': 'ICMP Flood',
                'description': 'Detects potential ICMP flood attacks',
                'severity': 'high',
                'condition': {
                    'type': 'icmp_flood',
                    'threshold': 100,  # ICMP packets
                    'time_window': 1   # second
                },
                'action': 'alert_and_block'
            },
            {
                'id': 'nips-005',
                'name': 'Suspicious DNS Query',
                'description': 'Detects suspicious DNS queries (DGA, data exfiltration, etc.)',
                'severity': 'medium',
                'condition': {
                    'type': 'dns_query',
                    'patterns': [
                        r'(?i)(xn--|\w{30,}\.|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
                        r'(?i)(exploit|malware|ransomware|botnet)\.'
                    ]
                },
                'action': 'alert'
            }
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: Dict[str, Any]):
        """
        Add a new detection rule.
        
        Args:
            rule: Dictionary containing rule definition
        """
        # Validate rule structure
        required_fields = ['id', 'name', 'description', 'severity', 'condition', 'action']
        if not all(field in rule for field in required_fields):
            self.logger.error(f"Invalid rule format, missing required fields: {rule}")
            return False
            
        # Check for duplicate rule ID
        if any(r['id'] == rule['id'] for r in self.rules):
            self.logger.warning(f"Rule with ID {rule['id']} already exists, updating")
            self.remove_rule(rule['id'])
        
        self.rules.append(rule)
        self.logger.info(f"Added rule: {rule['name']} (ID: {rule['id']})")
        return True
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a detection rule by ID.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            bool: True if rule was found and removed, False otherwise
        """
        for i, rule in enumerate(self.rules):
            if rule['id'] == rule_id:
                self.rules.pop(i)
                self.logger.info(f"Removed rule ID: {rule_id}")
                return True
        
        self.logger.warning(f"Rule with ID {rule_id} not found")
        return False
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Get all detection rules.
        
        Returns:
            List of rule dictionaries
        """
        return self.rules.copy()
    
    def analyze_packet(self, packet) -> bool:
        """
        Analyze a network packet against all rules.
        
        Args:
            packet: The packet to analyze
            
        Returns:
            bool: True if a threat was detected, False otherwise
        """
        if not hasattr(packet, 'payload'):
            return False
            
        threat_detected = False
        
        for rule in self.rules:
            if self._matches_rule(packet, rule):
                self.logger.warning(f"Rule triggered: {rule['name']}")
                self._trigger_alert(packet, rule)
                threat_detected = True
                
                # If rule specifies to block, we can stop further processing
                if rule.get('action') in ['block', 'alert_and_block']:
                    return True
        
        return threat_detected
    
    def _matches_rule(self, packet, rule: Dict[str, Any]) -> bool:
        """
        Check if a packet matches a specific rule.
        
        Args:
            packet: The packet to check
            rule: The rule to check against
            
        Returns:
            bool: True if the packet matches the rule, False otherwise
        """
        condition = rule.get('condition', {})
        condition_type = condition.get('type')
        
        if condition_type == 'port_scan':
            # This would be implemented with state tracking across multiple packets
            # For now, this is a placeholder
            return False
            
        elif condition_type == 'http_request' and hasattr(packet, 'load'):
            # Check for suspicious patterns in HTTP requests
            payload = str(packet.load).lower()
            for pattern in condition.get('patterns', []):
                if re.search(pattern, payload):
                    return True
                    
        elif condition_type == 'ip_address':
            # Check if source or destination IP is in blacklist
            blacklist = condition.get('blacklist', [])
            src_ip = getattr(packet, 'src', '')
            dst_ip = getattr(packet, 'dst', '')
            
            return src_ip in blacklist or dst_ip in blacklist
            
        elif condition_type == 'icmp_flood':
            # This would be implemented with state tracking across multiple ICMP packets
            # For now, this is a placeholder
            return False
            
        elif condition_type == 'dns_query' and hasattr(packet, 'qd'):
            # Check DNS queries for suspicious patterns
            try:
                if hasattr(packet.qd, 'qname'):
                    query = packet.qd.qname.decode('utf-8', errors='ignore')
                    for pattern in condition.get('patterns', []):
                        if re.search(pattern, query):
                            return True
            except Exception as e:
                self.logger.debug(f"Error processing DNS query: {e}")
        
        return False
    
    def _trigger_alert(self, packet, rule: Dict[str, Any]):
        """
        Trigger an alert for a detected threat.
        
        Args:
            packet: The packet that triggered the alert
            rule: The rule that was triggered
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'rule_id': rule['id'],
            'rule_name': rule['name'],
            'severity': rule.get('severity', 'medium'),
            'description': rule.get('description', ''),
            'action': rule.get('action', 'alert'),
            'packet_summary': str(packet.summary()),
            'source_ip': getattr(packet, 'src', 'N/A'),
            'destination_ip': getattr(packet, 'dst', 'N/A'),
            'protocol': packet.name if hasattr(packet, 'name') else 'unknown'
        }
        
        self._notify_alert(alert)
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Register a callback function to be called when an alert is generated.
        
        Args:
            callback: Function that takes a dictionary of alert details
        """
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def _notify_alert(self, alert_info: Dict[str, Any]):
        """
        Notify all registered alert callbacks.
        
        Args:
            alert_info: Dictionary containing alert details
        """
        for callback in self.alert_callbacks:
            try:
                callback(alert_info)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
