"""
Network Traffic Analyzer

Analyzes network traffic for security threats and anomalies.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set

from .models.alert import NetworkAlert, AlertSeverity

logger = logging.getLogger('ndr.analyzer')

class TrafficAnalyzer:
    """Analyzes network traffic for security threats."""
    
    def __init__(self):
        """Initialize the traffic analyzer."""
        self.known_attackers: Set[str] = set()
        self.port_scan_threshold = 20  # Ports per minute
        self.host_scan_threshold = 50  # Hosts per minute
        self.port_scan_windows: Dict[str, List[datetime]] = {}
        self.host_scan_windows: Dict[str, List[datetime]] = {}
    
    def analyze_flow(self, flow: Dict[str, Any]) -> Optional[NetworkAlert]:
        """
        Analyze a network flow for security threats.
        
        Args:
            flow: Network flow dictionary
            
        Returns:
            NetworkAlert if a threat is detected, None otherwise
        """
        try:
            # Check for known malicious IPs
            if flow['src_ip'] in self.known_attackers:
                return NetworkAlert(
                    title="Known Malicious Source IP",
                    description=f"Traffic from known malicious IP: {flow['src_ip']}",
                    severity=AlertSeverity.HIGH,
                    source_ip=flow['src_ip'],
                    destination_ip=flow['dst_ip'],
                    protocol=flow['protocol']
                )
            
            # Check for port scanning
            self._update_scan_window(self.port_scan_windows, flow['src_ip'])
            if len(self.port_scan_windows[flow['src_ip']]) > self.port_scan_threshold:
                return NetworkAlert(
                    title="Possible Port Scan Detected",
                    description=f"Possible port scan detected from {flow['src_ip']}",
                    severity=AlertSeverity.MEDIUM,
                    source_ip=flow['src_ip'],
                    protocol=flow['protocol']
                )
            
            # Check for host scanning
            self._update_scan_window(self.host_scan_windows, flow['src_ip'])
            if len(self.host_scan_windows[flow['src_ip']]) > self.host_scan_threshold:
                return NetworkAlert(
                    title="Possible Host Scan Detected",
                    description=f"Possible host scan detected from {flow['src_ip']}",
                    severity=AlertSeverity.MEDIUM,
                    source_ip=flow['src_ip']
                )
            
            # Add more detection rules as needed
            
        except Exception as e:
            logger.error(f"Error analyzing flow: {e}")
        
        return None
    
    def _update_scan_window(self, window_dict: Dict[str, List[datetime]], ip: str):
        """Update the scan detection window for an IP."""
        now = datetime.now()
        one_min_ago = now - timedelta(minutes=1)
        
        if ip not in window_dict:
            window_dict[ip] = []
        
        # Remove timestamps older than 1 minute
        window_dict[ip] = [t for t in window_dict[ip] if t > one_min_ago]
        
        # Add current timestamp
        window_dict[ip].append(now)
    
    def add_malicious_ip(self, ip: str):
        """Add an IP to the known malicious IPs set."""
        self.known_attackers.add(ip)
    
    def analyze_flows(self, flows: List[Dict[str, Any]]) -> List[NetworkAlert]:
        """
        Analyze multiple network flows.
        
        Args:
            flows: List of network flow dictionaries
            
        Returns:
            List of NetworkAlert objects for detected threats
        """
        alerts = []
        for flow in flows:
            alert = self.analyze_flow(flow)
            if alert:
                alerts.append(alert)
        return alerts
