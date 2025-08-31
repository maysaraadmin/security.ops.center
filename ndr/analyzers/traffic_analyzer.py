"""
Traffic Analyzer Module

Analyzes network traffic flows for security threats and anomalies.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Deque, DefaultDict
from collections import defaultdict, deque
import ipaddress

from ..models.alert import NetworkAlert, AlertSeverity
from ..models.flow import NetworkFlow

logger = logging.getLogger('ndr.analyzer.traffic')

class TrafficAnalyzer:
    """Analyzes network traffic for security threats and anomalies."""
    
    def __init__(self):
        """Initialize the traffic analyzer with default thresholds."""
        # Thresholds for anomaly detection
        self.thresholds = {
            'high_bandwidth': 100 * 1024 * 1024,  # 100 MB
            'high_pps': 1000,  # 1000 packets per second
            'port_scan_threshold': 50,  # 50 connection attempts to different ports
            'host_scan_threshold': 50,  # 50 connection attempts to different hosts
            'long_connection': 3600,  # 1 hour
            'suspicious_ports': {
                22,  # SSH
                23,  # Telnet
                80,  # HTTP
                443,  # HTTPS
                3389,  # RDP
                5900,  # VNC
                8080,  # HTTP Alt
            },
            'suspicious_protocols': {
                1,  # ICMP
                6,  # TCP
                17,  # UDP
            },
        }
        
        # State for tracking connections and statistics
        self.connection_stats: Dict[Tuple[str, int, str, int], Dict[str, Any]] = {}
        self.host_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'connections': set(),
            'ports': set(),
            'last_seen': datetime.min
        })
        
        # Time windows for rate limiting
        self.alert_windows: Dict[str, Deque[datetime]] = defaultdict(deque)
        
        # Callbacks for alerts
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
    
    def analyze_flows(self, flows: List[NetworkFlow]) -> List[NetworkAlert]:
        """
        Analyze a list of network flows for security threats and anomalies.
        
        Args:
            flows: List of NetworkFlow objects to analyze
            
        Returns:
            List of NetworkAlert objects for detected threats
        """
        alerts: List[NetworkAlert] = []
        
        for flow in flows:
            # Update connection and host statistics
            self._update_stats(flow)
            
            # Check for various types of threats
            alerts.extend(self._check_high_bandwidth(flow))
            alerts.extend(self._check_port_scan(flow))
            alerts.extend(self._check_host_scan(flow))
            alerts.extend(self._check_suspicious_ports(flow))
            alerts.extend(self._check_long_connections(flow))
            alerts.extend(self._check_anomalous_behavior(flow))
        
        # Clean up old state
        self._cleanup_old_state()
        
        return alerts
    
    def _update_stats(self, flow: NetworkFlow) -> None:
        """Update connection and host statistics."""
        # Update connection stats
        conn_key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
        if conn_key not in self.connection_stats:
            self.connection_stats[conn_key] = {
                'start_time': flow.timestamp,
                'last_seen': flow.timestamp,
                'bytes_sent': 0,
                'packets_sent': 0,
                'state': 'new'
            }
        
        conn = self.connection_stats[conn_key]
        conn['last_seen'] = flow.timestamp
        conn['bytes_sent'] += flow.bytes_sent
        conn['packets_sent'] += flow.packets_sent
        
        # Update host stats
        for ip in [flow.src_ip, flow.dst_ip]:
            host = self.host_stats[ip]
            host['last_seen'] = flow.timestamp
            
            if ip == flow.src_ip:
                host['bytes_sent'] += flow.bytes_sent
                host['packets_sent'] += flow.packets_sent
                host['connections'].add((flow.dst_ip, flow.dst_port))
                host['ports'].add(flow.src_port)
            else:
                host['bytes_received'] += flow.bytes_sent
                host['packets_received'] += flow.packets_sent
                host['ports'].add(flow.dst_port)
    
    def _check_high_bandwidth(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for high bandwidth usage."""
        if flow.bytes_sent > self.thresholds['high_bandwidth']:
            return [NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='high_bandwidth',
                severity=AlertSeverity.HIGH,
                description=f"High bandwidth usage detected: {flow.bytes_sent / (1024 * 1024):.2f} MB"
            )]
        return []
    
    def _check_port_scan(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for port scanning activity."""
        src_host = self.host_stats[flow.src_ip]
        if len(src_host['ports']) > self.thresholds['port_scan_threshold']:
            return [NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='port_scan',
                severity=AlertSeverity.HIGH,
                description=f"Port scan detected from {flow.src_ip} to {len(src_host['ports'])} different ports"
            )]
        return []
    
    def _check_host_scan(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for host scanning activity."""
        src_host = self.host_stats[flow.src_ip]
        if len(src_host['connections']) > self.thresholds['host_scan_threshold']:
            return [NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='host_scan',
                severity=AlertSeverity.HIGH,
                description=f"Host scan detected from {flow.src_ip} to {len(src_host['connections'])} different hosts"
            )]
        return []
    
    def _check_suspicious_ports(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for connections to suspicious ports."""
        if flow.dst_port in self.thresholds['suspicious_ports']:
            return [NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='suspicious_port',
                severity=AlertSeverity.MEDIUM,
                description=f"Connection to suspicious port {flow.dst_port}"
            )]
        return []
    
    def _check_long_connections(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for unusually long-lived connections."""
        conn_key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
        if conn_key in self.connection_stats:
            conn = self.connection_stats[conn_key]
            duration = (flow.timestamp - conn['start_time']).total_seconds()
            if duration > self.thresholds['long_connection']:
                return [NetworkAlert(
                    timestamp=flow.timestamp,
                    source_ip=flow.src_ip,
                    destination_ip=flow.dst_ip,
                    source_port=flow.src_port,
                    destination_port=flow.dst_port,
                    protocol=flow.protocol,
                    alert_type='long_connection',
                    severity=AlertSeverity.LOW,
                    description=f"Long-lived connection detected: {duration/3600:.2f} hours"
                )]
        return []
    
    def _check_anomalous_behavior(self, flow: NetworkFlow) -> List[NetworkAlert]:
        """Check for other types of anomalous behavior."""
        alerts = []
        
        # Check for high packet rate
        if flow.packets_sent > self.thresholds['high_pps']:
            alerts.append(NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='high_packet_rate',
                severity=AlertSeverity.MEDIUM,
                description=f"High packet rate detected: {flow.packets_sent} packets"
            ))
        
        # Check for unusual protocols
        if flow.protocol not in self.thresholds['suspicious_protocols']:
            alerts.append(NetworkAlert(
                timestamp=flow.timestamp,
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                alert_type='unusual_protocol',
                severity=AlertSeverity.LOW,
                description=f"Unusual protocol detected: {flow.protocol}"
            ))
        
        return alerts
    
    def _cleanup_old_state(self) -> None:
        """Clean up old connection and host state."""
        now = datetime.utcnow()
        timeout = timedelta(hours=1)
        
        # Clean up old connections
        expired_conns = [
            k for k, v in self.connection_stats.items()
            if now - v['last_seen'] > timeout
        ]
        for k in expired_conns:
            del self.connection_stats[k]
        
        # Clean up old hosts
        expired_hosts = [
            k for k, v in self.host_stats.items()
            if now - v['last_seen'] > timeout
        ]
        for k in expired_hosts:
            del self.host_stats[k]
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]) -> None:
        """Register a callback to receive alerts."""
        self.alert_callbacks.append(callback)
