"""
NIPS Manager - Main module for Network Intrusion Prevention System.
Coordinates packet inspection, detection, and prevention actions.
"""
import logging
import signal
import sys
import threading
import time
from datetime import datetime
from typing import Optional, Dict, Any, List, Callable, Set

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

from .detection_engine import DetectionEngine
from .prevention_engine import PreventionEngine
from .packet_inspector import PacketInspector

class NIPSManager:
    """
    Main class for Network Intrusion Prevention System functionality.
    Handles packet inspection, threat detection, and prevention actions.
    """
    
    def __init__(self, interface: str = None, filter_exp: str = "ip"):
        """
        Initialize the NIPS manager.
        
        Args:
            interface: Network interface to monitor (None for default)
            filter_exp: BPF filter expression for traffic filtering
        """
        self.interface = interface
        self.filter_exp = filter_exp
        self.running = False
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.detection_engine = DetectionEngine()
        self.prevention_engine = PreventionEngine()
        self.packet_inspector = PacketInspector()
        
        # Connect components
        self.packet_inspector.add_callback(self._process_packet)
        self.detection_engine.add_alert_callback(self._handle_alert)
        
        # Thread for packet sniffing
        self.sniff_thread = None
        
        # Statistics
        self.stats = {
            'start_time': None,
            'packets_processed': 0,
            'threats_prevented': 0,
            'last_alert': None,
            'active_rules': 0,
            'blocked_ips': set()
        }
        
        # Alert callbacks
        self.alert_callbacks = []
    
    def start(self):
        """Start the NIPS system."""
        if self.running:
            self.logger.warning("NIPS is already running")
            return
            
        self.logger.info("Starting NIPS system...")
        self.running = True
        self.stats['start_time'] = datetime.now()
        self.stats['active_rules'] = len(self.detection_engine.rules)
        
        # Start packet inspection in a separate thread
        self.sniff_thread = threading.Thread(
            target=self._start_sniffing,
            daemon=True,
            name="NIPSSniffer"
        )
        self.sniff_thread.start()
        
        self.logger.info("NIPS system started")
    
    def stop(self):
        """Stop the NIPS system."""
        if not self.running:
            return
            
        self.logger.info("Stopping NIPS system...")
        self.running = False
        
        # Stop packet sniffing
        if self.sniff_thread and self.sniff_thread.is_alive():
            # Send a signal to stop the sniffer
            scapy.sniffer.StopCapture.set()
            self.sniff_thread.join(timeout=5)
        
        self.logger.info("NIPS system stopped")
        
    def _handle_alert(self, alert: Dict[str, Any]) -> None:
        """
        Handle alerts from the detection engine.
        
        Args:
            alert: Dictionary containing alert details including:
                - rule_id: ID of the triggered rule
                - rule_name: Name of the triggered rule
                - severity: Severity level of the alert
                - description: Detailed description of the alert
                - packet: The packet that triggered the alert (optional)
                - src_ip: Source IP address (optional)
                - dst_ip: Destination IP address (optional)
                - src_port: Source port (optional)
                - dst_port: Destination port (optional)
                - protocol: Network protocol (optional)
        """
        try:
            self.logger.warning(
                f"Alert triggered - Rule: {alert.get('rule_name', 'Unknown')} "
                f"(Severity: {alert.get('severity', 'Unknown')})\n"
                f"Description: {alert.get('description', 'No description')}\n"
                f"Source: {alert.get('src_ip', 'Unknown')}:{alert.get('src_port', 'N/A')} -> "
                f"Destination: {alert.get('dst_ip', 'Unknown')}:{alert.get('dst_port', 'N/A')} "
                f"({alert.get('protocol', 'Unknown')})"
            )
            
            # Update statistics
            self.stats['threats_prevented'] += 1
            self.stats['last_alert'] = datetime.now()
            
            # Call registered alert callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    self.logger.error(f"Error in alert callback: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error handling alert: {e}", exc_info=True)
    
    def _start_sniffing(self):
        """Start packet sniffing on the specified interface."""
        try:
            self.logger.info(f"Starting packet sniffing on interface {self.interface}")
            scapy.sniff(
                iface=self.interface,
                filter=self.filter_exp,
                prn=self.packet_inspector.inspect_packet,
                store=0,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error in packet sniffing: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """
        Process a captured packet through the detection engine.
        
        Args:
            packet: The captured network packet
        """
        if not self.running:
            return
            
        self.stats['packets_processed'] += 1
        
        # Check if packet should be blocked
        if self._should_block_packet(packet):
            return self._block_packet(packet)
        
        # Check for threats
        threat_detected = self.detection_engine.analyze_packet(packet)
        
        # If threat detected, take prevention action
        if threat_detected:
            self._handle_threat(packet)
    
    def _should_block_packet(self, packet) -> bool:
        """
        Check if a packet should be blocked based on current rules.
        
        Args:
            packet: The packet to check
            
        Returns:
            bool: True if the packet should be blocked, False otherwise
        """
        # Check if source or destination IP is in blocked list
        if hasattr(packet, 'src') and packet.src in self.stats['blocked_ips']:
            return True
        if hasattr(packet, 'dst') and packet.dst in self.stats['blocked_ips']:
            return True
            
        # Add more blocking conditions here based on rules
        
        return False
    
    def _block_packet(self, packet):
        """
        Block a packet by dropping it.
        
        Args:
            packet: The packet to block
        """
        self.stats['threats_prevented'] += 1
        self.logger.debug(f"Blocked packet: {packet.summary()}")
        return "Blocked"
    
    def _handle_threat(self, packet):
        """
        Handle a detected threat by taking appropriate prevention actions.
        
        Args:
            packet: The packet that triggered the threat
        """
        # Log the threat
        threat_info = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src if IP in packet else None,
            'destination_ip': packet[IP].dst if IP in packet else None,
            'protocol': packet[IP].proto if IP in packet else None,
            'threat_type': 'suspicious_activity',  # This would come from detection engine
            'action_taken': 'blocked'
        }
        
        # Take prevention action
        if IP in packet:
            self.block_ip(packet[IP].src)  # Block the source IP
        
        # Notify any registered callbacks
        self._notify_alert(threat_info)
    
    def block_ip(self, ip_address: str, duration: int = 3600):
        """
        Block traffic from a specific IP address.
        
        Args:
            ip_address: The IP address to block
            duration: Duration in seconds to block the IP (0 for permanent)
        """
        self.stats['blocked_ips'].add(ip_address)
        self.logger.info(f"Blocked IP: {ip_address} for {duration} seconds")
        
        # If duration is specified, schedule unblocking
        if duration > 0:
            threading.Timer(
                duration,
                self.unblock_ip,
                args=(ip_address,)
            ).start()
    
    def unblock_ip(self, ip_address: str):
        """
        Unblock a previously blocked IP address.
        
        Args:
            ip_address: The IP address to unblock
        """
        if ip_address in self.stats['blocked_ips']:
            self.stats['blocked_ips'].remove(ip_address)
            self.logger.info(f"Unblocked IP: {ip_address}")
    
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
        self.stats['last_alert'] = datetime.now()
        
        for callback in self.alert_callbacks:
            try:
                callback(alert_info)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the NIPS system.
        
        Returns:
            Dictionary containing status information
        """
        uptime = (datetime.now() - self.stats['start_time']).total_seconds() \
            if self.stats['start_time'] else 0
            
        return {
            'running': self.running,
            'uptime_seconds': uptime,
            'packets_processed': self.stats['packets_processed'],
            'threats_prevented': self.stats['threats_prevented'],
            'last_alert': self.stats['last_alert'].isoformat() if self.stats['last_alert'] else None,
            'active_rules': self.stats['active_rules'],
            'blocked_ips_count': len(self.stats['blocked_ips'])
        }
    
    def add_rule(self, rule: Dict[str, Any]):
        """
        Add a new detection rule.
        
        Args:
            rule: Dictionary containing rule definition
        """
        self.detection_engine.add_rule(rule)
        self.stats['active_rules'] = len(self.detection_engine.rules)
    
    def remove_rule(self, rule_id: str):
        """
        Remove a detection rule.
        
        Args:
            rule_id: ID of the rule to remove
        """
        self.detection_engine.remove_rule(rule_id)
        self.stats['active_rules'] = len(self.detection_engine.rules)
    
    def get_rules(self) -> List[Dict[str, Any]]:
        """
        Get all detection rules.
        
        Returns:
            List of rule dictionaries
        """
        return self.detection_engine.get_rules()
    
    def get_blocked_ips(self) -> Set[str]:
        """
        Get the set of currently blocked IP addresses.
        
        Returns:
            Set of blocked IP addresses
        """
        return self.stats['blocked_ips'].copy()
    
    def clear_blocked_ips(self):
        """Clear all blocked IP addresses."""
        self.stats['blocked_ips'].clear()
        self.logger.info("Cleared all blocked IPs")
