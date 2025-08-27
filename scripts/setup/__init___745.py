"""
NDR (Network Detection and Response) Service

This module provides network traffic analysis, anomaly detection, and encrypted traffic inspection.
"""
import time
import threading
import socket
import struct
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from core.base_service import BaseService

class NDRManager(BaseService):
    """NDR Service Manager."""
    
    def __init__(self, config_path: str = None):
        """Initialize the NDR service."""
        super().__init__("NDR", config_path)
        self.packet_capture = None
        self.anomaly_detector = None
        self.traffic_analyzer = None
        self._capture_thread = None
        self._stop_event = threading.Event()
        self._stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'alerts_triggered': 0,
            'last_alert_time': 0
        }
    
    def start(self):
        """Start the NDR service."""
        if self._running:
            self.logger.warning("NDR service is already running")
            return True
            
        super().start()
        self.logger.info("Initializing NDR service components...")
        
        try:
            # Initialize packet capture
            self.logger.info("Initializing packet capture...")
            # self.packet_capture = PacketCapture(self.config.get('capture', {}))
            
            # Initialize anomaly detector
            self.logger.info("Initializing anomaly detector...")
            # self.anomaly_detector = AnomalyDetector(self.config.get('anomaly_detection', {}))
            
            # Initialize traffic analyzer
            self.logger.info("Initializing traffic analyzer...")
            # self.traffic_analyzer = TrafficAnalyzer(self.config.get('traffic_analysis', {}))
            
            # Start packet capture thread
            self._stop_event.clear()
            self._capture_thread = threading.Thread(
                target=self._capture_loop,
                daemon=True
            )
            self._capture_thread.start()
            
            self.logger.info("NDR service started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start NDR service: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the NDR service."""
        if not self._running:
            return
            
        self.logger.info("Stopping NDR service...")
        
        # Signal capture thread to stop
        self._stop_event.set()
        
        try:
            # Stop components
            # if self.packet_capture:
            #     self.packet_capture.stop()
            # if self.anomaly_detector:
            #     self.anomaly_detector.cleanup()
            # if self.traffic_analyzer:
            #     self.traffic_analyzer.cleanup()
            
            # Wait for capture thread to finish
            if self._capture_thread and self._capture_thread.is_alive():
                self._capture_thread.join(timeout=5.0)
                
            super().stop()
            self.logger.info("NDR service stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping NDR service: {e}")
            return False
    
    def _capture_loop(self):
        """Main packet capture and analysis loop."""
        self.logger.info("Starting packet capture loop")
        
        try:
            # Create a raw socket to capture packets
            # This is a simplified example - in production, you'd use a library like Scapy
            raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            while not self._stop_event.is_set():
                try:
                    # Capture a packet (non-blocking with timeout)
                    raw_socket.settimeout(1.0)
                    packet = raw_socket.recvfrom(65535)
                    
                    # Process the packet
                    self._process_packet(packet[0])
                    
                except socket.timeout:
                    # Timeout is expected, just continue the loop
                    continue
                    
                except Exception as e:
                    self.logger.error(f"Error processing packet: {e}")
                    time.sleep(1)  # Prevent tight error loops
                    
        except Exception as e:
            self.logger.error(f"Fatal error in capture loop: {e}")
            
        finally:
            if 'raw_socket' in locals():
                raw_socket.close()
            self.logger.info("Packet capture loop stopped")
    
    def _process_packet(self, packet: bytes):
        """Process a single network packet."""
        self._stats['packets_processed'] += 1
        
        # Extract Ethernet header (first 14 bytes: 6 dest MAC, 6 src MAC, 2 ethertype)
        eth_header = packet[:14]
        eth = struct.unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        
        # Process IP packets (EtherType 0x0800 for IPv4, 0x86DD for IPv6)
        if eth_protocol == 8:
            self._process_ip_packet(packet[14:])
    
    def _process_ip_packet(self, packet: bytes):
        """Process an IP packet."""
        try:
            # Extract IP header (first 20 bytes for IPv4 without options)
            ip_header = packet[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            # Extract protocol and addresses
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dst_ip = socket.inet_ntoa(iph[9])
            
            # Process TCP packets (protocol 6)
            if protocol == 6:
                self._process_tcp_packet(packet[iph_length:], src_ip, dst_ip)
            
            # Process UDP packets (protocol 17)
            elif protocol == 17:
                self._process_udp_packet(packet[iph_length:], src_ip, dst_ip)
                
        except Exception as e:
            self.logger.error(f"Error processing IP packet: {e}")
    
    def _process_tcp_packet(self, packet: bytes, src_ip: str, dst_ip: str):
        """Process a TCP packet."""
        try:
            # Extract TCP header (first 20 bytes without options)
            tcp_header = packet[:20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            
            src_port = tcph[0]
            dst_port = tcph[1]
            flags = tcph[5]
            
            # Check for suspicious patterns (simplified example)
            if dst_port in [22, 3389] and (flags & 0x02):  # SYN flag set on SSH/RDP ports
                self._log_suspicious_activity(
                    "Suspicious connection attempt",
                    f"SYN packet to port {dst_port} from {src_ip}:{src_port}",
                    "medium"
                )
                
        except Exception as e:
            self.logger.error(f"Error processing TCP packet: {e}")
    
    def _process_udp_packet(self, packet: bytes, src_ip: str, dst_ip: str):
        """Process a UDP packet."""
        try:
            # Extract UDP header (8 bytes)
            udp_header = packet[:8]
            udph = struct.unpack('!HHHH', udp_header)
            
            src_port = udph[0]
            dst_port = udph[1]
            length = udph[2]
            
            # Check for suspicious patterns (simplified example)
            if length > 1500:  # Large UDP packet
                self._log_suspicious_activity(
                    "Large UDP packet detected",
                    f"{length} byte UDP packet from {src_ip}:{src_port} to {dst_ip}:{dst_port}",
                    "low"
                )
                
        except Exception as e:
            self.logger.error(f"Error processing UDP packet: {e}")
    
    def _log_suspicious_activity(self, title: str, details: str, severity: str):
        """Log suspicious network activity."""
        self._stats['alerts_triggered'] += 1
        self._stats['last_alert_time'] = int(time.time())
        
        log_message = f"{title} - {details} (Severity: {severity.upper()})"
        
        if severity == "high":
            self.logger.error(log_message)
        elif severity == "medium":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def get_network_stats(self) -> Dict[str, Any]:
        """Get current network statistics."""
        return {
            'status': 'running' if self._running else 'stopped',
            'packets_processed': self._stats['packets_processed'],
            'anomalies_detected': self._stats['anomalies_detected'],
            'alerts_triggered': self._stats['alerts_triggered'],
            'last_alert_time': self._stats['last_alert_time']
        }
    
    def status(self) -> Dict[str, Any]:
        """Get the current status of the NDR service."""
        status = super().status()
        status.update({
            'capture_active': self._capture_thread.is_alive() if self._capture_thread else False,
            'stats': {
                'packets_processed': self._stats['packets_processed'],
                'anomalies_detected': self._stats['anomalies_detected'],
                'alerts_triggered': self._stats['alerts_triggered'],
                'last_alert': self._stats['last_alert_time']
            }
        })
        return status
