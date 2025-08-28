"""
PCAP Manager for NIPS

Handles the capture, storage, and analysis of network packet captures.
"""
import os
import time
import logging
from typing import Optional, List, Dict, Any
import pyshark
from datetime import datetime

logger = logging.getLogger(__name__)

class PCAPManager:
    """Manages PCAP file operations for network forensics."""
    
    def __init__(self, output_dir: str = 'pcap_captures'):
        """Initialize the PCAP Manager.
        
        Args:
            output_dir: Directory to store PCAP files
        """
        self.output_dir = output_dir
        self.current_capture = None
        self.capture_start_time = None
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
    
    def start_capture(self, interface: str = None, output_file: str = None, 
                     packet_count: int = 0, timeout: int = 60) -> str:
        """Start a new packet capture.
        
        Args:
            interface: Network interface to capture on (None for default)
            output_file: Output PCAP file path (None for auto-generated name)
            packet_count: Number of packets to capture (0 for unlimited)
            timeout: Capture timeout in seconds (0 for no timeout)
            
        Returns:
            str: Path to the PCAP file
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f'capture_{timestamp}.pcap')
        else:
            output_file = os.path.join(self.output_dir, output_file)
        
        try:
            self.current_capture = pyshark.LiveCapture(
                interface=interface,
                output_file=output_file
            )
            self.capture_start_time = time.time()
            logger.info(f"Started packet capture on {interface or 'default interface'}, saving to {output_file}")
            
            # Start capture in a separate thread
            self.current_capture.sniff_continuously(packet_count=packet_count, timeout=timeout)
            
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to start packet capture: {str(e)}")
            raise
    
    def stop_capture(self):
        """Stop the current packet capture."""
        if self.current_capture:
            self.current_capture.close()
            self.current_capture = None
            capture_duration = time.time() - self.capture_start_time
            self.capture_start_time = None
            logger.info(f"Stopped packet capture after {capture_duration:.2f} seconds")
    
    def analyze_pcap(self, pcap_file: str) -> Dict[str, Any]:
        """Analyze a PCAP file and extract relevant information.
        
        Args:
            pcap_file: Path to the PCAP file to analyze
            
        Returns:
            Dict containing analysis results
        """
        if not os.path.exists(pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")
        
        analysis = {
            'file': pcap_file,
            'packet_count': 0,
            'protocols': {},
            'source_ips': {},
            'destination_ports': {},
            'start_time': None,
            'end_time': None
        }
        
        try:
            capture = pyshark.FileCapture(pcap_file)
            
            for packet in capture:
                analysis['packet_count'] += 1
                
                # Track protocols
                if hasattr(packet, 'highest_layer'):
                    protocol = packet.highest_layer
                    analysis['protocols'][protocol] = analysis['protocols'].get(protocol, 0) + 1
                
                # Track source IPs
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    analysis['source_ips'][src_ip] = analysis['source_ips'].get(src_ip, 0) + 1
                
                # Track destination ports (for TCP/UDP)
                if hasattr(packet, 'tcp'):
                    dst_port = packet.tcp.dstport
                    analysis['destination_ports'][dst_port] = analysis['destination_ports'].get(dst_port, 0) + 1
                elif hasattr(packet, 'udp'):
                    dst_port = packet.udp.dstport
                    analysis['destination_ports'][dst_port] = analysis['destination_ports'].get(dst_port, 0) + 1
                
                # Update start/end times
                if analysis['start_time'] is None or packet.sniff_time < analysis['start_time']:
                    analysis['start_time'] = packet.sniff_time
                if analysis['end_time'] is None or packet.sniff_time > analysis['end_time']:
                    analysis['end_time'] = packet.sniff_time
            
            capture.close()
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {str(e)}")
            raise
    
    def list_captures(self) -> List[Dict[str, Any]]:
        """List all available PCAP captures.
        
        Returns:
            List of dictionaries containing capture information
        """
        captures = []
        
        for filename in os.listdir(self.output_dir):
            if filename.endswith('.pcap'):
                filepath = os.path.join(self.output_dir, filename)
                stats = os.stat(filepath)
                
                captures.append({
                    'filename': filename,
                    'path': filepath,
                    'size': stats.st_size,
                    'created': datetime.fromtimestamp(stats.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stats.st_mtime).isoformat()
                })
        
        return captures
