"""
NIPS (Network Intrusion Prevention System) Manager

This module provides network intrusion prevention functionality for the Security Operations Center.
"""

import logging
import socket
import threading
import time
from typing import Optional, Dict, Any, List, Set, Callable

logger = logging.getLogger('nips.manager')

class NIPSManager:
    """Manager for Network Intrusion Prevention System functionality."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the NIPS Manager.
        
        Args:
            config: Configuration dictionary for the NIPS manager.
        """
        self.config = config or {}
        self.is_running = False
        self.rules: List[Dict[str, Any]] = []
        self.blocked_ips: Set[str] = set()
        self.callbacks: List[Callable] = []
        self.monitor_thread: Optional[threading.Thread] = None
        logger.info("NIPS Manager initialized")
    
    def start(self) -> None:
        """Start the NIPS Manager and begin monitoring network traffic."""
        if self.is_running:
            logger.warning("NIPS Manager is already running")
            return
            
        logger.info("Starting NIPS Manager...")
        self.is_running = True
        
        # Start the monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_network, daemon=True)
        self.monitor_thread.start()
        
        logger.info("NIPS Manager started successfully")
    
    def stop(self) -> None:
        """Stop the NIPS Manager and all monitoring."""
        if not self.is_running:
            logger.warning("NIPS Manager is not running")
            return
            
        logger.info("Stopping NIPS Manager...")
        self.is_running = False
        
        # Wait for the monitoring thread to finish
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
        
        logger.info("NIPS Manager stopped successfully")
    
    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new NIPS rule.
        
        Args:
            rule: The rule configuration to add.
            
        Returns:
            bool: True if the rule was added successfully, False otherwise.
        """
        try:
            required_fields = ['name', 'pattern', 'action', 'severity']
            if not all(field in rule for field in required_fields):
                logger.error("Rule is missing required fields")
                return False
                
            self.rules.append(rule)
            logger.info(f"Added NIPS rule: {rule['name']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add NIPS rule: {e}")
            return False
    
    def block_ip(self, ip_address: str, reason: str = "", duration: int = 3600) -> bool:
        """Block an IP address.
        
        Args:
            ip_address: The IP address to block.
            reason: Reason for blocking the IP.
            duration: Duration in seconds to block the IP (0 for permanent).
            
        Returns:
            bool: True if the IP was blocked successfully, False otherwise.
        """
        try:
            # Validate IP address
            try:
                socket.inet_pton(socket.AF_INET, ip_address)
            except socket.error:
                try:
                    socket.inet_pton(socket.AF_INET6, ip_address)
                except socket.error:
                    logger.error(f"Invalid IP address: {ip_address}")
                    return False
            
            self.blocked_ips.add(ip_address)
            logger.warning(f"Blocked IP {ip_address}: {reason}")
            
            # Schedule unblock if duration is specified
            if duration > 0:
                def unblock_later():
                    time.sleep(duration)
                    if ip_address in self.blocked_ips:
                        self.unblock_ip(ip_address)
                        logger.info(f"Auto-unblocked IP {ip_address} after {duration} seconds")
                
                threading.Thread(target=unblock_later, daemon=True).start()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock a previously blocked IP address.
        
        Args:
            ip_address: The IP address to unblock.
            
        Returns:
            bool: True if the IP was unblocked successfully, False otherwise.
        """
        try:
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                logger.info(f"Unblocked IP: {ip_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip_address}: {e}")
            return False
    
    def is_ip_blocked(self, ip_address: str) -> bool:
        """Check if an IP address is blocked.
        
        Args:
            ip_address: The IP address to check.
            
        Returns:
            bool: True if the IP is blocked, False otherwise.
        """
        return ip_address in self.blocked_ips
    
    def register_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback function to be called when an alert is triggered.
        
        Args:
            callback: A function that takes an alert dictionary as its only argument.
        """
        if callable(callback):
            self.callbacks.append(callback)
    
    def _monitor_network(self) -> None:
        """Monitor network traffic for suspicious activity."""
        logger.info("Starting network monitoring...")
        
        # This is a placeholder for actual network monitoring logic
        # In a real implementation, this would use a packet capture library like scapy
        
        while self.is_running:
            try:
                # Check for blocked IPs and take action
                # This is where you would implement actual packet inspection
                
                # Sleep to prevent high CPU usage
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}")
                time.sleep(5)  # Prevent tight loop on error
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the NIPS Manager.
        
        Returns:
            Dictionary containing status information.
        """
        return {
            "status": "running" if self.is_running else "stopped",
            "rules_count": len(self.rules),
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips),
            "version": "1.0.0"
        }
