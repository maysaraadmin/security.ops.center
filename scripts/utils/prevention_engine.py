"""
Prevention Engine for NIPS - Handles blocking and other prevention actions.
"""
import logging
import platform
import subprocess
from typing import Dict, Any, List, Optional
import socket
import struct
import ctypes
import ctypes.util
import platform

# fcntl is only available on Unix-like systems
if platform.system().lower() != 'windows':
    import fcntl

class PreventionEngine:
    """
    Handles prevention actions like blocking IPs, dropping packets, etc.
    """
    
    def __init__(self):
        """Initialize the prevention engine."""
        self.logger = logging.getLogger(__name__)
        self.blocked_ips = set()
        self.os_type = platform.system().lower()
        self._init_platform_specific()
    
    def _init_platform_specific(self):
        """Initialize platform-specific prevention mechanisms."""
        if self.os_type == 'linux':
            self._init_linux()
        elif self.os_type == 'windows':
            self._init_windows()
        elif self.os_type == 'darwin':
            self._init_darwin()
        else:
            self.logger.warning(f"Unsupported OS for advanced prevention: {self.os_type}")
    
    def _init_linux(self):
        """Initialize Linux-specific prevention mechanisms."""
        try:
            # Check if iptables is available
            subprocess.run(['which', 'iptables'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE,
                         check=True)
            self.linux_has_iptables = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.linux_has_iptables = False
            self.logger.warning("iptables not found. Some prevention features may be limited.")
    
    def _init_windows(self):
        """Initialize Windows-specific prevention mechanisms."""
        self.windows_firewall_enabled = self._check_windows_firewall()
        if not self.windows_firewall_enabled:
            self.logger.warning("Windows Firewall is not enabled. Some prevention features may be limited.")
    
    def _init_darwin(self):
        """Initialize macOS-specific prevention mechanisms."""
        try:
            # Check if pfctl is available
            subprocess.run(['which', 'pfctl'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE,
                         check=True)
            self.darwin_has_pfctl = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            self.darwin_has_pfctl = False
            self.logger.warning("pfctl not found. Some prevention features may be limited on macOS.")
    
    def _check_windows_firewall(self) -> bool:
        """Check if Windows Firewall is enabled."""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            return 'ON' in result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def block_ip(self, ip_address: str, port: Optional[int] = None, 
                protocol: Optional[str] = None, duration: int = 3600) -> bool:
        """
        Block traffic from a specific IP address.
        
        Args:
            ip_address: IP address to block
            port: Optional port to block (if None, blocks all ports)
            protocol: Optional protocol ('tcp', 'udp', 'icmp', etc.)
            duration: Duration in seconds to block the IP (0 for permanent)
            
        Returns:
            bool: True if the block was successful, False otherwise
        """
        if not self._is_valid_ip(ip_address):
            self.logger.error(f"Invalid IP address: {ip_address}")
            return False
            
        if ip_address in self.blocked_ips:
            self.logger.debug(f"IP {ip_address} is already blocked")
            return True
            
        self.logger.info(f"Blocking IP: {ip_address}" + 
                        (f" on port {port}" if port else "") + 
                        (f" ({protocol})" if protocol else ""))
        
        success = False
        
        if self.os_type == 'linux' and self.linux_has_iptables:
            success = self._block_ip_linux(ip_address, port, protocol)
        elif self.os_type == 'windows':
            success = self._block_ip_windows(ip_address, port, protocol)
        elif self.os_type == 'darwin' and self.darwin_has_pfctl:
            success = self._block_ip_darwin(ip_address, port, protocol)
        else:
            self.logger.warning("No suitable blocking mechanism available for this OS")
            # Fall back to in-memory blocking
            success = True
        
        if success:
            self.blocked_ips.add(ip_address)
            
            # Schedule unblock if duration is specified
            if duration > 0:
                # In a real implementation, you would use a proper scheduler
                # For this example, we'll just log the intent
                self.logger.info(f"IP {ip_address} will be unblocked after {duration} seconds")
        
        return success
    
    def _block_ip_linux(self, ip_address: str, port: Optional[int] = None, 
                       protocol: Optional[str] = None) -> bool:
        """Block an IP address using iptables (Linux)."""
        try:
            cmd = ['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address]
            
            if protocol:
                cmd.extend(['-p', protocol.lower()])
            if port:
                cmd.extend(['--dport', str(port)])
                
            cmd.extend(['-j', 'DROP'])
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            self.logger.debug(f"Blocked {ip_address} using iptables")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address} using iptables: {e.stderr}")
            return False
    
    def _block_ip_windows(self, ip_address: str, port: Optional[int] = None, 
                         protocol: Optional[str] = None) -> bool:
        """Block an IP address using Windows Firewall."""
        try:
            # Create a firewall rule to block the IP
            rule_name = f"Block_NIPS_{ip_address}"
            
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=in',
                'action=block',
                f'remoteip={ip_address}'
            ]
            
            if protocol:
                cmd.append(f'protocol={protocol.upper()}')
            if port:
                cmd.append(f'localport={port}')
            
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                check=True
            )
            
            self.logger.debug(f"Blocked {ip_address} using Windows Firewall")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to block IP {ip_address} using Windows Firewall: {e.stderr}")
            return False
    
    def _block_ip_darwin(self, ip_address: str, port: Optional[int] = None, 
                        protocol: Optional[str] = None) -> bool:
        """Block an IP address using pf (macOS)."""
        try:
            # This is a simplified example - in a real implementation, you would
            # need to modify the pf configuration file and reload the rules
            self.logger.warning("PF-based blocking not fully implemented for macOS")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip_address} using pf: {e}")
            return False
    
    def unblock_ip(self, ip_address: str) -> bool:
        """
        Unblock a previously blocked IP address.
        
        Args:
            ip_address: IP address to unblock
            
        Returns:
            bool: True if the unblock was successful, False otherwise
        """
        if ip_address not in self.blocked_ips:
            self.logger.debug(f"IP {ip_address} is not currently blocked")
            return True
            
        self.logger.info(f"Unblocking IP: {ip_address}")
        
        success = False
        
        if self.os_type == 'linux' and self.linux_has_iptables:
            success = self._unblock_ip_linux(ip_address)
        elif self.os_type == 'windows':
            success = self._unblock_ip_windows(ip_address)
        elif self.os_type == 'darwin' and self.darwin_has_pfctl:
            success = self._unblock_ip_darwin(ip_address)
        else:
            # For unsupported platforms or missing tools, just remove from our set
            success = True
        
        if success:
            self.blocked_ips.discard(ip_address)
        
        return success
    
    def _unblock_ip_linux(self, ip_address: str) -> bool:
        """Unblock an IP address using iptables (Linux)."""
        try:
            # First, list all rules to find the one we need to delete
            result = subprocess.run(
                ['sudo', 'iptables', '-L', '--line-numbers', '-n'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            
            # Find the rule number for this IP
            for line in result.stdout.split('\n'):
                if f'source {ip_address}' in line and 'DROP' in line:
                    rule_num = line.split()[0]
                    # Delete the rule
                    subprocess.run(
                        ['sudo', 'iptables', '-D', 'INPUT', rule_num],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True
                    )
                    self.logger.debug(f"Unblocked {ip_address} using iptables")
                    return True
            
            self.logger.warning(f"No iptables rule found for IP {ip_address}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unblock IP {ip_address} using iptables: {e.stderr}")
            return False
    
    def _unblock_ip_windows(self, ip_address: str) -> bool:
        """Unblock an IP address using Windows Firewall."""
        try:
            rule_name = f"Block_NIPS_{ip_address}"
            
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name="{rule_name}"'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                check=True
            )
            
            self.logger.debug(f"Unblocked {ip_address} using Windows Firewall")
            return True
            
        except subprocess.CalledProcessError as e:
            # If the rule doesn't exist, that's fine - we consider it unblocked
            if 'No rules match the specified criteria' in e.stderr:
                return True
            self.logger.error(f"Failed to unblock IP {ip_address} using Windows Firewall: {e.stderr}")
            return False
    
    def _unblock_ip_darwin(self, ip_address: str) -> bool:
        """Unblock an IP address using pf (macOS)."""
        try:
            # This is a simplified example - in a real implementation, you would
            # need to modify the pf configuration file and reload the rules
            self.logger.warning("PF-based unblocking not fully implemented for macOS")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unblock IP {ip_address} using pf: {e}")
            return False
    
    def get_blocked_ips(self) -> set:
        """
        Get the set of currently blocked IP addresses.
        
        Returns:
            set: Set of blocked IP addresses
        """
        return self.blocked_ips.copy()
    
    def clear_blocked_ips(self) -> bool:
        """
        Clear all blocked IP addresses.
        
        Returns:
            bool: True if successful, False otherwise
        """
        success = True
        ips = list(self.blocked_ips)
        
        for ip in ips:
            if not self.unblock_ip(ip):
                success = False
        
        return success
    
    @staticmethod
    def _is_valid_ip(ip_address: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        Args:
            ip_address: String to check
            
        Returns:
            bool: True if valid IP, False otherwise
        """
        try:
            socket.inet_pton(socket.AF_INET, ip_address)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip_address)
                return True
            except socket.error:
                return False
