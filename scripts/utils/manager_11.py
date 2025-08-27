"""
HIPS (Host-based Intrusion Prevention System) Manager

This module provides host-based intrusion prevention functionality for the Security Operations Center.
"""

import logging
import platform
import psutil
from typing import Optional, Dict, Any, List, Set

logger = logging.getLogger('hips.manager')

class HIPSManager:
    """Manager for Host-based Intrusion Prevention System functionality."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the HIPS Manager.
        
        Args:
            config: Configuration dictionary for the HIPS manager.
        """
        self.config = config or {}
        self.is_running = False
        self.policies: List[Dict[str, Any]] = []
        self.blocked_processes: Set[str] = set()
        self.os_type = platform.system().lower()
        logger.info(f"HIPS Manager initialized for {self.os_type}")
    
    def start(self) -> None:
        """Start the HIPS Manager and begin monitoring."""
        if self.is_running:
            logger.warning("HIPS Manager is already running")
            return
            
        logger.info("Starting HIPS Manager...")
        self.is_running = True
        logger.info("HIPS Manager started successfully")
    
    def stop(self) -> None:
        """Stop the HIPS Manager and all monitoring."""
        if not self.is_running:
            logger.warning("HIPS Manager is not running")
            return
            
        logger.info("Stopping HIPS Manager...")
        self.is_running = False
        logger.info("HIPS Manager stopped successfully")
    
    def add_policy(self, policy: Dict[str, Any]) -> bool:
        """Add a new HIPS policy.
        
        Args:
            policy: The policy configuration to add.
            
        Returns:
            bool: True if the policy was added successfully, False otherwise.
        """
        try:
            required_fields = ['name', 'action', 'conditions']
            if not all(field in policy for field in required_fields):
                logger.error("Policy is missing required fields")
                return False
                
            self.policies.append(policy)
            logger.info(f"Added HIPS policy: {policy['name']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add HIPS policy: {e}")
            return False
    
    def block_process(self, process_name: str) -> bool:
        """Block a process from executing.
        
        Args:
            process_name: Name of the process to block.
            
        Returns:
            bool: True if the process was blocked successfully, False otherwise.
        """
        try:
            self.blocked_processes.add(process_name.lower())
            logger.warning(f"Blocked process: {process_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block process {process_name}: {e}")
            return False
    
    def unblock_process(self, process_name: str) -> bool:
        """Unblock a previously blocked process.
        
        Args:
            process_name: Name of the process to unblock.
            
        Returns:
            bool: True if the process was unblocked successfully, False otherwise.
        """
        try:
            if process_name.lower() in self.blocked_processes:
                self.blocked_processes.remove(process_name.lower())
                logger.info(f"Unblocked process: {process_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock process {process_name}: {e}")
            return False
    
    def check_process(self, process_name: str) -> bool:
        """Check if a process is blocked.
        
        Args:
            process_name: Name of the process to check.
            
        Returns:
            bool: True if the process is blocked, False otherwise.
        """
        return process_name.lower() in self.blocked_processes
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """Get information about currently running processes.
        
        Returns:
            List of dictionaries containing process information.
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            try:
                process_info = proc.info
                process_info['blocked'] = self.check_process(process_info['name'])
                processes.append(process_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        return processes
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the HIPS Manager.
        
        Returns:
            Dictionary containing status information.
        """
        return {
            "status": "running" if self.is_running else "stopped",
            "os_type": self.os_type,
            "policies_count": len(self.policies),
            "blocked_processes_count": len(self.blocked_processes),
            "version": "1.0.0"
        }
