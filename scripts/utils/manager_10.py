"""
FIM (File Integrity Monitoring) Manager

This module provides file integrity monitoring functionality for the Security Operations Center.
"""

import logging
import hashlib
import os
from typing import Optional, Dict, Any, List, Set
from pathlib import Path

logger = logging.getLogger('fim.manager')

class FIMManager:
    """Manager for File Integrity Monitoring functionality."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the FIM Manager.
        
        Args:
            config: Configuration dictionary for the FIM manager.
        """
        self.config = config or {}
        self.is_running = False
        self.monitored_paths: Set[str] = set()
        self.file_hashes: Dict[str, str] = {}
        logger.info("FIM Manager initialized")
    
    def start(self) -> None:
        """Start the FIM Manager and begin monitoring files."""
        if self.is_running:
            logger.warning("FIM Manager is already running")
            return
            
        logger.info("Starting FIM Manager...")
        self.is_running = True
        logger.info("FIM Manager started successfully")
    
    def stop(self) -> None:
        """Stop the FIM Manager and all monitoring."""
        if not self.is_running:
            logger.warning("FIM Manager is not running")
            return
            
        logger.info("Stopping FIM Manager...")
        self.is_running = False
        logger.info("FIM Manager stopped successfully")
    
    def add_path(self, path: str, recursive: bool = True) -> bool:
        """Add a path to be monitored.
        
        Args:
            path: The filesystem path to monitor.
            recursive: Whether to monitor subdirectories recursively.
            
        Returns:
            bool: True if the path was added successfully, False otherwise.
        """
        try:
            path = os.path.abspath(path)
            if not os.path.exists(path):
                logger.warning(f"Path does not exist: {path}")
                return False
                
            self.monitored_paths.add(path)
            logger.info(f"Added path to monitoring: {path} (recursive: {recursive})")
            
            # Initial scan of the path
            self._scan_path(path, recursive)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add path {path}: {e}")
            return False
    
    def _scan_path(self, path: str, recursive: bool) -> None:
        """Scan a path and record file hashes."""
        try:
            if os.path.isfile(path):
                self._hash_file(path)
                return
                
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self._hash_file(file_path)
                
                if not recursive:
                    break
                    
        except Exception as e:
            logger.error(f"Error scanning path {path}: {e}")
    
    def _hash_file(self, file_path: str) -> None:
        """Calculate and store the hash of a file."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            self.file_hashes[file_path] = hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Error hashing file {file_path}: {e}")
    
    def check_integrity(self) -> Dict[str, List[str]]:
        """Check the integrity of all monitored files.
        
        Returns:
            Dictionary containing lists of modified, added, and removed files.
        """
        results = {
            "modified": [],
            "added": [],
            "removed": []
        }
        
        current_files = set()
        
        # Check all monitored paths
        for path in self.monitored_paths:
            if os.path.isfile(path):
                current_files.add(path)
                self._check_file(path, results)
            else:
                for root, _, files in os.walk(path):
                    for file in files:
                        file_path = os.path.join(root, file)
                        current_files.add(file_path)
                        self._check_file(file_path, results)
        
        # Check for removed files
        for file_path in set(self.file_hashes.keys()) - current_files:
            results["removed"].append(file_path)
            del self.file_hashes[file_path]
        
        return results
    
    def _check_file(self, file_path: str, results: Dict[str, List[str]]) -> None:
        """Check if a file has been modified."""
        try:
            if file_path not in self.file_hashes:
                results["added"].append(file_path)
                self._hash_file(file_path)
                return
                
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            current_hash = hasher.hexdigest()
            if current_hash != self.file_hashes[file_path]:
                results["modified"].append(file_path)
                self.file_hashes[file_path] = current_hash
                
        except Exception as e:
            logger.error(f"Error checking file {file_path}: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the FIM Manager.
        
        Returns:
            Dictionary containing status information.
        """
        return {
            "status": "running" if self.is_running else "stopped",
            "monitored_paths_count": len(self.monitored_paths),
            "tracked_files_count": len(self.file_hashes),
            "version": "1.0.0"
        }
