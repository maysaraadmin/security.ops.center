""
Memory analysis and forensics module for the EDR system.

This module provides functionality for analyzing process memory to detect
sophisticated threats like fileless malware, code injection, and other
memory-resident attacks.
"""

import os
import re
import sys
import ctypes
import struct
import logging
import platform
import binascii
import hashlib
from typing import Dict, List, Optional, Tuple, Union, Any, Set
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('edr.memory_analyzer')

class MemoryAnalyzer:
    ""
    Memory analysis and forensics for endpoint detection and response.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the memory analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.platform = platform.system().lower()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration settings."""
        # Default configuration
        self.scan_all_processes = self.config.get('scan_all_processes', False)
        self.scan_processes = self.config.get('scan_processes', [])
        self.skip_processes = self.config.get('skip_processes', [])
        self.suspicious_dlls = self.config.get('suspicious_dlls', [])
        self.suspicious_strings = self.config.get('suspicious_strings', [])
        self.suspicious_patterns = self.config.get('suspicious_patterns', [])
        self.max_scan_size = self.config.get('max_scan_size', 100 * 1024 * 1024)  # 100MB
        
        # Compile regex patterns
        self.compiled_patterns = []
        for pattern in self.suspicious_patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE | re.DOTALL))
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {e}")
    
    def analyze_process(self, pid: int) -> Dict[str, Any]:
        """
        Analyze a process for signs of malicious activity.
        
        Args:
            pid: Process ID to analyze
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            'pid': pid,
            'timestamp': datetime.utcnow().isoformat(),
            'findings': [],
            'suspicious': False,
            'error': None
        }
        
        try:
            # Import psutil here to make it optional
            import psutil
            
            # Get process info
            process = psutil.Process(pid)
            results['process_name'] = process.name()
            results['process_cmdline'] = process.cmdline()
            results['process_username'] = process.username()
            
            # Get memory maps
            memory_maps = self._get_memory_maps(process)
            results['memory_maps'] = memory_maps
            
            # Check for suspicious memory regions
            suspicious_regions = self._check_suspicious_regions(process, memory_maps)
            if suspicious_regions:
                results['findings'].extend(suspicious_regions)
            
            # Check for code injection
            code_injection = self._check_code_injection(process, memory_maps)
            if code_injection:
                results['findings'].extend(code_injection)
            
            # Check for suspicious strings in memory
            suspicious_strings = self._check_suspicious_strings(process, memory_maps)
            if suspicious_strings:
                results['findings'].extend(suspicious_strings)
            
            # Mark as suspicious if we found any findings
            if results['findings']:
                results['suspicious'] = True
        
        except Exception as e:
            results['error'] = str(e)
            logger.error(f"Error analyzing process {pid}: {e}", exc_info=True)
        
        return results
    
    def _get_memory_maps(self, process) -> List[Dict[str, Any]]:
        """Get memory maps for a process."""
        memory_maps = []
        
        try:
            for m in process.memory_maps(grouped=False):
                memory_maps.append({
                    'path': m.path,
                    'rss': m.rss,
                    'size': m.size,
                    'pss': getattr(m, 'pss', 0),
                    'shared_clean': getattr(m, 'shared_clean', 0),
                    'shared_dirty': getattr(m, 'shared_dirty', 0),
                    'private_clean': getattr(m, 'private_clean', 0),
                    'private_dirty': getattr(m, 'private_dirty', 0),
                    'referenced': getattr(m, 'referenced', 0),
                    'anonymous': getattr(m, 'anonymous', 0),
                    'swap': getattr(m, 'swap', 0)
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
        return memory_maps
    
    def _check_suspicious_regions(self, process, memory_maps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for suspicious memory regions."""
        findings = []
        
        for region in memory_maps:
            # Check for executable stack (common in exploits)
            if 'x' in region.get('perms', '') and 'stack' in region.get('path', '').lower():
                findings.append({
                    'type': 'executable_stack',
                    'path': region.get('path', ''),
                    'size': region.get('size', 0),
                    'perms': region.get('perms', '')
                })
            
            # Check for RWX memory (highly suspicious)
            if 'rwx' in region.get('perms', '').lower():
                findings.append({
                    'type': 'rwx_memory',
                    'path': region.get('path', ''),
                    'size': region.get('size', 0),
                    'perms': region.get('perms', '')
                })
            
            # Check for suspicious module paths
            path = region.get('path', '').lower()
            if any(suspicious in path for suspicious in ['temp', 'appdata', 'temporary']):
                findings.append({
                    'type': 'suspicious_module_path',
                    'path': region.get('path', ''),
                    'reason': 'Module loaded from temporary directory'
                })
        
        return findings
    
    def _check_code_injection(self, process, memory_maps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for signs of code injection."""
        findings = []
        
        try:
            # Check for threads with start addresses outside of loaded modules
            for thread in process.threads():
                try:
                    # This is a simplified check - actual implementation would be platform-specific
                    # and require more advanced memory forensics
                    pass
                except Exception as e:
                    logger.warning(f"Error checking thread {thread.id}: {e}")
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return findings
    
    def _check_suspicious_strings(self, process, memory_maps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Check for suspicious strings in process memory."""
        findings = []
        
        # This is a placeholder - actual implementation would scan process memory
        # for the suspicious strings defined in the configuration
        
        return findings

    def scan_system(self) -> List[Dict[str, Any]]:
        """
        Scan all running processes for signs of malicious activity.
        
        Returns:
            List of analysis results for each process
        """
        results = []
        
        try:
            import psutil
            
            for process in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    pid = process.info['pid']
                    name = process.info['name']
                    
                    # Skip processes in the skip list
                    if name.lower() in [p.lower() for p in self.skip_processes]:
                        continue
                    
                    # If not scanning all processes, check if this one is in our target list
                    if not self.scan_all_processes and name.lower() not in [p.lower() for p in self.scan_processes]:
                        continue
                    
                    # Analyze the process
                    result = self.analyze_process(pid)
                    if result['suspicious'] or result['error']:
                        results.append(result)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    logger.error(f"Error scanning process {process.info.get('pid', 'unknown')}: {e}")
        
        except ImportError:
            logger.error("psutil module is required for process scanning")
        
        return results

def analyze_process(pid: int, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ""
    Convenience function to analyze a single process.
    
    Args:
        pid: Process ID to analyze
        config: Optional configuration dictionary
        
    Returns:
        Dictionary with analysis results
    ""
    analyzer = MemoryAnalyzer(config or {})
    return analyzer.analyze_process(pid)

def scan_system(config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    ""
    Convenience function to scan all running processes.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        List of analysis results for each process
    ""
    analyzer = MemoryAnalyzer(config or {})
    return analyzer.scan_system()

# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'scan_all_processes': True,
        'skip_processes': ['System', 'System Idle Process', 'svchost.exe'],
        'suspicious_dlls': ['evil.dll', 'injector.dll'],
        'suspicious_strings': ['http://malicious.com', 'evil_command'],
        'suspicious_patterns': [
            r'[0-9a-fA-F]{32}',  # MD5 hashes
            r'[0-9a-fA-F]{40}',  # SHA-1 hashes
            r'[0-9a-fA-F]{64}'   # SHA-256 hashes
        ]
    }
    
    # Create analyzer with configuration
    analyzer = MemoryAnalyzer(config)
    
    # Scan all processes
    results = analyzer.scan_system()
    
    # Print results
    for result in results:
        if result['suspicious']:
            print(f"\nSuspicious process found: {result.get('process_name', 'unknown')} (PID: {result['pid']})")
            for finding in result.get('findings', []):
                print(f"  - {finding.get('type', 'unknown')}: {finding.get('reason', 'No reason provided')}")
        elif result.get('error'):
            print(f"\nError analyzing process {result['pid']}: {result['error']}")
