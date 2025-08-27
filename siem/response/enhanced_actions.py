"""
Enhanced response actions for SIEM incident response.
"""
import subprocess
import logging
import platform
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json
import socket
import os

from .base import ResponseAction

class TerminateProcessAction(ResponseAction):
    """Terminates a potentially malicious process."""
    
    def _setup(self) -> None:
        """Initialize the process termination action."""
        self.logger = logging.getLogger("siem.response.terminate_process")
        self.platform = platform.system().lower()
        self.whitelist = set(self.config.get('whitelisted_processes', []))
        
    def execute(self, alert: Dict[str, Any]) -> bool:
        """
        Terminate the process specified in the alert.
        
        Args:
            alert: Dictionary containing alert details including process information
            
        Returns:
            bool: True if process was terminated successfully, False otherwise
        """
        try:
            process_info = alert.get('process', {})
            pid = process_info.get('pid')
            name = process_info.get('name', '').lower()
            
            if not pid:
                self.logger.warning("No process ID in alert")
                return False
                
            # Check if process is whitelisted
            if name in self.whitelist:
                self.logger.info(f"Process {name} (PID: {pid}) is whitelisted, skipping termination")
                return False
                
            # Additional safety check - verify process exists
            if not psutil.pid_exists(pid):
                self.logger.warning(f"Process with PID {pid} does not exist")
                return False
                
            # Terminate the process
            if self.platform == 'windows':
                result = subprocess.run(
                    ['taskkill', '/F', '/PID', str(pid)],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['kill', '-9', str(pid)],
                    capture_output=True,
                    text=True
                )
                
            if result.returncode == 0:
                self.logger.info(f"Successfully terminated process {name} (PID: {pid})")
                return True
            else:
                self.logger.error(
                    f"Failed to terminate process {name} (PID: {pid}): "
                    f"{result.stderr or result.stdout}"
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Error terminating process: {str(e)}", exc_info=True)
            return False

class MemoryDumpAction(ResponseAction):
    """Captures a memory dump of a suspicious process for forensic analysis.
    
    On Windows, requires Sysinternals Procdump (https://learn.microsoft.com/en-us/sysinternals/downloads/procdump)
    On Linux, requires gcore (part of gdb)
    """
    
    def _setup(self) -> None:
        """Initialize the memory dump action."""
        self.logger = logging.getLogger("siem.response.memory_dump")
        self.platform = platform.system().lower()
        self.output_dir = self.config.get('output_dir', '/var/forensics/memory_dumps')
        self.compress = self.config.get('compress', True)
        self.required_tools = self._get_required_tools()
        
        # Create output directory if it doesn't exist
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except Exception as e:
            self.logger.error(f"Failed to create output directory {self.output_dir}: {str(e)}")
            raise
    
    def _get_required_tools(self) -> Dict[str, List[str]]:
        """Return the required tools for the current platform."""
        if self.platform == 'windows':
            return {
                'procdump': [
                    'Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump',
                    'Add the directory containing procdump.exe to your PATH',
                    'Accept the Sysinternals license agreement on first run'
                ]
            }
        else:
            return {
                'gcore': [
                    'Install gdb package (e.g., `sudo apt-get install gdb` on Debian/Ubuntu)',
                    'Ensure gcore is in your PATH'
                ]
            }
    
    def _check_prerequisites(self) -> Optional[Dict[str, str]]:
        """Check if required tools are available."""
        missing_tools = []
        
        for tool in self.required_tools.keys():
            try:
                if self.platform == 'windows':
                    subprocess.run(
                        ['where', tool],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True
                    )
                else:
                    subprocess.run(
                        ['which', tool],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True
                    )
            except (subprocess.SubprocessError, FileNotFoundError):
                missing_tools.append(tool)
        
        if missing_tools:
            error_msg = "Missing required tools for memory dump:\n"
            for tool in missing_tools:
                error_msg += f"\n{tool} is required but not found.\n"
                error_msg += "\n".join(f"  - {step}" for step in self.required_tools[tool])
                error_msg += "\n"
            return {"status": "error", "message": error_msg}
        return None
        
    def execute(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Capture a memory dump of the specified process.
        
        Args:
            alert: Dictionary containing alert details including process information
            
        Returns:
            Dict containing status and output file path or error message
        """
        try:
            # Check prerequisites first
            prereq_check = self._check_prerequisites()
            if prereq_check:
                return prereq_check
                
            process_info = alert.get('process', {})
            pid = process_info.get('pid')
            
            if not pid:
                error_msg = "No process ID in alert"
                self.logger.warning(error_msg)
                return {"status": "error", "message": error_msg}
            
            # Verify the process exists
            try:
                psutil.Process(pid)
            except psutil.NoSuchProcess:
                error_msg = f"Process with PID {pid} does not exist"
                self.logger.warning(error_msg)
                return {"status": "error", "message": error_msg}
                
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(
                self.output_dir,
                f"memory_dump_pid{pid}_{timestamp}.dmp"
            )
            
            # Platform-specific memory dumping
            if self.platform == 'windows':
                result = self._dump_windows(pid, output_file)
            else:
                result = self._dump_linux(pid, output_file)
            
            if result['status'] == 'success':
                self.logger.info(f"Successfully created memory dump at {output_file}")
                return {
                    "status": "success",
                    "output_file": output_file,
                    "size_mb": os.path.getsize(output_file) / (1024 * 1024),
                    "message": "Memory dump completed successfully"
                }
            return result
                
        except Exception as e:
            error_msg = f"Unexpected error creating memory dump: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {
                "status": "error",
                "message": error_msg
            }
    
    def _dump_windows(self, pid: int, output_file: str) -> Dict[str, str]:
        """Create a memory dump on Windows using procdump."""
        try:
            result = subprocess.run(
                ['procdump', '-accepteula', '-ma', str(pid), output_file],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0 or not os.path.exists(output_file):
                error_msg = result.stderr or "Unknown error creating memory dump"
                if "The system cannot find the file specified" in error_msg:
                    error_msg = ("procdump not found. Please install Sysinternals Procdump from "
                               "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump and ensure it's in your PATH.")
                self.logger.error(f"Failed to create memory dump: {error_msg}")
                return {
                    "status": "error",
                    "message": f"Failed to create memory dump: {error_msg}"
                }
                
            return {"status": "success"}
            
        except subprocess.TimeoutExpired:
            error_msg = "Memory dump timed out after 5 minutes"
            self.logger.error(error_msg)
            return {"status": "error", "message": error_msg}
            
        except Exception as e:
            error_msg = f"Error creating memory dump: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {"status": "error", "message": error_msg}
    
    def _dump_linux(self, pid: int, output_file: str) -> Dict[str, str]:
        """Create a memory dump on Linux using gcore."""
        try:
            result = subprocess.run(
                ['gcore', '-o', output_file, str(pid)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode != 0 or not any(f.startswith(os.path.basename(output_file)) 
                                              for f in os.listdir(self.output_dir)):
                error_msg = result.stderr or "Unknown error creating memory dump"
                if "command not found" in error_msg:
                    error_msg = ("gcore not found. Please install gdb package (e.g., "
                               "`sudo apt-get install gdb` on Debian/Ubuntu).")
                self.logger.error(f"Failed to create memory dump: {error_msg}")
                return {
                    "status": "error",
                    "message": f"Failed to create memory dump: {error_msg}"
                }
                
            return {"status": "success"}
            
        except subprocess.TimeoutExpired:
            error_msg = "Memory dump timed out after 5 minutes"
            self.logger.error(error_msg)
            return {"status": "error", "message": error_msg}
            
        except Exception as e:
            error_msg = f"Error creating memory dump: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return {"status": "error", "message": error_msg}

# Export available actions
ACTIONS = {
    'terminate_process': TerminateProcessAction,
    'memory_dump': MemoryDumpAction
}
