"""
Memory Analysis for EDR.
Provides capabilities for memory acquisition and analysis.
"""
import os
import platform
import logging
import subprocess
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple, BinaryIO, Union
from datetime import datetime
import hashlib
import json
import gzip
import io

from .timeline import TimelineEvent, EventType
from .collector import Evidence, EvidenceType

class MemoryDumpMethod(str, Enum):
    """Supported memory dump methods."""
    WINPMEM = 'winpmem'
    REKALL = 'rekall'
    VOLATILITY = 'volatility'
    DUMPIT = 'dumpit'
    LIBCOREDUMP = 'libcoredump'

class MemoryAnalyzer:
    """Handles memory acquisition and analysis."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the memory analyzer."""
        self.config = config
        self.logger = logging.getLogger('edr.forensics.memory')
        self.temp_dir = tempfile.mkdtemp(prefix='edr_mem_')
        
        # Platform-specific settings
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == 'windows'
        self.is_linux = self.os_type == 'linux'
        self.is_macos = self.os_type == 'darwin'
        
        # Default dump method based on OS
        self.default_method = {
            'windows': MemoryDumpMethod.WINPMEM,
            'linux': MemoryDumpMethod.LIBCOREDUMP,
            'darwin': MemoryDumpMethod.LIBCOREDUMP
        }.get(self.os_type, MemoryDumpMethod.LIBCOREDUMP)
    
    def __del__(self):
        """Clean up temporary files."""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            self.logger.warning(f"Failed to clean up temporary directory: {e}")
    
    def acquire_memory(
        self,
        output_path: Optional[str] = None,
        method: Optional[Union[str, MemoryDumpMethod]] = None,
        compress: bool = True
    ) -> Optional[Evidence]:
        """
        Acquire a memory dump from the system.
        
        Args:
            output_path: Path to save the memory dump (default: temporary file)
            method: Memory acquisition method to use
            compress: Whether to compress the memory dump
            
        Returns:
            Evidence object containing the memory dump, or None if acquisition failed
        """
        if method is None:
            method = self.default_method
        elif isinstance(method, str):
            method = MemoryDumpMethod(method.lower())
        
        self.logger.info(f"Acquiring memory dump using {method.value}")
        
        try:
            if method == MemoryDumpMethod.WINPMEM and self.is_windows:
                return self._acquire_with_winpmem(output_path, compress)
            elif method == MemoryDumpMethod.LIBCOREDUMP and (self.is_linux or self.is_macos):
                return self._acquire_with_libcoredump(output_path, compress)
            else:
                self.logger.error(f"Unsupported memory acquisition method for this platform: {method}")
                return None
                
        except Exception as e:
            self.logger.error(f"Memory acquisition failed: {e}", exc_info=True)
            return None
    
    def _acquire_with_winpmem(
        self,
        output_path: Optional[str] = None,
        compress: bool = True
    ) -> Optional[Evidence]:
        """Acquire memory using WinPMEM (Windows)."""
        try:
            # Check if WinPMEM is installed
            try:
                import winpmem
            except ImportError:
                self.logger.error("WinPMEM not installed. Install with: pip install winpmem")
                return None
            
            # Create temporary file if no output path specified
            if not output_path:
                output_path = os.path.join(
                    self.temp_dir,
                    f"memory_dump_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.raw"
                )
            
            # Configure WinPMEM
            pmem = winpmem.WinPmem()
            
            # Check if we have write access to the output path
            try:
                with open(output_path, 'wb') as f:
                    pass
                os.remove(output_path)
            except IOError as e:
                self.logger.error(f"Cannot write to output path {output_path}: {e}")
                return None
            
            # Dump memory
            self.logger.info(f"Dumping memory to {output_path}...")
            pmem.acquire(output_path)
            
            # Verify the dump
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                self.logger.error("Memory dump file is empty or was not created")
                return None
            
            # Calculate hashes
            file_hashes = self._calculate_file_hashes(output_path)
            
            # Compress if requested
            if compress:
                compressed_path = f"{output_path}.gz"
                self.logger.info(f"Compressing memory dump to {compressed_path}...")
                with open(output_path, 'rb') as f_in, gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                
                # Update hashes for the compressed file
                compressed_hashes = self._calculate_file_hashes(compressed_path)
                os.remove(output_path)  # Remove uncompressed file
                output_path = compressed_path
                file_hashes.update({
                    f'compressed_{k}': v for k, v in compressed_hashes.items()
                })
            
            # Create evidence
            return Evidence(
                evidence_type=EvidenceType.MEMORY,
                source='winpmem',
                data={
                    'dump_path': output_path,
                    'size': os.path.getsize(output_path),
                    'hashes': file_hashes,
                    'compressed': compress,
                    'method': 'winpmem',
                    'platform': 'windows'
                },
                metadata={
                    'acquisition_time': datetime.utcnow().isoformat() + 'Z',
                    'hostname': platform.node(),
                    'os': platform.system(),
                    'os_version': platform.version(),
                    'architecture': platform.machine(),
                    'memory_size': self._get_total_memory()
                }
            )
            
        except Exception as e:
            self.logger.error(f"WinPMEM acquisition failed: {e}", exc_info=True)
            return None
    
    def _acquire_with_libcoredump(
        self,
        output_path: Optional[str] = None,
        compress: bool = True
    ) -> Optional[Evidence]:
        """Acquire memory using libcoredump (Linux/macOS)."""
        try:
            # Check if we have permission to read /dev/mem or /dev/kmem
            if not os.access("/dev/mem", os.R_OK) and not os.access("/proc/kcore", os.R_OK):
                self.logger.error("Insufficient permissions to read memory. Run as root.")
                return None
            
            # Create temporary file if no output path specified
            if not output_path:
                output_path = os.path.join(
                    self.temp_dir,
                    f"memory_dump_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.dump"
                )
            
            # Try to use /proc/kcore first (Linux)
            if os.path.exists("/proc/kcore"):
                self.logger.info("Acquiring memory using /proc/kcore...")
                with open("/proc/kcore", 'rb') as src, open(output_path, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
            # Fall back to /dev/mem
            elif os.path.exists("/dev/mem") and os.access("/dev/mem", os.R_OK):
                self.logger.info("Acquiring memory using /dev/mem...")
                with open("/dev/mem", 'rb') as src, open(output_path, 'wb') as dst:
                    # Only copy the first 4GB (adjust as needed)
                    shutil.copyfileobj(io.BytesIO(src.read(4 * 1024 * 1024 * 1024)), dst)
            else:
                self.logger.error("No supported memory acquisition method available")
                return None
            
            # Verify the dump
            if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
                self.logger.error("Memory dump file is empty or was not created")
                return None
            
            # Calculate hashes
            file_hashes = self._calculate_file_hashes(output_path)
            
            # Compress if requested
            if compress:
                compressed_path = f"{output_path}.gz"
                self.logger.info(f"Compressing memory dump to {compressed_path}...")
                with open(output_path, 'rb') as f_in, gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                
                # Update hashes for the compressed file
                compressed_hashes = self._calculate_file_hashes(compressed_path)
                os.remove(output_path)  # Remove uncompressed file
                output_path = compressed_path
                file_hashes.update({
                    f'compressed_{k}': v for k, v in compressed_hashes.items()
                })
            
            # Create evidence
            return Evidence(
                evidence_type=EvidenceType.MEMORY,
                source='libcoredump',
                data={
                    'dump_path': output_path,
                    'size': os.path.getsize(output_path),
                    'hashes': file_hashes,
                    'compressed': compress,
                    'method': 'libcoredump',
                    'platform': self.os_type
                },
                metadata={
                    'acquisition_time': datetime.utcnow().isoformat() + 'Z',
                    'hostname': platform.node(),
                    'os': platform.system(),
                    'os_version': platform.version(),
                    'architecture': platform.machine(),
                    'memory_size': self._get_total_memory()
                }
            )
            
        except Exception as e:
            self.logger.error(f"Memory acquisition failed: {e}", exc_info=True)
            return None
    
    def analyze_memory(
        self,
        memory_dump_path: str,
        plugins: Optional[List[str]] = None,
        output_format: str = 'json'
    ) -> Dict[str, Any]:
        """
        Analyze a memory dump using Volatility or Rekall.
        
        Args:
            memory_dump_path: Path to the memory dump file
            plugins: List of analysis plugins to run
            output_format: Output format (json, text, csv)
            
        Returns:
            Dictionary containing analysis results
        """
        if not os.path.exists(memory_dump_path):
            self.logger.error(f"Memory dump file not found: {memory_dump_path}")
            return {}
        
        # Default plugins if none specified
        if not plugins:
            plugins = [
                'pslist', 'pstree', 'dlllist', 'handles', 'sockets', 'connections',
                'sockscan', 'netscan', 'cmdline', 'envars', 'filescan', 'malfind'
            ]
        
        results = {}
        
        # Try to use Volatility if available
        if self._is_tool_available('vol.py'):
            self.logger.info("Analyzing memory with Volatility...")
            for plugin in plugins:
                try:
                    cmd = [
                        'vol.py',
                        '-f', memory_dump_path,
                        '--output', output_format,
                        plugin
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    if output_format == 'json':
                        try:
                            results[plugin] = json.loads(result.stdout)
                        except json.JSONDecodeError:
                            results[plugin] = result.stdout
                    else:
                        results[plugin] = result.stdout
                        
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Volatility plugin {plugin} failed: {e}")
                    results[plugin] = {"error": str(e)}
        
        # Fall back to Rekall if Volatility is not available
        elif self._is_tool_available('rekall'):
            self.logger.info("Analyzing memory with Rekall...")
            for plugin in plugins:
                try:
                    cmd = [
                        'rekall',
                        '-f', memory_dump_path,
                        '--format', output_format,
                        plugin
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        check=True
                    )
                    
                    if output_format == 'json':
                        try:
                            results[plugin] = json.loads(result.stdout)
                        except json.JSONDecodeError:
                            results[plugin] = result.stdout
                    else:
                        results[plugin] = result.stdout
                        
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Rekall plugin {plugin} failed: {e}")
                    results[plugin] = {"error": str(e)}
        
        else:
            self.logger.error("Neither Volatility nor Rekall is installed")
            return {"error": "No memory analysis tools available"}
        
        return results
    
    def _is_tool_available(self, tool_name: str) -> bool:
        """Check if a command-line tool is available."""
        try:
            subprocess.run(
                [tool_name, '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return True
        except (OSError, subprocess.SubprocessError):
            return False
    
    def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes for a file."""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {file_path}: {e}")
            return {}
    
    def _get_total_memory(self) -> int:
        """Get total system memory in bytes."""
        try:
            if self.is_linux or self.is_macos:
                with open('/proc/meminfo' if self.is_linux else '/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            return int(line.split()[1]) * 1024  # Convert from KB to bytes
            elif self.is_windows:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ('dwLength', ctypes.c_ulong),
                        ('dwMemoryLoad', ctypes.c_ulong),
                        ('ullTotalPhys', ctypes.c_ulonglong),
                        ('ullAvailPhys', ctypes.c_ulonglong),
                        ('ullTotalPageFile', ctypes.c_ulonglong),
                        ('ullAvailPageFile', ctypes.c_ulonglong),
                        ('ullTotalVirtual', ctypes.c_ulonglong),
                        ('ullAvailVirtual', ctypes.c_ulonglong),
                        ('sullAvailExtendedVirtual', ctypes.c_ulonglong),
                    ]
                
                memory_status = MEMORYSTATUSEX()
                memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                    return memory_status.ullTotalPhys
        except Exception as e:
            self.logger.warning(f"Failed to get total memory: {e}")
        
        return 0

class MemoryForensics:
    """High-level memory forensics interface."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the memory forensics module."""
        self.config = config
        self.analyzer = MemoryAnalyzer(config)
        self.logger = logging.getLogger('edr.forensics.memory')
    
    def acquire_and_analyze(
        self,
        output_dir: Optional[str] = None,
        compress: bool = True,
        plugins: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Acquire and analyze system memory.
        
        Args:
            output_dir: Directory to save memory dump and analysis results
            compress: Whether to compress the memory dump
            plugins: List of analysis plugins to run
            
        Returns:
            Dictionary containing acquisition and analysis results
        """
        # Create output directory if it doesn't exist
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Acquire memory
        memory_dump_path = os.path.join(output_dir, 'memory.dump') if output_dir else None
        evidence = self.analyzer.acquire_memory(memory_dump_path, compress=compress)
        
        if not evidence:
            return {"error": "Failed to acquire memory dump"}
        
        # Save evidence
        if output_dir:
            evidence_path = os.path.join(output_dir, 'memory_evidence.json')
            evidence.save_to_file(evidence_path)
        
        # Analyze memory if a dump was created
        analysis_results = {}
        if evidence.data.get('dump_path') and os.path.exists(evidence.data['dump_path']):
            analysis_results = self.analyzer.analyze_memory(
                evidence.data['dump_path'],
                plugins=plugins
            )
            
            # Save analysis results
            if output_dir and analysis_results:
                analysis_path = os.path.join(output_dir, 'memory_analysis.json')
                with open(analysis_path, 'w') as f:
                    json.dump(analysis_results, f, indent=2)
        
        return {
            "acquisition": evidence.to_dict(),
            "analysis": analysis_results
        }
