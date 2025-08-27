"""
System Call Monitor Module

This module provides system call monitoring capabilities for the HIPS system,
allowing detection of suspicious system-level activities that may indicate
malware or unauthorized access attempts.
"""

import os
import sys
import time
import ctypes
import signal
import logging
import platform
import threading
import subprocess
from typing import Dict, List, Optional, Set, Tuple, Callable, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import json

# Platform-specific imports
try:
    import psutil
    import win32api
    import win32con
    import win32process
    import win32security
    WINDOWS = True
except ImportError:
    import psutil
    WINDOWS = False

# Import local modules
from ..utils.helpers import is_suspicious_file_extension, calculate_entropy

logger = logging.getLogger('hips.system_call_monitor')

@dataclass
class SyscallEvent:
    """Represents a system call event."""
    timestamp: float
    pid: int
    process_name: str
    syscall: str
    arguments: Dict[str, Any]
    return_value: Any = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class SystemCallMonitor:
    """Monitors system calls for suspicious activities."""
    
    def __init__(
        self,
        config: Dict[str, Any],
        event_logger: 'EventLogger',
        response_engine: 'ResponseEngine',
        policy_manager: 'PolicyManager'
    ):
        """Initialize the system call monitor.
        
        Args:
            config: Configuration dictionary
            event_logger: Event logger instance
            response_engine: Response engine for taking actions
            policy_manager: Policy manager for access control
        """
        self.config = config
        self.enabled = config.get('enabled', True)
        self.monitor_syscalls = set(config.get('monitor_syscalls', []))
        
        self.event_logger = event_logger
        self.response_engine = response_engine
        self.policy_manager = policy_manager
        
        self.running = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._syscall_handlers = {}
        
        # Initialize platform-specific components
        self._init_platform()
        
        # Register default syscall handlers
        self._register_default_handlers()
        
        logger.info("System call monitor initialized")
    
    def _init_platform(self) -> None:
        """Initialize platform-specific components."""
        self.platform = platform.system().lower()
        
        if self.platform == 'windows':
            self._init_windows()
        elif self.platform == 'linux':
            self._init_linux()
        else:
            logger.warning(f"Unsupported platform: {self.platform}")
            self.enabled = False
    
    def _init_windows(self) -> None:
        """Initialize Windows-specific components."""
        try:
            # Import Windows-specific modules
            import win32api
            import win32con
            import win32process
            import win32security
            
            # Set up API hooking for Windows
            self._setup_windows_hooks()
            
        except ImportError as e:
            logger.error(f"Failed to initialize Windows components: {e}")
            self.enabled = False
    
    def _init_linux(self) -> None:
        """Initialize Linux-specific components."""
        try:
            # Check for required Linux capabilities
            if os.geteuid() != 0:
                logger.warning("System call monitor requires root privileges on Linux")
                self.enabled = False
                return
                
            # Set up eBPF or ptrace for system call monitoring
            self._setup_linux_hooks()
            
        except Exception as e:
            logger.error(f"Failed to initialize Linux components: {e}")
            self.enabled = False
    
    def _setup_windows_hooks(self) -> None:
        """Set up API hooks for Windows system calls."""
        # This is a simplified version - in a real implementation, you would use
        # a library like Detours, EasyHook, or Frida for API hooking
        self._hooked_apis = {}
        
        # Map Windows API functions to their modules
        self._api_mapping = {
            'CreateFileW': 'kernel32.dll',
            'CreateProcessW': 'kernel32.dll',
            'OpenProcess': 'kernel32.dll',
            'WriteProcessMemory': 'kernel32.dll',
            'VirtualAllocEx': 'kernel32.dll',
            'CreateRemoteThread': 'kernel32.dll',
            'RegCreateKeyExW': 'advapi32.dll',
            'RegSetValueExW': 'advapi32.dll',
            'LoadLibraryA': 'kernel32.dll',
            'LoadLibraryW': 'kernel32.dll',
            'LoadLibraryExA': 'kernel32.dll',
            'LoadLibraryExW': 'kernel32.dll',
            'WinExec': 'kernel32.dll',
            'ShellExecuteA': 'shell32.dll',
            'ShellExecuteW': 'shell32.dll',
            'ShellExecuteExA': 'shell32.dll',
            'ShellExecuteExW': 'shell32.dll',
        }
        
        logger.info("Windows API hooks initialized")
    
    def _setup_linux_hooks(self) -> None:
        """Set up eBPF or ptrace for Linux system call monitoring."""
        # This is a placeholder - in a real implementation, you would use
        # eBPF, ptrace, or auditd for system call monitoring
        self._bpf_program = None
        
        try:
            # Try to use eBPF if available
            from bcc import BPF
            
            # Simple eBPF program to trace execve syscalls
            bpf_text = """
            #include <uapi/linux/ptrace.h>
            #include <linux/sched.h>
            
            struct data_t {
                u32 pid;
                u32 uid;
                char comm[TASK_COMM_LEN];
                char filename[256];
            };
            
            BPF_PERF_OUTPUT(events);
            
            int trace_sys_execve(struct pt_regs *ctx, const char __user *filename,
                               const char __user *const __user *argv,
                               const char __user *const __user *envp) {
                struct data_t data = {};
                struct task_struct *task = (struct task_struct *)bpf_get_current_task();
                
                data.pid = bpf_get_current_pid_tgid() >> 32;
                data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);
                
                events.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }
            """
            
            self._bpf = BPF(text=bpf_text)
            self._bpf.attach_kprobe(event="__x64_sys_execve", fn_name="trace_sys_execve")
            
            logger.info("eBPF-based system call monitoring enabled")
            
        except ImportError:
            # Fall back to using strace if eBPF is not available
            logger.warning("eBPF not available, using ptrace-based monitoring")
            self._use_ptrace = True
    
    def _register_default_handlers(self) -> None:
        """Register default system call handlers."""
        # File operations
        self.register_handler('open', self._handle_file_open)
        self.register_handler('openat', self._handle_file_open)
        self.register_handler('execve', self._handle_execve)
        self.register_handler('execveat', self._handle_execve)
        
        # Process operations
        self.register_handler('fork', self._handle_process_ops)
        self.register_handler('vfork', self._handle_process_ops)
        self.register_handler('clone', self._handle_process_ops)
        self.register_handler('kill', self._handle_kill)
        
        # Network operations
        self.register_handler('connect', self._handle_connect)
        self.register_handler('bind', self._handle_bind)
        self.register_handler('accept', self._handle_accept)
        
        # Privilege escalation
        self.register_handler('setuid', self._handle_privilege_ops)
        self.register_handler('setgid', self._handle_privilege_ops)
        self.register_handler('setreuid', self._handle_privilege_ops)
        self.register_handler('setregid', self._handle_privilege_ops)
        self.register_handler('setresuid', self._handle_privilege_ops)
        self.register_handler('setresgid', self._handle_privilege_ops)
        self.register_handler('capset', self._handle_capset)
        
        # Memory operations
        self.register_handler('mprotect', self._handle_mprotect)
        self.register_handler('ptrace', self._handle_ptrace)
        
        # Windows-specific handlers
        if WINDOWS:
            self.register_handler('CreateFileW', self._handle_win32_createfile)
            self.register_handler('CreateProcessW', self._handle_win32_createprocess)
            self.register_handler('WriteProcessMemory', self._handle_win32_writeprocmem)
            self.register_handler('VirtualAllocEx', self._handle_win32_virtualallocex)
            self.register_handler('CreateRemoteThread', self._handle_win32_createremotethread)
            self.register_handler('RegCreateKeyExW', self._handle_win32_regcreatekey)
            self.register_handler('RegSetValueExW', self._handle_win32_regsetvalue)
    
    def register_handler(self, syscall: str, handler: Callable) -> None:
        """Register a handler for a specific system call.
        
        Args:
            syscall: Name of the system call
            handler: Callback function to handle the system call
        """
        self._syscall_handlers[syscall] = handler
    
    def unregister_handler(self, syscall: str) -> None:
        """Unregister a system call handler.
        
        Args:
            syscall: Name of the system call
        """
        if syscall in self._syscall_handlers:
            del self._syscall_handlers[syscall]
    
    def start(self) -> None:
        """Start the system call monitor."""
        if not self.enabled:
            logger.info("System call monitor is disabled in configuration")
            return
            
        if self.running:
            logger.warning("System call monitor is already running")
            return
            
        logger.info("Starting system call monitor...")
        self.running = True
        self._stop_event.clear()
        
        # Start monitoring in a separate thread
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="SystemCallMonitor",
            daemon=True
        )
        self._monitor_thread.start()
        
        logger.info("System call monitor started")
    
    def stop(self) -> None:
        """Stop the system call monitor."""
        if not self.running:
            return
            
        logger.info("Stopping system call monitor...")
        self.running = False
        self._stop_event.set()
        
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
            if self._monitor_thread.is_alive():
                logger.warning("System call monitor thread did not stop gracefully")
            self._monitor_thread = None
        
        # Clean up platform-specific resources
        self._cleanup_platform()
        
        logger.info("System call monitor stopped")
    
    def _cleanup_platform(self) -> None:
        """Clean up platform-specific resources."""
        if hasattr(self, '_bpf'):
            try:
                self._bpf = None
            except Exception as e:
                logger.error(f"Error cleaning up eBPF: {e}")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        logger.debug("System call monitor loop started")
        
        try:
            if hasattr(self, '_bpf'):
                self._monitor_ebpf()
            else:
                self._monitor_ptrace()
                
        except Exception as e:
            logger.error(f"Error in system call monitor loop: {e}", exc_info=True)
    
    def _monitor_ebpf(self) -> None:
        """Monitor system calls using eBPF."""
        from bcc import BPF
        
        def print_event(cpu, data, size):
            event = self._bpf['events'].event(data)
            print(f"PID: {event.pid}, UID: {event.uid}, CMD: {event.comm.decode()}, EXEC: {event.filename.decode()}")
        
        self._bpf['events'].open_perf_buffer(print_event)
        
        while not self._stop_event.is_set():
            try:
                self._bpf.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error polling eBPF events: {e}")
                time.sleep(1)
    
    def _monitor_ptrace(self) -> None:
        """Monitor system calls using ptrace (fallback)."""
        # This is a simplified implementation
        # In a real implementation, you would use ptrace to trace system calls
        while not self._stop_event.is_set():
            try:
                # Simulate system call monitoring
                # In a real implementation, this would use ptrace or similar
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in ptrace monitor: {e}")
                time.sleep(1)
    
    # System call handlers
    
    def _handle_file_open(self, event: SyscallEvent) -> None:
        """Handle file open operations."""
        try:
            filepath = event.arguments.get('pathname', '')
            if not filepath:
                return
                
            # Check if the file is in a protected directory
            protected_dirs = self.policy_manager.get_protected_paths()
            if any(filepath.startswith(d) for d in protected_dirs):
                # Check if the process has permission to access this file
                if not self.policy_manager.check_file_access(
                    event.pid, 
                    filepath, 
                    'read' if 'O_RDONLY' in event.arguments.get('flags', '') else 'write'
                ):
                    # Deny access
                    event.return_value = -1  # EACCES
                    event.error = "Permission denied"
                    
                    # Log the violation
                    self._log_violation(
                        event,
                        'unauthorized_file_access',
                        f"Process {event.process_name} (PID: {event.pid}) attempted to access protected file: {filepath}",
                        'high'
                    )
        
        except Exception as e:
            logger.error(f"Error in _handle_file_open: {e}", exc_info=True)
    
    def _handle_execve(self, event: SyscallEvent) -> None:
        """Handle process execution."""
        try:
            filename = event.arguments.get('filename', '')
            if not filename:
                return
                
            # Check if the executable is allowed
            if not self.policy_manager.check_executable(event.pid, filename):
                # Deny execution
                event.return_value = -1  # EACCES
                event.error = "Execution not permitted"
                
                # Log the violation
                self._log_violation(
                    event,
                    'unauthorized_execution',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to execute unauthorized binary: {filename}",
                    'high'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_execve: {e}", exc_info=True)
    
    def _handle_process_ops(self, event: SyscallEvent) -> None:
        """Handle process operations (fork, vfork, clone)."""
        try:
            # Check if process creation is allowed
            if not self.policy_manager.check_process_creation(event.pid):
                # Deny process creation
                event.return_value = -1  # EPERM
                event.error = "Process creation not permitted"
                
                # Log the violation
                self._log_violation(
                    event,
                    'unauthorized_process_creation',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to create a new process",
                    'high'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_process_ops: {e}", exc_info=True)
    
    def _handle_kill(self, event: SyscallEvent) -> None:
        """Handle process termination signals."""
        try:
            target_pid = event.arguments.get('pid', -1)
            sig = event.arguments.get('sig', 0)
            
            # Check if the process is allowed to send signals to the target
            if not self.policy_manager.check_signal_permission(event.pid, target_pid, sig):
                # Deny the signal
                event.return_value = -1  # EPERM
                event.error = "Operation not permitted"
                
                # Log the violation
                self._log_violation(
                    event,
                    'unauthorized_signal',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to send signal {sig} to process {target_pid}",
                    'medium'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_kill: {e}", exc_info=True)
    
    def _handle_connect(self, event: SyscallEvent) -> None:
        """Handle network connection attempts."""
        try:
            # Check if the process is allowed to make network connections
            if not self.policy_manager.check_network_access(event.pid, 'outbound'):
                # Deny the connection
                event.return_value = -1  # EACCES
                event.error = "Network access denied"
                
                # Log the violation
                self._log_violation(
                    event,
                    'unauthorized_network_access',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to make an outbound network connection",
                    'medium'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_connect: {e}", exc_info=True)
    
    def _handle_privilege_ops(self, event: SyscallEvent) -> None:
        """Handle privilege-related system calls."""
        try:
            # Check if the process is allowed to change privileges
            if not self.policy_manager.check_privilege_change(event.pid):
                # Deny the operation
                event.return_value = -1  # EPERM
                event.error = "Operation not permitted"
                
                # Log the violation
                self._log_violation(
                    event,
                    'privilege_escalation_attempt',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to change privileges",
                    'critical'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_privilege_ops: {e}", exc_info=True)
    
    def _log_violation(
        self, 
        event: SyscallEvent, 
        violation_type: str, 
        message: str, 
        severity: str
    ) -> None:
        """Log a security violation."""
        violation = {
            'timestamp': event.timestamp,
            'type': violation_type,
            'severity': severity,
            'process_id': event.pid,
            'process_name': event.process_name,
            'syscall': event.syscall,
            'message': message,
            'arguments': event.arguments,
            'return_value': event.return_value,
            'error': event.error
        }
        
        self.event_logger.log('syscall_violation', violation)
        
        # Take action based on severity
        if severity in ['high', 'critical']:
            self.response_engine.handle_violation(violation)
    
    # Windows-specific handlers
    
    def _handle_win32_createfile(self, event: SyscallEvent) -> None:
        """Handle Windows CreateFileW API calls."""
        try:
            filename = event.arguments.get('lpFileName', '')
            if not filename:
                return
                
            # Check if the file is in a protected directory
            protected_dirs = self.policy_manager.get_protected_paths()
            if any(filename.lower().startswith(d.lower()) for d in protected_dirs):
                # Check access rights
                desired_access = event.arguments.get('dwDesiredAccess', 0)
                access_type = 'write' if (desired_access & 0x40000000) else 'read'  # GENERIC_WRITE
                
                if not self.policy_manager.check_file_access(event.pid, filename, access_type):
                    # Deny access
                    event.return_value = None  # INVALID_HANDLE_VALUE
                    event.error = "Access denied"
                    
                    # Log the violation
                    self._log_violation(
                        event,
                        'unauthorized_file_access',
                        f"Process {event.process_name} (PID: {event.pid}) attempted to access protected file: {filename}",
                        'high'
                    )
        
        except Exception as e:
            logger.error(f"Error in _handle_win32_createfile: {e}", exc_info=True)
    
    def _handle_win32_createprocess(self, event: SyscallEvent) -> None:
        """Handle Windows CreateProcessW API calls."""
        try:
            application_name = event.arguments.get('lpApplicationName', '')
            command_line = event.arguments.get('lpCommandLine', '')
            
            # Check if process creation is allowed
            if not self.policy_manager.check_process_creation(event.pid):
                # Deny process creation
                event.return_value = False
                event.error = "Process creation not permitted"
                
                # Log the violation
                self._log_violation(
                    event,
                    'unauthorized_process_creation',
                    f"Process {event.process_name} (PID: {event.pid}) attempted to create a new process: {application_name or command_line}",
                    'high'
                )
        
        except Exception as e:
            logger.error(f"Error in _handle_win32_createprocess: {e}", exc_info=True)
    
    def _handle_win32_writeprocmem(self, event: SyscallEvent) -> None:
        """Handle Windows WriteProcessMemory API calls."""
        try:
            process_handle = event.arguments.get('hProcess')
            base_address = event.arguments.get('lpBaseAddress')
            buffer = event.arguments.get('lpBuffer')
            size = event.arguments.get('nSize', 0)
            
            # Check for potential code injection
            if size > 4096:  # Arbitrary size threshold
                # Calculate entropy of the buffer
                entropy = calculate_entropy(buffer)
                if entropy > 7.0:  # High entropy may indicate shellcode
                    # Deny the write
                    event.return_value = False
                    event.error = "Suspicious memory write blocked"
                    
                    # Log the violation
                    self._log_violation(
                        event,
                        'possible_code_injection',
                        f"Process {event.process_name} (PID: {event.pid}) attempted to write high-entropy data to process memory (possible shellcode)",
                        'critical'
                    )
        
        except Exception as e:
            logger.error(f"Error in _handle_win32_writeprocmem: {e}", exc_info=True)
    
    # Add more Windows API handlers as needed...
    
    # Utility methods
    
    def get_monitored_syscalls(self) -> List[str]:
        """Get a list of currently monitored system calls."""
        return list(self._syscall_handlers.keys())
    
    def add_monitored_syscall(self, syscall: str) -> None:
        """Add a system call to monitor."""
        if syscall not in self.monitor_syscalls:
            self.monitor_syscalls.add(syscall)
    
    def remove_monitored_syscall(self, syscall: str) -> None:
        """Remove a system call from monitoring."""
        if syscall in self.monitor_syscalls:
            self.monitor_syscalls.remove(syscall)
    
    def get_violations(self, limit: int = 100) -> List[Dict]:
        """Get recent security violations."""
        return self.event_logger.get_events('syscall_violation', limit=limit)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            'enabled': self.enabled,
            'monitored_syscalls': len(self.monitor_syscalls),
            'active_handlers': len(self._syscall_handlers),
            'platform': self.platform,
            'violations_count': len(self.get_violations(1000))  # Last 1000 violations
        }
