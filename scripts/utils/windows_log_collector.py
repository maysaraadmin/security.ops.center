import random
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Set, Tuple, Any, Callable
from .event import EventModel
import pythoncom
import win32evtlog
import win32con
import win32security
import win32api
import win32net
import win32netcon
import pywintypes
import os
import re
import sys
import traceback
import queue

# Configure logger
logger = logging.getLogger('siem.winlog')

class WindowsLogCollector:
    """
    Windows Event Log Collector for the SIEM system.
    
    Handles collection of Windows event logs with proper error handling,
    thread safety, and permission management.
    """
    
    def __init__(self, event_model: EventModel):
        """
        Initialize Windows Log Collector.
        
        Args:
            event_model: Instance of EventModel for storing collected events
        """
        self.event_model = event_model
        self.running = False
        self.threads: List[threading.Thread] = []
        self.log_handles: Dict[str, object] = {}
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._thread_errors: queue.Queue[Tuple[str, Exception]] = queue.Queue()
        
        # Define all Windows log sources we want to monitor with their priorities
        # Format: (log_name, collector_function, is_critical, required_privileges)
        self.log_sources = [
            ('Security', self._collect_security_events, True, ['SeSecurityPrivilege']),
            ('System', self._collect_system_events, True, []),
            ('Application', self._collect_application_events, True, []),
            ('Microsoft-Windows-PowerShell/Operational', self._collect_powershell_events, False, []),
            ('Microsoft-Windows-TaskScheduler/Operational', self._collect_task_scheduler_events, False, []),
            ('Microsoft-Windows-Sysmon/Operational', self._collect_sysmon_events, True, []),
            ('Microsoft-Windows-Windows Defender/Operational', self._collect_defender_events, True, []),
            ('Microsoft-Windows-GroupPolicy/Operational', self._collect_gpo_events, False, [])
        ]
        
        # Add domain controller specific logs if applicable
        self._add_domain_controller_logs()
        
        # Track which logs we have permission to access
        self.accessible_logs: Set[str] = set()
        self._check_log_access()
    
    def _add_domain_controller_logs(self) -> None:
        """Add domain controller specific logs if running on a DC."""
        try:
            if self._is_domain_controller():
                self.log_sources.extend([
                    ('Directory Service', self._collect_directory_service_events, True, ['SeSecurityPrivilege']),
                    ('DNS Server', self._collect_dns_events, True, ['SeSecurityPrivilege'])
                ])
        except Exception as e:
            logger.warning(f"Error checking domain controller status: {e}")
    
    def _check_log_access(self) -> None:
        """
        Check which event logs are accessible with current permissions.
        
        This method attempts to open each log to check for access permissions
        and provides detailed guidance for resolving common permission issues.
        """
        # First, check if we can get a process token (requires admin rights)
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_QUERY | win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY_SOURCE
            )
            token.Close()
        except Exception as e:
            if hasattr(e, 'winerror') and e.winerror == 5:  # Access Denied
                logger.warning(
                    "Could not open process token. The application needs to be run as Administrator "
                    "to access some logs like the Security log."
                )
            else:
                logger.warning(f"Error checking process token: {e}")
        
        for log_name, _, is_critical, required_privs in self.log_sources:
            handle = None
            try:
                # Special handling for Security log
                if log_name.lower() == 'security':
                    try:
                        # Try to enable the required privilege
                        if not self._has_required_privileges(required_privs):
                            logger.warning(
                                f"Skipping {log_name} log - missing required privileges: "
                                f"{', '.join(required_privs)}. Running as administrator is required."
                            )
                            self._log_security_privilege_help()
                            continue
                    except Exception as priv_e:
                        logger.error(f"Error checking privileges for {log_name}: {priv_e}")
                        continue
                
                # For non-Security logs, just check if we have the required privileges
                elif required_privs and not self._has_required_privileges(required_privs):
                    logger.warning(
                        f"Skipping {log_name} log - missing required privileges: "
                        f"{', '.join(required_privs)}. Running as administrator may be required."
                    )
                    continue
                
                # Try to open and close the log to check access
                try:
                    handle = win32evtlog.OpenEventLog(None, log_name)
                    if handle:
                        self.accessible_logs.add(log_name)
                        logger.info(f"Successfully accessed log: {log_name}")
                        
                        # If this is the Security log and we got here, log a success message
                        if log_name.lower() == 'security':
                            logger.info("Successfully obtained required privileges for Security log access")
                            
                except pywintypes.error as e:
                    # Re-raise to be handled by the outer exception handler
                    if log_name.lower() == 'security' and e.winerror == 5:  # Access Denied
                        self._log_security_privilege_help()
                    raise
                except Exception as e:
                    logger.error(f"Unexpected error accessing log {log_name}: {e}", exc_info=True)
                    continue
                
            except pywintypes.error as e:
                # Clean up the handle if it exists
                if handle:
                    try:
                        win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass  # Ignore errors during cleanup
                
                # Get the error message
                error_msg = str(e).lower()
                
                # Common error codes and their meanings
                error_messages = {
                    5: "Access is denied. The application needs to be run as Administrator.",
                    2: f"The log '{log_name}' was not found. Make sure the log exists and the name is correct.",
                    1500: "The Event Log service is not running. Please start the Windows Event Log service.",
                    13: "Data error. The log may be corrupted or inaccessible.",
                    1816: "The specified log is not available on this system.",
                    6: "The handle is invalid. This is an internal error.",
                    87: "The parameter is incorrect. The log name may be invalid.",
                    1722: "The RPC server is unavailable. The Event Log service may not be running.",
                    1314: "A required privilege is not held by the client. Run as Administrator."
                }
                
                # Get the friendly error message or use the default
                friendly_msg = error_messages.get(e.winerror, str(e))
                
                # Log the error with appropriate severity
                if is_critical:
                    logger.error(
                        f"CRITICAL: Cannot access {log_name} log - {friendly_msg} "
                        f"(Error {e.winerror}: {e.strerror})"
                    )
                    
                    # Special handling for Security log access
                    if log_name.lower() == 'security':
                        logger.error(
                            "The Security log requires Administrator privileges. "
                            "Please run the application as Administrator to collect Security events."
                        )
                    # Special handling for Sysmon log access
                    elif 'sysmon' in log_name.lower():
                        logger.error(
                            "Sysmon log access requires Administrator privileges. "
                            "Please ensure Sysmon is installed and running, and that the application "
                            "is running with Administrator privileges."
                        )
                else:
                    logger.warning(f"Cannot access {log_name} log - {friendly_msg}")
                
                # Add troubleshooting guidance for common issues
                if e.winerror == 5:  # Access Denied
                    logger.info("Troubleshooting steps:")
                    logger.info("  1. Close the application")
                    logger.info("  2. Right-click the application and select 'Run as administrator'")
                    logger.info("  3. If using a service account, ensure it has the 'Manage auditing and security log' right")
            
            except Exception as e:
                logger.error(f"Unexpected error checking access to {log_name} log: {e}", exc_info=True)
    
    def _has_required_privileges(self, privileges: List[str]) -> bool:
        """Check if the current process has the required privileges."""
        if not privileges:
            return True
            
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_QUERY | win32security.TOKEN_ADJUST_PRIVILEGES
            )
            
            try:
                privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                current_privs = {}
                
                for priv_luid, priv_attrs in privs:
                    try:
                        priv_name = win32security.LookupPrivilegeName(None, priv_luid)
                        current_privs[priv_name] = bool(priv_attrs & win32security.SE_PRIVILEGE_ENABLED)
                    except Exception as e:
                        logger.warning(f"Error looking up privilege: {e}")
                        continue
                
                for priv in privileges:
                    if priv not in current_privs or not current_privs[priv]:
                        if not self._enable_privilege(token, priv):
                            logger.warning(f"Missing or failed to enable privilege: {priv}")
                            return False
                return True
                
            finally:
                win32api.CloseHandle(token)
                
        except Exception as e:
            logger.error(f"Error checking privileges: {e}", exc_info=True)
            return False
            
    def _log_security_privilege_help(self) -> None:
        """Log detailed help for Security log access issues."""
        logger.warning("""
        ===== SECURITY LOG ACCESS INSTRUCTIONS =====
        To access the Security log, the application needs the 'Manage auditing and security log' 
        privilege (SeSecurityPrivilege). Here's how to fix this:
        
        1. Run the application as Administrator (easiest solution):
           - Close the application
           - Right-click on the application and select 'Run as administrator'
           - If using a shortcut, right-click and select 'Run as administrator'
           
        2. If running as a service, ensure the service account has the required privilege:
           a. Open 'Local Security Policy' (secpol.msc)
           b. Navigate to: Security Settings > Local Policies > User Rights Assignment
           c. Find 'Manage auditing and security log' (SeSecurityPrivilege)
           d. Add the service account or group
           e. Restart the application/service
        
        Note: After making changes, you may need to log off and log back on for the changes to take effect.
        ==========================================
        """)

    def _enable_privilege(self, token, privilege_name: str) -> bool:
        """Enable a specific privilege for the given token.
        
        Args:
            token: The access token handle
            privilege_name: Name of the privilege to enable (e.g., 'SeSecurityPrivilege')
            
        Returns:
            bool: True if the privilege was successfully enabled, False otherwise
        """
        try:
            # Get the LUID for the privilege
            luid = win32security.LookupPrivilegeValue(None, privilege_name)
            
            # Enable the privilege
            win32security.AdjustTokenPrivileges(
                token,
                False,
                [(luid, win32security.SE_PRIVILEGE_ENABLED)]
            )
            
            # Verify the privilege was enabled
            privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
            for priv_luid, priv_attrs in privs:
                if priv_luid == luid:
                    return bool(priv_attrs & win32security.SE_PRIVILEGE_ENABLED)
            return False
            
        except Exception as e:
            logger.error(f"Failed to enable privilege {privilege_name}: {e}")
            return False

    def _check_privileges(self, privileges: List[str]) -> bool:
        """Check and enable the specified privileges.
        
        Args:
            privileges: List of privilege names to check/enable
            
        Returns:
            bool: True if all privileges are available and enabled, False otherwise
        """
        try:
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_QUERY | win32security.TOKEN_ADJUST_PRIVILEGES
            )
            
            try:
                # Get current privileges
                privs = win32security.GetTokenInformation(token, win32security.TokenPrivileges)
                
                # Convert to a more usable format: {privilege_name: (enabled, luid)}
                current_privs = {}
                for priv_luid, priv_attrs in privs:
                    try:
                        priv_name = win32security.LookupPrivilegeName(None, priv_luid)
                        enabled = bool(priv_attrs & win32security.SE_PRIVILEGE_ENABLED)
                        current_privs[priv_name] = (enabled, priv_luid)
                    except Exception as e:
                        logger.warning(f"Error processing privilege: {e}")
                        continue
                
                # Check and enable each required privilege
                all_ok = True
                for priv in privileges:
                    try:
                        # Check if privilege exists in the token
                        if priv not in current_privs:
                            logger.warning(f"Privilege {priv} is not assigned to the current user/process")
                            all_ok = False
                            continue
                        
                        # Enable the privilege if not already enabled
                        enabled, luid = current_privs[priv]
                        if not enabled:
                            logger.info(f"Attempting to enable privilege: {priv}")
                            if not self._enable_privilege(token, priv):
                                logger.warning(f"Failed to enable privilege: {priv}")
                                all_ok = False
                            else:
                                logger.info(f"Successfully enabled privilege: {priv}")
                    
                    except Exception as e:
                        logger.error(f"Error processing privilege {priv}: {e}", exc_info=True)
                        all_ok = False
                
                # If any privilege check failed, provide guidance
                if not all_ok:
                    logger.warning("\nPrivilege troubleshooting:")
                    logger.warning("1. Run the application as Administrator")
                    logger.warning("2. Or grant the required privileges via Group Policy:")
                    logger.warning("   - Open 'gpedit.msc' (Local Group Policy Editor)")
                    logger.warning("   - Navigate to: Computer Configuration > Windows Settings > "
                                "Security Settings > Local Policies > User Rights Assignment")
                    logger.warning("   - Find the required privilege (e.g., 'Manage auditing and security log' for SeSecurityPrivilege)")
                    logger.warning("   - Add the user or group that runs this application")
                    logger.warning("3. After making changes, log off and log back in for them to take effect\n")
                
                return all_ok
                
            except pywintypes.error as e:
                logger.error(f"Failed to get token information: {e}")
                return False
                
            finally:
                if 'token' in locals() and token:
                    try:
                        win32api.CloseHandle(token)
                    except Exception as e:
                        logger.warning(f"Error closing token handle: {e}")
                
        except Exception as e:
            logger.error(f"Error in privilege check: {e}", exc_info=True)
            return False

    def start(self) -> bool:
        """
        Start all Windows log collection threads.
        
        Returns:
            bool: True if all critical collectors started successfully, False otherwise
        """
        if self.running:
            logger.warning("Log collector is already running")
            return False
            
        self.running = True
        self._stop_event.clear()
        started_count = 0
        critical_failures = 0
        
        logger.info("Starting Windows log collectors...")
        
        # Start event log collectors with error handling and retries
        for log_name, collector, is_critical, required_privs in self.log_sources:
            # Skip logs we know we can't access
            if log_name not in self.accessible_logs:
                logger.warning(f"Skipping inaccessible log: {log_name}")
                if is_critical:
                    critical_failures += 1
                continue
                
            # Check for required privileges
            if not self._has_required_privileges(required_privs):
                logger.error(
                    f"Insufficient privileges for log: {log_name}. "
                    f"Required privileges: {', '.join(required_privs) or 'None'}"
                )
                if is_critical:
                    critical_failures += 1
                continue
                
            max_retries = 3 if is_critical else 1
            last_error = None
            
            for attempt in range(max_retries):
                try:
                    # Try to open the event log
                    hand = win32evtlog.OpenEventLog(None, log_name)
                    with self._lock:
                        self.log_handles[log_name] = hand
                    
                    # Create and start the collector thread
                    thread = threading.Thread(
                        target=self._safe_collector_wrapper,
                        args=(collector, hand, log_name),
                        daemon=True,
                        name=f"WinLog-{log_name[:10]}"
                    )
                    thread.start()
                    self.threads.append(thread)
                    started_count += 1
                    logger.info(f"Started {log_name} collector")
                    break  # Success, exit retry loop
                    
                except Exception as e:
                    last_error = e
                    error_msg = (
                        f"Failed to start {log_name} collector "
                        f"(attempt {attempt + 1}/{max_retries}): {str(e)}"
                    )
                    logger.error(error_msg)
                    
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)  # Exponential backoff
                    
            else:  # No break, all retries failed
                if is_critical:
                    critical_failures += 1
                    logger.error(
                        f"CRITICAL: Failed to start required log source: {log_name}. "
                        f"Last error: {last_error}"
                    )
        
        # Start additional collectors (like firewall)
        self._start_additional_collectors()
        
        # Check if we have any critical failures
        if critical_failures > 0:
            logger.error(
                f"Failed to start {critical_failures} critical log sources. "
                "Some functionality may be limited."
            )
            # We'll still return True if we started at least one collector
            return started_count > 0
            
        logger.info(f"Started {started_count} log collectors successfully")
        return started_count > 0
        
    def _start_additional_collectors(self) -> None:
        """Start any additional log collectors (like firewall, etc.)"""
        try:
            # Start firewall log collector
            firewall_thread = threading.Thread(
                target=self._collect_firewall_logs,
                daemon=True,
                name="WinLog-Firewall"
            )
            firewall_thread.start()
            self.threads.append(firewall_thread)
            logger.info("Started Firewall log collector")
            
            # Add other additional collectors here
            # Example:
            # self._start_custom_collector()
            
        except Exception as e:
            logger.error(f"Failed to start additional collectors: {e}", exc_info=True)
    
    def _reconnect_log_handle(self, log_name: str) -> None:
        """
        Attempt to reconnect to a log that was disconnected.
        
        Args:
            log_name: Name of the log to reconnect to
        """
        with self._lock:
            try:
                # Close the old handle if it exists
                old_handle = self.log_handles.get(log_name)
                if old_handle is not None:
                    try:
                        win32evtlog.CloseEventLog(old_handle)
                    except Exception:
                        pass
                
                # Open a new handle
                new_handle = win32evtlog.OpenEventLog(None, log_name)
                self.log_handles[log_name] = new_handle
                logger.info(f"Successfully reconnected to {log_name} log")
                
            except Exception as e:
                logger.error(f"Failed to reconnect to {log_name} log: {e}")
                # Remove the handle from our dictionary if we couldn't reconnect
                self.log_handles.pop(log_name, None)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the log collector.
        
        Returns:
            dict: Status information including running state and active collectors
        """
        with self._lock:
            return {
                'running': self.running,
                'active_collectors': [
                    {
                        'name': t.name,
                        'alive': t.is_alive(),
                        'daemon': t.daemon,
                        'ident': t.ident
                    }
                    for t in self.threads
                ],
                'log_handles': list(self.log_handles.keys()),
                'accessible_logs': list(self.accessible_logs)
            }
    
    def _safe_collector_wrapper(self, collector: Callable, hand: Any, log_name: str) -> None:
        """
        Wrapper function to safely run collector functions with error handling.
        
        Args:
            collector: The collector function to run
            hand: Handle to the event log
            log_name: Name of the event log
        """
        thread_name = threading.current_thread().name
        logger.info(f"Starting collector thread: {thread_name} for {log_name}")
        
        try:
            # Initialize COM for this thread if needed
            pythoncom.CoInitialize()
            
            # Run the collector
            collector(hand)
            
        except Exception as e:
            error_msg = f"Error in {log_name} collector: {e}"
            logger.error(error_msg, exc_info=True)
            
            # Store the error for the main thread to handle
            self._thread_errors.put((log_name, e))
            
            # Re-raise to allow thread to die if it's a critical error
            raise
            
        finally:
            # Clean up COM
            pythoncom.CoUninitialize()
            
            # Close the log handle if it's still open
            if hand is not None:
                try:
                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.warning(f"Error closing log handle for {log_name}: {e}")
            
            logger.info(f"Collector thread {thread_name} for {log_name} stopped")
    
    def stop(self, timeout: float = 10.0) -> None:
        """
        Stop all log collection threads and clean up resources.
        
        Args:
            timeout: Maximum time to wait for threads to stop (in seconds)
        """
        if not self.running:
            return
            
        logger.info("Stopping Windows log collectors...")
        self.running = False
        self._stop_event.set()
        
        # Close all log handles
        with self._lock:
            for log_name, hand in list(self.log_handles.items()):
                try:
                    if hand is not None:
                        win32evtlog.CloseEventLog(hand)
                        logger.debug(f"Closed log handle for {log_name}")
                except Exception as e:
                    logger.error(f"Error closing {log_name} handle: {e}", exc_info=True)
                finally:
                    self.log_handles.pop(log_name, None)
        
        # Wait for threads to finish
        end_time = time.time() + timeout
        for thread in list(self.threads):
            try:
                time_left = max(0.0, end_time - time.time())
                if time_left <= 0:
                    logger.warning("Timeout waiting for threads to stop")
                    break
                    
                thread.join(timeout=min(1.0, time_left))
                if thread.is_alive():
                    logger.warning(f"Thread {thread.name} did not stop gracefully")
                else:
                    logger.debug(f"Thread {thread.name} stopped")
                    
            except Exception as e:
                logger.error(f"Error stopping thread {thread.name}: {e}", exc_info=True)
        
        # Clear the thread list
        self.threads.clear()
        
        # Log any errors from the threads
        self._log_thread_errors()
        
        logger.info("All log collectors stopped")
    
    def _log_thread_errors(self) -> None:
        """Log any errors that occurred in collector threads."""
        errors = []
        while True:
            try:
                log_name, error = self._thread_errors.get_nowait()
                errors.append(f"{log_name}: {str(error)}")
            except queue.Empty:
                break
                
        if errors:
            logger.error("The following errors occurred in collector threads:\n  " + 
                        "\n  ".join(errors))
    
    def _get_application_event_map(self) -> Dict[int, Tuple[str, int]]:
        """
        Get a mapping of Application log event IDs to (name, severity) tuples.
        
        Returns:
            Dict[int, Tuple[str, int]]: Mapping of event IDs to (name, severity)
        """
        return {
            # Application Error Events
            1000: ("Application Error", 3),  # High severity for application crashes
            1001: ("Windows Error Reporting", 2),
            
            # .NET Runtime Events
            1023: (".NET Runtime Error", 3),
            1026: (".NET Runtime Error", 3),
            1025: (".NET Runtime Warning", 2),
            
            # Windows Installer Events
            1001: ("Windows Installer", 2),
            1004: ("Windows Installer", 2),
            1013: ("Windows Installer", 2),
            1014: ("Windows Installer", 2),
            
            # Application Hang Events
            1002: ("Application Hang", 3),
            1005: ("Application Hang", 3),
            
            # Windows Error Reporting Events
            1010: ("Windows Error Reporting", 2),
            1011: ("Windows Error Reporting", 2),
            
            # Default mapping for unhandled event IDs
            # Format: event_id: ("Event Name", severity)
            # Severity: 1=Low, 2=Medium, 3=High, 4=Critical
        }

    def _is_domain_controller(self) -> bool:
        """
        Check if the current system is a domain controller.
        
        Returns:
            bool: True if the system is a domain controller, False otherwise
        """
        try:
            # Get server information at level 101 which includes server type
            server_info = win32net.NetServerGetInfo(None, 101)
            
            # Check if the server is a domain controller
            if not server_info or 'server_type' not in server_info:
                logger.warning("Could not determine server type: 'server_type' not in server info")
                return False
                
            is_dc = (server_info['server_type'] & win32netcon.SV_TYPE_DOMAIN_CTRL) != 0
            logger.debug(f"Domain Controller check: {is_dc}")
            return is_dc
            
        except pywintypes.error as e:
            # Handle specific Windows API errors
            if e.winerror == 5:  # ERROR_ACCESS_DENIED
                logger.warning("Access denied when checking domain controller status. Running with elevated privileges may be required.")
            else:
                logger.warning(f"Windows API error checking domain controller status: {e}")
            return False
            
        except Exception as e:
            logger.warning(f"Error checking domain controller status: {e}")
            return False

    # Individual log collectors for each source
    def _collect_gpo_events(self, hand: Any) -> None:
        """
        Collect Group Policy operational events.
        
        Args:
            hand: Handle to the Group Policy operational log
        """
        logger.info("Starting Group Policy operational log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'GroupPolicy/Operational'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for Group Policy events
                            event_map = self._get_gpo_event_map()
                            formatter = self._format_gpo_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing Group Policy event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Group Policy event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Group Policy event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Group Policy event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Group Policy event collector stopped")

    def _collect_defender_events(self, hand: Any) -> None:
        """
        Collect Windows Defender operational events.
        
        Args:
            hand: Handle to the Windows Defender operational log
        """
        logger.info("Starting Windows Defender operational log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'Windows Defender/Operational'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for Windows Defender events
                            event_map = self._get_defender_event_map()
                            formatter = self._format_defender_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing Windows Defender event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Windows Defender event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Windows Defender event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Windows Defender event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Windows Defender event collector stopped")

    def _collect_sysmon_events(self, hand: Any) -> None:
        """
        Collect Sysmon operational events.
        
        Args:
            hand: Handle to the Sysmon operational log
        """
        logger.info("Starting Sysmon operational log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'Sysmon/Operational'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for Sysmon events
                            event_map = self._get_sysmon_event_map()
                            formatter = self._format_sysmon_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing Sysmon event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Sysmon event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Sysmon event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Sysmon event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Sysmon event collector stopped")

    def _collect_task_scheduler_events(self, hand: Any) -> None:
        """
        Collect Task Scheduler operational events.
        
        Args:
            hand: Handle to the Task Scheduler operational log
        """
        logger.info("Starting Task Scheduler operational log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'TaskScheduler/Operational'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for Task Scheduler events
                            event_map = self._get_task_scheduler_event_map()
                            formatter = self._format_task_scheduler_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing Task Scheduler event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Task Scheduler event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Task Scheduler event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Task Scheduler event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Task Scheduler event collector stopped")

    def _collect_powershell_events(self, hand: Any) -> None:
        """
        Collect PowerShell operational events.
        
        Args:
            hand: Handle to the PowerShell operational log
        """
        logger.info("Starting PowerShell operational log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'PowerShell/Operational'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for PowerShell events
                            event_map = self._get_powershell_event_map()
                            formatter = self._format_powershell_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing PowerShell event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in PowerShell event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in PowerShell event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in PowerShell event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("PowerShell event collector stopped")

    def _collect_application_events(self, hand: Any) -> None:
        """
        Collect application events from the Windows Application log.
        
        Args:
            hand: Handle to the Application event log
        """
        logger.info("Starting Application event log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'Application'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for application events
                            event_map = self._get_application_event_map()
                            formatter = self._format_application_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing application event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Application event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Application event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Application event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Application event collector stopped")

    def _collect_system_events(self, hand: Any) -> None:
        """
        Collect system events from Windows System log.
        
        Args:
            hand: Handle to the event log
        """
        self._collect_standard_events(hand, 'System')
        
    def _collect_application_events(self, hand: Any) -> None:
        """
        Collect application events from Windows Application log.
        
        Args:
            hand: Handle to the event log
        """
        self._collect_standard_events(hand, 'Application')
        
    def _collect_powershell_events(self, hand: Any) -> None:
        """
        Collect PowerShell operational events.
        
        Args:
            hand: Handle to the event log
        """
        self._collect_standard_events(hand, 'Microsoft-Windows-PowerShell/Operational')
        
    def _collect_defender_events(self, hand: Any) -> None:
        """
        Collect Windows Defender events.
        
        Args:
            hand: Handle to the event log
        """
        self._collect_standard_events(hand, 'Microsoft-Windows-Windows Defender/Operational')
        
    def _collect_gpo_events(self, hand: Any) -> None:
        """
        Collect Group Policy operational events.
        
        Args:
            hand: Handle to the event log
        """
        self._collect_standard_events(hand, 'Microsoft-Windows-GroupPolicy/Operational')
        
    def _parse_event(self, event: Any) -> Optional[Dict[str, Any]]:
        """
        Parse a Windows event log record into a standardized format.
        
        Args:
            event: Windows event log record from pywin32
            
        Returns:
            Dictionary containing parsed event data or None if event should be skipped
        """
        try:
            # Skip if event is None or invalid
            if not event or not hasattr(event, 'TimeGenerated'):
                return None
                
            # Get event severity and type
            event_type = getattr(event, 'EventType', 0)
            event_id = getattr(event, 'EventID', 0) & 0xFFFF  # Lower 16 bits are the actual event ID
            
            # Format the timestamp
            timestamp = event.TimeGenerated
            if hasattr(timestamp, 'strftime'):
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            # Basic event data
            event_data = {
                'timestamp': timestamp_str,
                'event_id': event_id,
                'source': 'Windows',
                'computer': getattr(event, 'ComputerName', None),
                'severity': self._get_severity(event_type),
                'event_type': self._get_event_type(event_id, event_type),
                'description': self._format_event_description(event),
                'raw_data': None,
                'metadata': {}
            }
            
            # Add user information if available
            if hasattr(event, 'UserSid'):
                try:
                    sid = event.UserSid
                    if sid:
                        if hasattr(sid, 'Format'):
                            event_data['user'] = sid.Format(win32security.SidTypeUser, 0)
                except Exception as e:
                    logger.debug(f"Could not resolve user SID: {e}")
            
            # Add string inserts if present
            if hasattr(event, 'StringInserts') and event.StringInserts:
                event_data['metadata']['strings'] = [str(s) for s in event.StringInserts if s is not None]
                
                # Try to extract IP address from string inserts
                ip = self._extract_ip_from_event(event)
                if ip:
                    event_data['ip_address'] = ip
            
            # Add binary data if present
            if hasattr(event, 'Data') and event.Data:
                try:
                    if hasattr(event.Data, 'tobytes'):
                        event_data['raw_data'] = event.Data.tobytes().hex()
                    else:
                        event_data['raw_data'] = event.Data.hex()
                except Exception as e:
                    logger.debug(f"Could not process binary data: {e}")
            
            # Add event record ID and category if available
            if hasattr(event, 'RecordNumber'):
                event_data['metadata']['record_id'] = event.RecordNumber
            if hasattr(event, 'EventCategory'):
                event_data['category'] = str(event.EventCategory)
            
            return event_data
            
        except Exception as e:
            logger.error(f"Error parsing event: {e}", exc_info=True)
            return None
    
    def _get_event_type(self, event_id: int, event_type: int) -> str:
        """Map Windows event ID and type to a human-readable event type."""
        # Common Windows security events
        if event_id in [4624, 4625]:  # Logon events
            return 'authentication'
        elif event_id in [4634, 4647]:  # Logoff events
            return 'logoff'
        elif event_id in [4663, 4660]:  # File system events
            return 'file_system'
        elif event_id in [4688, 4689]:  # Process events
            return 'process'
        elif event_id in [4720, 4722, 4725, 4726]:  # Account management
            return 'account_management'
        elif event_id in [4738, 4739]:  # User account changes
            return 'user_change'
        elif event_id in [4776, 4778, 4779]:  # Authentication events
            return 'authentication'
        
        # Map Windows event types to general categories
        event_type_map = {
            1: 'error',
            2: 'warning',
            3: 'information',
            4: 'audit_success',
            5: 'audit_failure'
        }
        
        return event_type_map.get(event_type, 'unknown')
    
    def _get_severity(self, event_type: int) -> int:
        """Map Windows event type to severity level (1-5)."""
        severity_map = {
            1: 4,  # Error - High severity
            2: 3,  # Warning - Medium severity
            3: 1,  # Information - Low severity
            4: 2,  # Audit Success - Medium-Low severity
            5: 4   # Audit Failure - High severity
        }
        return severity_map.get(event_type, 3)  # Default to medium
    
    def _format_event_description(self, event: Any) -> str:
        """Format the event description with available data.
        
        Args:
            event: Windows event log record from pywin32 or win32evtlog
            
        Returns:
            Formatted event description string
        """
        try:
            # Get event ID safely
            event_id = getattr(event, 'EventID', 0) & 0xFFFF
            
            # Handle case where we have string inserts
            if hasattr(event, 'StringInserts') and event.StringInserts:
                try:
                    # Format string inserts, handling None values and non-string objects
                    parts = []
                    for item in event.StringInserts:
                        if item is None:
                            continue
                        if not isinstance(item, str):
                            item = str(item)
                        item = item.strip()
                        if item:  # Only add non-empty strings
                            parts.append(item)
                    
                    if parts:
                        return ' | '.join(parts)
                except Exception as e:
                    logger.debug(f"Error formatting string inserts: {e}")
            
            # Fall back to event ID if we can't get a better description
            return f"Event ID: {event_id}"
            
        except Exception as e:
            logger.warning(f"Error in _format_event_description: {e}")
            return "Event description not available"
    
    def _collect_standard_events(self, hand: Any, log_name: str) -> None:
        """
        Generic method to collect events from standard Windows logs.
        
        Args:
            hand: Handle to the event log
            log_name: Name of the log for identification
        """
        logger.info(f"Starting {log_name} event collector")
        error_count = 0
        last_error_time = 0
        processed_count = 0
        batch_start_time = time.time()
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in small batches
                    events = win32evtlog.ReadEventLog(
                        hand,
                        win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                        0,
                        100  # Limit number of events per read
                    )
                    
                    if not events:
                        # Log stats if we processed any events in this batch
                        if processed_count > 0:
                            batch_duration = time.time() - batch_start_time
                            logger.debug(
                                f"Processed {processed_count} {log_name} events in {batch_duration:.2f} seconds "
                                f"({processed_count/max(batch_duration, 0.1):.1f} events/sec)"
                            )
                            processed_count = 0
                            batch_start_time = time.time()
                        
                        time.sleep(1)  # Small delay if no events
                        continue
                    
                    processed_count += len(events)
                    
                    for event in events:
                        try:
                            event_data = self._parse_event(event)
                            if event_data:
                                event_data['source'] = log_name
                                self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            last_error_time = current_time
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing system event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in System event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in System event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in System event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("System event collector stopped")

    def _collect_task_scheduler_events(self, log_handle: object, log_name: str) -> None:
        """
        Collect events from the Task Scheduler operational log.
        
        Args:
            log_handle: Handle to the event log
            log_name: Name of the event log
        """
        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            
            for event in events:
                try:
                    event_data = {
                        'EventID': event.EventID,
                        'TimeGenerated': event.TimeGenerated,
                        'SourceName': event.SourceName,
                        'ComputerName': event.ComputerName,
                        'Strings': event.StringInserts or [],
                        'EventCategory': event.EventCategory,
                        'EventType': event.EventType,
                        'RecordNumber': event.RecordNumber,
                        'raw_data': str(event.StringInserts) if event.StringInserts else ''
                    }
                    
                    # Create event for the SIEM
                    self.event_model.queue_event({
                        'source': 'Windows Task Scheduler',
                        'event_type': f'TaskScheduler-{event.EventID}',
                        'description': f'Task Scheduler Event ID: {event.EventID}',
                        'severity': 3 if event.EventType in [win32evtlog.EVENTLOG_ERROR_TYPE, 
                                                          win32evtlog.EVENTLOG_AUDIT_FAILURE] else 2,
                        'timestamp': event.TimeGenerated,
                        'computer': event.ComputerName,
                        'category': 'TaskScheduler',
                        'metadata': {
                            'source_name': event.SourceName,
                            'record_number': event.RecordNumber,
                            'event_data': event_data
                        },
                        'raw_data': str(event_data)
                    })
                    
                except Exception as e:
                    logger.error(f"Error processing Task Scheduler event: {e}", exc_info=True)
                    continue
                    
        except Exception as e:
            logger.error(f"Error reading from Task Scheduler log: {e}", exc_info=True)
            raise

    def _collect_security_events(self, hand: Any) -> None:
        """
        Collect security events from the Windows Security log.
        
        Args:
            hand: Handle to the Security event log
        """
        logger.info("Starting Security event log collector")
        
        # Initialize variables for event reading
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        last_error_time = 0
        error_count = 0
        source = 'Security'  # Define source for this collector
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read events in batches
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    # If no events, sleep briefly and continue
                    if not events:
                        time.sleep(1.0)
                        continue
                    
                    # Process each event
                    for event in events:
                        if self._stop_event.is_set():
                            break
                            
                        try:
                            # Get event map and formatter for security events
                            event_map = self._get_security_event_map()
                            formatter = self._format_security_event
                            
                            # Get event ID and process it
                            event_id = getattr(event, 'EventID', 0)
                            if event_id in event_map:
                                name, severity = event_map[event_id]
                            else:
                                name = f"{source} Event ID {event_id}"
                                severity = 2  # Default medium severity
                            
                            message = formatter(event, name)
                            ip_address = self._extract_ip_from_event(event)
                            
                            # Safely get the timestamp
                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            if hasattr(event, 'TimeGenerated'):
                                try:
                                    timestamp = event.TimeGenerated.Format()
                                except:
                                    pass
                                    
                            event_data = {
                                'timestamp': timestamp,
                                'source': source,
                                'event_type': name,
                                'severity': severity,
                                'description': message,
                                'ip_address': ip_address or "N/A"
                            }
                            self.event_model.queue_event(event_data)
                            error_count = 0  # Reset error count on success
                            
                        except Exception as e:
                            error_count += 1
                            current_time = time.time()
                            
                            # Only log the error if it's been more than 60 seconds since the last error
                            # or if this is one of the first few errors
                            if error_count <= 3 or (current_time - last_error_time) > 60:
                                logger.error(
                                    f"Error processing security event: {e}",
                                    exc_info=error_count <= 3  # Only show traceback for first few errors
                                )
                                last_error_time = current_time
                            
                            # If we're seeing too many errors, take a break
                            if error_count > 10:
                                logger.error(
                                    f"Too many errors ({error_count}) in Security event processing. "
                                    "Pausing for 30 seconds..."
                                )
                                time.sleep(30)
                    
                    # Small delay between batches
                    time.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in Security event collector: {e}", exc_info=True)
                    time.sleep(10)  # Wait before retrying after an error
                    
        except Exception as e:
            logger.critical(f"Critical error in Security event collector: {e}", exc_info=True)
            raise  # Re-raise to be handled by the caller
        finally:
            logger.info("Security event collector stopped")

    # Event mapping methods
    def _get_security_event_map(self):
        return {
            # Logon/Logoff Events
            4624: ("Successful Logon", 2),
            4625: ("Failed Logon", 4),
            4634: ("Logoff", 2),
            4647: ("User-Initiated Logoff", 2),
            4648: ("Explicit Credential Used", 3),
            
            # Account Lockouts
            4740: ("User Account Locked Out", 4),
            
            # Account Management (4720-4738)
            4720: ("User Account Created", 4),
            4722: ("User Account Enabled", 3),
            4724: ("Attempt to Reset Password", 4),
            4725: ("User Account Disabled", 3),
            4726: ("User Account Deleted", 4),
            4728: ("User Added to Privileged Group", 4),
            4732: ("Member Added to Security-Enabled Global Group", 4),
            4735: ("Security-Enabled Local Group Changed", 4),
            4738: ("User Account Changed", 3),
            
            # Privilege Use
            4672: ("Special Privileges Assigned to New Logon", 4),
            4673: ("A privileged service was called", 4),
            4674: ("An operation was attempted on a privileged object", 4),
            
            # Audit Policy Changes
            4719: ("System Audit Policy was changed", 4),
            4902: ("Per-user audit policy table was created", 3),
            4907: ("Audit policy on an object was changed", 4),
            
            # System Integrity (cryptographic operations)
            5038: ("Code integrity determined that the image hash of a file is not valid", 4),
            5058: ("Key file operation", 3),
            5061: ("Cryptographic operation", 3),
            
            # Other Important Security Events
            4663: ("File Accessed", 3),
            4670: ("Permissions Changed on Object", 4),
            4688: ("New Process Created", 3),
            4698: ("Scheduled Task Created", 3),
            4702: ("Scheduled Task Updated", 3),
            4717: ("System security access was granted to an account", 4),
            4718: ("System audit policy was changed", 4),
            4727: ("A security-enabled global group was created", 4),
            4739: ("Domain Policy was changed", 4),
            4768: ("A Kerberos authentication ticket (TGT) was requested", 3),
            4769: ("A Kerberos service ticket was requested", 3),
            4776: ("The domain controller attempted to validate the credentials for an account", 3),
            4798: ("A user's local group membership was enumerated", 3),
            4964: ("Special groups have been assigned to a new logon", 3)
        }

    def _get_system_event_map(self):
        return {
            # System startup/shutdown events
            12: ("System Startup", 1),
            13: ("System Shutdown", 1),
            41: ("System Rebooted Without Clean Shutdown", 3),
            42: ("System Sleep", 1),
            1001: ("Windows Error Reporting", 2),
            1074: ("System Shutdown Initiated", 2),
            1076: ("System Shutdown with Reason", 2),
            1077: ("System Shutdown by User", 2),
            6005: ("Event Log Service Started", 1),
            6006: ("Event Log Service Stopped", 2),
            6008: ("System Crash", 4),
            
            # Service events
            7000: ("Service Failed to Start", 3),
            7001: ("Service Start Failed - Dependency Service Failed", 3),
            7002: ("Service Hanging", 3),
            7009: ("Service Start Failed - Timeout", 3),
            7011: ("Service Hung During Startup", 3),
            7022: ("Service Hung on Startup or Shutdown", 3),
            7023: ("Service Terminated with Service-Specific Error", 3),
            7024: ("Service Terminated with Specific Exit Code", 3),
            7030: ("Service Marked as Interactive", 3),
            7031: ("Service Crashed", 4),
            7032: ("Service Crashed During Shutdown", 3),
            7034: ("Service Crashed Unexpectedly", 4),
            7035: ("Service State Changed", 2),
            7036: ("Service State Changed (Detailed)", 2),
            
            # Time changes
            1: ("System Time Changed (Old Time)", 2),
            2: ("System Time Changed (New Time)", 2),
            144: ("System Time Changed (NTP Client)", 2),
            4616: ("System Time Changed (Audit Policy)", 3),
            
            # Disk/Storage events
            7: ("Disk Configuration Changed", 2),
            9: ("Disk Resource Exhausted", 3),
            50: ("File System Error", 3),
            51: ("Disk Error", 3),
            52: ("Disk Warning", 2),
            55: ("File System Error", 3),
            56: ("File System Warning", 2),
            57: ("File System Information", 1),
            
            # Network events
            1003: ("DHCP Service Started", 1),
            1004: ("DHCP Service Stopped", 2),
            1005: ("DHCP Service Paused", 2),
            1006: ("DHCP Service Continued", 1),
            1007: ("DHCP Service Terminated Unexpectedly", 3),
            1008: ("DHCP Service Network Disabled", 2),
            1009: ("DHCP Service Network Enabled", 1),
            1010: ("DHCP Service Network Disabled Due to Conflict", 3),
            
            # System health and performance
            2004: ("System Out of Virtual Memory", 4),
            2019: ("System Low on Resources", 3),
            2020: ("System Out of Paged Pool Memory", 4),
            2021: ("System Out of Nonpaged Pool Memory", 4),
            2022: ("System Out of Paged Pool Memory (Detailed)", 4),
            2023: ("System Out of Nonpaged Pool Memory (Detailed)", 4),
            
            # Other critical system events
            6000: ("Driver Loaded", 2),
            6001: ("Driver Unloaded", 2),
            6002: ("System Sleep", 1),
            6003: ("System Resumed from Sleep", 1),
            6004: ("System Entering Sleep", 1),
            6009: ("System Boot Type", 1),
            6013: ("System Uptime", 1),
            6016: ("System Time Synchronization", 1)
        }

    def _get_powershell_event_map(self):
        return {
            # Module and Provider Events
            400: ("PowerShell Provider Start", 2),
            403: ("PowerShell Provider Activity", 2),
            600: ("PowerShell Provider Lifecycle", 2),
            800: ("PowerShell Pipeline Execution Details", 2),
            
            # Command and Script Execution
            4100: ("PowerShell Command Start", 2),
            4101: ("PowerShell Command End", 2),
            4102: ("PowerShell Command Output", 2),
            4103: ("PowerShell Command Execution", 3),
            4104: ("PowerShell Script Block Execution", 4),
            4105: ("PowerShell Script Block Start", 2),
            4106: ("PowerShell Script Block End", 2),
            
            # Remote Sessions
            1040: ("PowerShell Remote Session Start", 3),
            1041: ("PowerShell Remote Session End", 2),
            1042: ("PowerShell Remote Session Failed", 3),
            1043: ("PowerShell Remote Session Disconnected", 2),
            1044: ("PowerShell Remote Session Reconnected", 2),
            
            # Script Execution and Analysis
            4107: ("PowerShell Script Block Logging", 3),
            4108: ("PowerShell Script Block Execution Warning", 3),
            4109: ("PowerShell Script Block Execution Error", 4),
            4110: ("PowerShell Script Block Execution Warning (Detailed)", 3),
            4111: ("PowerShell Script Block Execution Error (Detailed)", 4),
            
            # Module and Snapin Events
            8001: ("PowerShell Module Load", 2),
            8002: ("PowerShell Module Unload", 2),
            8003: ("PowerShell Snapin Load", 2),
            8004: ("PowerShell Snapin Unload", 2),
            
            # Security and Authentication
            53504: ("PowerShell Script Block Logging - Warning", 3),
            53505: ("PowerShell Script Block Logging - Information", 2),
            53506: ("PowerShell Script Block Logging - Error", 4),
            
            # Engine Events
            501: ("PowerShell Engine Lifecycle", 2),
            1000: ("PowerShell Engine Start", 1),
            1001: ("PowerShell Engine Stop", 1),
            1002: ("PowerShell Engine Restart", 2),
            
            # Host and Runspace Events
            40961: ("PowerShell Host Start", 1),
            40962: ("PowerShell Host Stop", 1),
            45056: ("PowerShell Runspace Open", 2),
            45057: ("PowerShell Runspace Close", 2),
            45058: ("PowerShell Runspace Debug", 3),
            
            # Pipeline and Command Events
            49152: ("PowerShell Pipeline Start", 2),
            49153: ("PowerShell Pipeline Stop", 2),
            53248: ("PowerShell Command Start (Detailed)", 2),
            53249: ("PowerShell Command Stop (Detailed)", 2)
        }

    def _get_task_scheduler_event_map(self):
        return {
            106: ("Scheduled Task Created", 3),
            140: ("Scheduled Task Updated", 3),
            141: ("Scheduled Task Deleted", 3),
            200: ("Scheduled Task Executed", 2)
        }

    def _get_sysmon_event_map(self):
        return {
            1: ("Process Create", 3),
            2: ("A process changed a file creation time", 4),
            3: ("Network Connection", 3),
            4: ("Sysmon service state changed", 2),
            5: ("Process terminated", 2),
            6: ("Driver loaded", 4),
            7: ("Image loaded", 3),
            8: ("CreateRemoteThread", 4),
            9: ("RawAccessRead detected", 4),
            10: ("Process accessed", 4),
            11: ("File created", 3),
            12: ("RegistryEvent (Object create and delete)", 3),
            13: ("RegistryEvent (Value Set)", 3),
            14: ("RegistryEvent (Key and Value Rename)", 3),
            15: ("FileCreateStreamHash", 3),
            16: ("Sysmon config state changed", 2),
            17: ("Pipe Created", 2),
            18: ("Pipe Connected", 2),
            19: ("WmiEvent (WmiEventFilter activity detected)", 4),
            20: ("WmiEvent (WmiEventConsumer activity detected)", 4),
            21: ("WmiEvent (WmiEventConsumerToFilter activity detected)", 4),
            22: ("DNS query", 2),
            23: ("File Delete", 3),
            24: ("Clipboard Capture", 3),
            25: ("Process Tampering", 5),
            26: ("File Delete Detected", 3)
        }

    def _get_defender_event_map(self):
        return {
            # Malware Detection and Remediation
            1006: ("Malware Detected (Early Launch Antimalware)", 5),
            1007: ("Malware Remediation Incomplete (Early Launch Antimalware)", 4),
            1008: ("Malware Remediation Failed (Early Launch Antimalware)", 5),
            1009: ("Malware Remediation Completed (Early Launch Antimalware)", 2),
            1010: ("Malware Action Taken (Early Launch Antimalware)", 3),
            1011: ("Malware Action Failed (Early Launch Antimalware)", 4),
            1012: ("Malware Action Not Taken (Early Launch Antimalware)", 3),
            
            # Real-time Protection
            1116: ("Malware Detected", 5),
            1117: ("Malware Remediated", 4),
            1118: ("Malware Allowed", 5),
            1119: ("Suspicious Behavior Detected", 4),
            1120: ("Suspicious Behavior Blocked", 4),
            1121: ("Suspicious Behavior Allowed", 5),
            1122: ("Exploit Protection Mitigation Event", 4),
            
            # Definition Updates
            2000: ("Definition Update Started", 1),
            2001: ("Definition Update Failed", 3),
            2002: ("Definition Update Completed", 1),
            2003: ("Definition Update Partially Completed", 2),
            2004: ("Definition Update Restore Point Created", 1),
            2005: ("Definition Update Restore Point Failed", 3),
            2006: ("Definition Update Restore Point Deleted", 1),
            2007: ("Definition Update Restore Point Delete Failed", 3),
            
            # Engine and Platform Updates
            2010: ("Engine Update Started", 1),
            2011: ("Engine Update Failed", 3),
            2012: ("Engine Update Completed", 1),
            2013: ("Platform Update Started", 1),
            2014: ("Platform Update Failed", 3),
            2015: ("Platform Update Completed", 1),
            
            # Security Intelligence Updates
            2016: ("Security Intelligence Update Started", 1),
            2017: ("Security Intelligence Update Failed", 3),
            2018: ("Security Intelligence Update Completed", 1),
            2019: ("Security Intelligence Update Partially Completed", 2),
            
            # Protection Status
            3002: ("Real-time Protection Disabled", 4),
            3003: ("Real-time Protection Restored", 2),
            3004: ("Real-time Protection Failure", 4),
            3005: ("Real-time Protection Failure Resolved", 2),
            3006: ("Real-time Protection Configuration Changed", 3),
            3007: ("Real-time Protection Malware Action Taken", 4),
            3008: ("Real-time Protection Malware Action Failed", 5),
            
            # Network Protection
            5000: ("Network Protection Blocked Connection", 4),
            5001: ("Network Protection Blocked and Audited", 3),
            5002: ("Network Protection Block Override", 4),
            5003: ("Network Protection Block Override Failed", 4),
            5004: ("Network Protection Block Override Allowed by Policy", 3),
            
            # Controlled Folder Access
            5007: ("Controlled Folder Access Blocked", 4),
            5008: ("Controlled Folder Access Blocked and Audited", 3),
            5009: ("Controlled Folder Access Block Override", 4),
            5010: ("Controlled Folder Access Block Override Failed", 4),
            5011: ("Controlled Folder Access Block Override Allowed by Policy", 3),
            
            # Attack Surface Reduction
            5024: ("Attack Surface Reduction Blocked", 4),
            5025: ("Attack Surface Reduction Blocked and Audited", 3),
            5026: ("Attack Surface Reduction Block Override", 4),
            5027: ("Attack Surface Reduction Block Override Failed", 4),
            5028: ("Attack Surface Reduction Block Override Allowed by Policy", 3),
            
            # Tamper Protection
            5031: ("Tamper Protection Blocked Change", 5),
            5032: ("Tamper Protection Blocked and Audited Change", 4),
            5033: ("Tamper Protection Block Override", 5),
            5034: ("Tamper Protection Block Override Failed", 5),
            5035: ("Tamper Protection Block Override Allowed by Policy", 4)
        }

    def _get_gpo_event_map(self):
        return {
            # Group Policy Processing Events
            4000: ("GPO Processing Started", 2),
            4001: ("GPO Processing Completed", 2),
            4002: ("GPO Processing Failed", 3),
            4003: ("GPO Applied", 2),
            4004: ("GPO Not Applied", 2),
            4005: ("GPO Processing Started (Background)", 2),
            4006: ("GPO Processing Completed (Background)", 2),
            4007: ("GPO Processing Failed (Background)", 3),
            4008: ("GPO Applied (Background)", 2),
            4009: ("GPO Not Applied (Background)", 2),
            
            # Group Policy Extension Processing
            4010: ("GPO Extension Processing Started", 2),
            4011: ("GPO Extension Processing Completed", 2),
            4012: ("GPO Extension Processing Failed", 3),
            4013: ("GPO Extension Applied", 2),
            4014: ("GPO Extension Not Applied", 2),
            
            # Security Policy Processing
            4015: ("Security Policy Processing Started", 2),
            4016: ("Security Policy Processing Completed", 2),
            4017: ("Security Policy Processing Failed", 3),
            4018: ("Security Policy Applied", 2),
            4019: ("Security Policy Not Applied", 2),
            
            # Group Policy Preference Processing
            4020: ("GPO Preference Processing Started", 2),
            4021: ("GPO Preference Processing Completed", 2),
            4022: ("GPO Preference Processing Failed", 3),
            4023: ("GPO Preference Applied", 2),
            4024: ("GPO Preference Not Applied", 2),
            
            # Group Policy Client-Side Extension Processing
            5000: ("CSE Processing Started", 2),
            5001: ("CSE Processing Completed", 2),
            5002: ("CSE Processing Failed", 3),
            5003: ("CSE Processing Warning", 2),
            5004: ("CSE Processing Information", 1),
            
            # Group Policy Core Events
            5017: ("Group Policy Core Initialization Started", 1),
            5018: ("Group Policy Core Initialization Completed", 1),
            5019: ("Group Policy Core Processing Started", 1),
            5020: ("Group Policy Core Processing Completed", 1),
            5021: ("Group Policy Core Extension Processing Started", 1),
            5022: ("Group Policy Core Extension Processing Completed", 1),
            
            # Group Policy Infrastructure Events
            5030: ("Group Policy Infrastructure Warning", 2),
            5031: ("Group Policy Infrastructure Error", 3),
            5032: ("Group Policy Infrastructure Information", 1),
            
            # Group Policy Security Settings Events
            5050: ("Security Settings Applied (Account Policies)", 2),
            5051: ("Security Settings Applied (Local Policies)", 2),
            5052: ("Security Settings Applied (Event Log)", 2),
            5053: ("Security Settings Applied (Restricted Groups)", 2),
            5054: ("Security Settings Applied (System Services)", 2),
            5055: ("Security Settings Applied (Registry)", 2),
            5056: ("Security Settings Applied (File System)", 2),
            5057: ("Security Settings Applied (Wireless Network Policies)", 2),
            5058: ("Security Settings Applied (Public Key Policies)", 2),
            5059: ("Security Settings Applied (Software Restriction Policies)", 2),
            
            # Group Policy Software Installation Events
            5070: ("Software Installation Started", 2),
            5071: ("Software Installation Completed", 2),
            5072: ("Software Installation Failed", 3),
            5073: ("Software Installation Warning", 2),
            5074: ("Software Installation Information", 1),
            
            # Group Policy Folder Redirection Events
            5080: ("Folder Redirection Started", 2),
            5081: ("Folder Redirection Completed", 2),
            5082: ("Folder Redirection Failed", 3),
            5083: ("Folder Redirection Warning", 2),
            5084: ("Folder Redirection Information", 1),
            
            # Group Policy Scripts Events
            5090: ("Startup Script Execution Started", 2),
            5091: ("Startup Script Execution Completed", 2),
            5092: ("Startup Script Execution Failed", 3),
            5093: ("Shutdown Script Execution Started", 2),
            5094: ("Shutdown Script Execution Completed", 2),
            5095: ("Shutdown Script Execution Failed", 3),
            5096: ("Logon Script Execution Started", 2),
            5097: ("Logon Script Execution Completed", 2),
            5098: ("Logon Script Execution Failed", 3),
            5099: ("Logoff Script Execution Started", 2),
            5100: ("Logoff Script Execution Completed", 2),
            5101: ("Logoff Script Execution Failed", 3)
        }

    def _get_directory_service_event_map(self):
        return {
            # LDAP Interface Events
            2886: ("LDAP Connection Established", 1),
            2887: ("LDAP Connection Disconnected", 1),
            2888: ("LDAP Connection Error", 3),
            2889: ("LDAP Bind Request", 2),
            2890: ("LDAP Bind Response", 2),
            4928: ("LDAP Bind", 2),
            4929: ("LDAP Unbind", 1),
            4930: ("LDAP Search Request", 2),
            4931: ("LDAP Search Response", 2),
            4932: ("LDAP Add Request", 3),
            4933: ("LDAP Add Response", 3),
            4934: ("LDAP Modify Request", 3),
            4935: ("LDAP Modify Response", 3),
            4936: ("LDAP Delete Request", 3),
            4937: ("LDAP Delete Response", 3),
            4938: ("LDAP Extended Request", 2),
            4939: ("LDAP Extended Response", 2),
            
            # Kerberos Authentication Events
            4768: ("Kerberos TGT Request", 2),
            4769: ("Kerberos Service Ticket Request", 2),
            4770: ("Kerberos Service Ticket Renewal", 2),
            4771: ("Kerberos Pre-Authentication Failed", 3),
            4772: ("Kerberos Authentication Ticket Request", 2),
            4773: ("Kerberos Service Ticket Request (UDP)", 2),
            4774: ("Kerberos Ticket Renewal Failed", 3),
            4775: ("Kerberos Pre-authentication Information", 2),
            4776: ("Kerberos Authentication Ticket Request (AS Exchange)", 2),
            4777: ("Kerberos Service Ticket Request (TGS Exchange)", 2),
            4778: ("Kerberos Ticket Was Not Granted", 3),
            4779: ("Kerberos TGT Request (PKINIT)", 2),
            4780: ("Kerberos TGT Request (PKINIT) Failed", 3),
            4781: ("Kerberos TGT Request (PKINIT) Succeeded", 1),
            
            # Account Management Events
            4720: ("User Account Created", 4),
            4722: ("User Account Enabled", 3),
            4723: ("User Account Password Change Attempted", 3),
            4724: ("User Account Password Reset Attempted", 3),
            4725: ("User Account Disabled", 3),
            4726: ("User Account Deleted", 4),
            4727: ("Security-Enabled Global Group Created", 3),
            4728: ("User Added to Security-Enabled Global Group", 3),
            4729: ("User Removed from Security-Enabled Global Group", 3),
            4730: ("Security-Enabled Global Group Deleted", 3),
            4731: ("Security-Enabled Local Group Created", 3),
            4732: ("User Added to Security-Enabled Local Group", 3),
            4733: ("User Removed from Security-Enabled Local Group", 3),
            4734: ("Security-Enabled Local Group Deleted", 3),
            4735: ("Security-Enabled Local Group Changed", 3),
            4737: ("Security-Enabled Global Group Changed", 3),
            4738: ("User Account Changed", 3),
            4739: ("Domain Policy Changed", 3),
            4740: ("User Account Locked Out", 4),
            4741: ("Computer Account Created", 3),
            4742: ("Computer Account Changed", 3),
            4743: ("Computer Account Deleted", 3),
            
            # Directory Service Access Events
            4662: ("Directory Service Object Operation", 3),
            5136: ("Directory Service Object Modified", 3),
            5137: ("Directory Service Object Created", 3),
            5138: ("Directory Service Object Undeleted", 3),
            5139: ("Directory Service Object Moved", 3),
            5141: ("Directory Service Object Deleted", 3),
            
            # Replication Events
            4928: ("Active Directory Replication Started", 2),
            4929: ("Active Directory Replication Ended", 2),
            4930: ("Active Directory Replication Failed", 3),
            4931: ("Active Directory Replication Retry", 2),
            4932: ("Active Directory Replication Link Established", 2),
            4933: ("Active Directory Replication Link Disconnected", 2),
            4934: ("Active Directory Replication Link Error", 3),
            4935: ("Active Directory Replication Link Established (RPC)", 2),
            4936: ("Active Directory Replication Link Disconnected (RPC)", 2),
            4937: ("Active Directory Replication Link Error (RPC)", 3),
            
            # DNS Server Events (on Domain Controllers)
            150: ("DNS Query", 1),
            151: ("DNS Response", 1),
            600: ("DNS Server Started", 1),
            601: ("DNS Server Shutdown", 1),
            602: ("DNS Server Configuration Changed", 2),
            603: ("DNS Server Configuration Error", 3),
            604: ("DNS Server Dynamic Update Request", 2),
            605: ("DNS Server Dynamic Update Failed", 3),
            606: ("DNS Server Dynamic Update Successful", 1),
            607: ("DNS Server Zone Transfer Request", 2),
            608: ("DNS Server Zone Transfer Failed", 3),
            609: ("DNS Server Zone Transfer Successful", 1),
            610: ("DNS Server Zone Updated from Active Directory", 1),
            611: ("DNS Server Zone Write to File", 1),
            612: ("DNS Server Zone Loading", 1),
            613: ("DNS Server Zone Information", 1),
            614: ("DNS Server Zone Error", 3),
            615: ("DNS Server Zone Warning", 2),
            616: ("DNS Server Zone Transfer to Secondary Server", 2),
            617: ("DNS Server Zone Transfer from Master Server", 2),
            618: ("DNS Server Zone Transfer to Secondary Server Failed", 3),
            619: ("DNS Server Zone Transfer from Master Server Failed", 3),
            620: ("DNS Server Added Root Hints", 1),
            621: ("DNS Server Root Hints Error", 3),
            622: ("DNS Server Root Hints Warning", 2),
            
            # Security Auditing Events
            4616: ("System Time Changed", 3),
            4648: ("Logon with Explicit Credentials", 3),
            4656: ("Handle to an Object Was Requested", 3),
            4657: ("Registry Value Was Modified", 3),
            4658: ("Handle to an Object Was Closed", 2),
            4659: ("Handle to an Object Was Requested with Intent to Delete", 3),
            4660: ("Object Was Deleted", 3),
            4661: ("Handle to an Object Was Requested (Detailed)", 3),
            4662: ("Operation Was Performed on an Object", 3),
            4663: ("Attempt to Access an Object", 3),
            4664: ("Attempt to Create a Hard Link", 3),
            4665: ("Attempt to Create an Application Client Context", 2),
            4666: ("Application Client Context Deleted", 2),
            4667: ("Application Client Context Modified", 2),
            4668: ("Application Client Context Deleted on Request", 2),
            4670: ("Permissions on an Object Were Changed", 3),
            4671: ("Application Attempted to Disable a Privilege", 3),
            4672: ("Special Privileges Assigned to New Logon", 3),
            4673: ("Privileged Service Was Called", 3),
            4674: ("Operation Was Performed on a Privileged Object", 3)
        }

    def _get_dns_event_map(self):
        return {
            # DNS Client Events
            150: ("DNS Query", 1),
            151: ("DNS Response", 1),
            300: ("DNS Query Received", 1),
            301: ("DNS Response Sent", 1),
            302: ("DNS Query Sent", 1),
            303: ("DNS Response Received", 1),
            
            # DNS Server Service Events
            304: ("DNS Query Received (UDP)", 1),
            305: ("DNS Response Sent (UDP)", 1),
            306: ("DNS Query Sent (UDP)", 1),
            307: ("DNS Response Received (UDP)", 1),
            
            # DNS Server Service Lifecycle
            150: ("DNS Server Starting", 1),
            151: ("DNS Server Started", 1),
            152: ("DNS Server Stopping", 1),
            153: ("DNS Server Stopped", 1),
            154: ("DNS Server Paused", 1),
            155: ("DNS Server Resumed", 1),
            
            # DNS Server Configuration Events
            200: ("DNS Server Configuration Changed", 2),
            201: ("DNS Server Configuration Applied", 1),
            202: ("DNS Server Configuration Error", 3),
            203: ("DNS Server Configuration Warning", 2),
            204: ("DNS Server Zone Configuration Changed", 2),
            205: ("DNS Server Zone Configuration Applied", 1),
            206: ("DNS Server Zone Configuration Error", 3),
            207: ("DNS Server Zone Configuration Warning", 2),
            
            # DNS Server Zone Events
            400: ("DNS Zone Loaded", 1),
            401: ("DNS Zone Unloaded", 1),
            402: ("DNS Zone Paused", 1),
            403: ("DNS Zone Resumed", 1),
            404: ("DNS Zone Updated", 1),
            405: ("DNS Zone Write to File", 1),
            406: ("DNS Zone Transfer Started", 2),
            407: ("DNS Zone Transfer Completed", 1),
            408: ("DNS Zone Transfer Failed", 3),
            409: ("DNS Zone Transfer Requested", 2),
            410: ("DNS Zone Transfer to Secondary Server", 2),
            411: ("DNS Zone Transfer from Master Server", 2),
            412: ("DNS Zone Transfer to Secondary Server Failed", 3),
            413: ("DNS Zone Transfer from Master Server Failed", 3),
            
            # DNS Server Dynamic Update Events
            500: ("DNS Dynamic Update Requested", 2),
            501: ("DNS Dynamic Update Completed", 1),
            502: ("DNS Dynamic Update Failed", 3),
            503: ("DNS Dynamic Update Rejected", 3),
            504: ("DNS Dynamic Update Conflict", 3),
            505: ("DNS Dynamic Update Success", 1),
            
            # DNS Server Security Events
            600: ("DNS Server Started", 1),
            601: ("DNS Server Shutdown", 1),
            602: ("DNS Server Configuration Changed", 2),
            603: ("DNS Server Configuration Error", 3),
            604: ("DNS Server Dynamic Update Request", 2),
            605: ("DNS Server Dynamic Update Failed", 3),
            606: ("DNS Server Dynamic Update Successful", 1),
            607: ("DNS Server Zone Transfer Request", 2),
            608: ("DNS Server Zone Transfer Failed", 3),
            609: ("DNS Server Zone Transfer Successful", 1),
            610: ("DNS Server Zone Updated from Active Directory", 1),
            611: ("DNS Server Zone Write to File", 1),
            612: ("DNS Server Zone Loading", 1),
            613: ("DNS Server Zone Information", 1),
            614: ("DNS Server Zone Error", 3),
            615: ("DNS Server Zone Warning", 2),
            616: ("DNS Server Zone Transfer to Secondary Server", 2),
            617: ("DNS Server Zone Transfer from Master Server", 2),
            618: ("DNS Server Zone Transfer to Secondary Server Failed", 3),
            619: ("DNS Server Zone Transfer from Master Server Failed", 3),
            620: ("DNS Server Added Root Hints", 1),
            621: ("DNS Server Root Hints Error", 3),
            622: ("DNS Server Root Hints Warning", 2),
            
            # DNS Server Debug Events
            1000: ("DNS Server Debug Logging Started", 1),
            1001: ("DNS Server Debug Logging Stopped", 1),
            1002: ("DNS Server Debug Logging Configuration Changed", 2),
            1003: ("DNS Server Debug Logging Error", 3),
            1004: ("DNS Server Debug Logging Warning", 2),
            1005: ("DNS Server Debug Logging Information", 1),
            
            # DNS Server Performance Events
            2000: ("DNS Server Performance Data Collection Started", 1),
            2001: ("DNS Server Performance Data Collection Stopped", 1),
            2002: ("DNS Server Performance Data Collection Error", 3),
            2003: ("DNS Server Performance Data Collection Warning", 2),
            2004: ("DNS Server Performance Data Collection Information", 1),
            
            # DNS Server Active Directory Integrated Zone Events
            3000: ("DNS Server Active Directory Integrated Zone Loaded", 1),
            3001: ("DNS Server Active Directory Integrated Zone Unloaded", 1),
            3002: ("DNS Server Active Directory Integrated Zone Updated", 1),
            3003: ("DNS Server Active Directory Integrated Zone Error", 3),
            3004: ("DNS Server Active Directory Integrated Zone Warning", 2),
            3005: ("DNS Server Active Directory Integrated Zone Information", 1)
        }

    # Event formatting methods
    def _format_security_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.StringInserts and len(event.StringInserts) > 1:
                message += f"User: {event.StringInserts[1]}\n"
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_system_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.EventID in [7001, 7002] and event.StringInserts:
                message += f"Service: {event.StringInserts[0]}\n"
            if event.StringInserts:
                message += "Details: " + " | ".join(str(i) for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_application_event(self, event, name):
        try:
            message = f"{name} (Event ID: {event.EventID & 0xFFFF})\n"
            message += f"Source: {event.SourceName}\n"
            message += f"Computer: {event.ComputerName}\n"
            if event.StringInserts:
                message += "Details: " + " | ".join(str(i) for i in event.StringInserts)
            return message
        except Exception as e:
            return f"Application Event - Error formatting: {str(e)}"

    def _format_powershell_event(self, event, name):
        try:
            message = f"{name}\nComputer: {event.ComputerName}\n"
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"
            
    def _collect_task_scheduler_events(self, hand):
        """
        Collect Task Scheduler operational events.
        
        Args:
            hand: Handle to the Task Scheduler operational log
        """
        import win32evtlog
        import win32con
        
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        try:
            while True:
                events = win32evtlog.ReadEventLog(
                    hand,
                    flags,
                    0,
                    100  # Read up to 100 events at a time
                )
                
                if not events:
                    break
                    
                for event in events:
                    try:
                        event_data = self._parse_event(event)
                        if event_data:
                            self.event_model.queue_event(event_data)
                    except Exception as e:
                        logger.error(f"Error processing Task Scheduler event: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Error reading Task Scheduler events: {str(e)}")
            raise
            
    def _format_defender_event(self, event, name):
        try:
            message = f"{name} (Event ID: {event.EventID & 0xFFFF})\n"
            message += f"Computer: {event.ComputerName}\n"
            if hasattr(event, 'TimeGenerated'):
                try:
                    message += f"Time: {event.TimeGenerated}\n"
                except:
                    message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            else:
                message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
                
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"
            
    def _format_gpo_event(self, event, name):
        try:
            message = f"{name} (Event ID: {event.EventID & 0xFFFF})\n"
            message += f"Computer: {event.ComputerName}\n"
            if hasattr(event, 'TimeGenerated'):
                try:
                    message += f"Time: {event.TimeGenerated}\n"
                except:
                    message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            else:
                message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                
            if event.StringInserts:
                message += "Details:\n" + "\n".join(f"- {i}" for i in event.StringInserts)
                
            return message
        except Exception as e:
            return f"{name} - Error formatting: {str(e)}"

    def _format_sysmon_event(self, event, name):
        try:
            # Get the actual Sysmon event ID from the first string insert
            if event.StringInserts and len(event.StringInserts) > 0:
                try:
                    sysmon_event_id = int(event.StringInserts[0])
                except (ValueError, IndexError):
                    sysmon_event_id = event.EventID & 0xFFFF
            else:
                sysmon_event_id = event.EventID & 0xFFFF

            message = f"{name} (Sysmon Event ID: {sysmon_event_id})\n"
            message += f"Computer: {event.ComputerName}\n"
            # Safely get the timestamp
            if hasattr(event, 'TimeGenerated'):
                try:
                    message += f"Time: {event.TimeGenerated}\n"
                except:
                    message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            else:
                message += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            if not hasattr(event, 'StringInserts') or not event.StringInserts:
                return message + "No event data available"
                
            # Different event types have different field structures
            if sysmon_event_id == 1:  # Process Create
                fields = [
                    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                    "FileVersion", "Description", "Product", "Company", "OriginalFileName",
                    "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId",
                    "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid",
                    "ParentProcessId", "ParentImage", "ParentCommandLine"
                ]
                details = {}
                for i in range(1, len(event.StringInserts)):  # Skip first field (event ID)
                    if i-1 < len(fields):
                        details[fields[i-1]] = event.StringInserts[i]
                
                message += f"Process: {details.get('Image', 'N/A')}\n"
                message += f"PID: {details.get('ProcessId', 'N/A')}\n"
                if 'CommandLine' in details:
                    message += f"Command Line: {details['CommandLine']}\n"
                message += f"User: {details.get('User', 'N/A')}\n"
                parent_pid = details.get('ParentProcessId', 'N/A')
                parent_image = details.get('ParentImage', 'N/A')
                if parent_pid != 'N/A' or parent_image != 'N/A':
                    message += f"Parent: {parent_image} (PID: {parent_pid})\n"
                
                # Add any additional fields that might be interesting
                for field in ['Hashes', 'IntegrityLevel', 'LogonId', 'TerminalSessionId']:
                    if field in details and details[field]:
                        message += f"{field}: {details[field]}\n"
            
            elif sysmon_event_id == 3:  # Network Connection
                fields = [
                    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                    "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp",
                    "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6",
                    "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"
                ]
                details = {}
                for i in range(1, len(event.StringInserts)):  # Skip first field (event ID)
                    if i-1 < len(fields):
                        details[fields[i-1]] = event.StringInserts[i]
                
                message += f"Process: {details.get('Image', 'N/A')} (PID: {details.get('ProcessId', 'N/A')})\n"
                message += f"User: {details.get('User', 'N/A')}\n"
                src_ip = details.get('SourceIp', 'N/A')
                src_port = details.get('SourcePort', 'N/A')
                dst_ip = details.get('DestinationIp', 'N/A')
                dst_port = details.get('DestinationPort', 'N/A')
                protocol = details.get('Protocol', 'N/A')
                
                message += f"Connection: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({protocol})\n"
                
                if 'Initiated' in details:
                    message += f"Initiated: {details['Initiated']}\n"
            
            elif sysmon_event_id == 7:  # Image Loaded
                fields = [
                    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                    "ImageLoaded", "FileVersion", "Description", "Product", "Company",
                    "OriginalFileName", "Hashes", "Signed", "Signature"
                ]
                details = {}
                for i in range(1, len(event.StringInserts)):  # Skip first field (event ID)
                    if i-1 < len(fields):
                        details[fields[i-1]] = event.StringInserts[i]
                
                message += f"Process: {details.get('Image', 'N/A')} (PID: {details.get('ProcessId', 'N/A')})\n"
                message += f"Image Loaded: {details.get('ImageLoaded', 'N/A')}\n"
                
                if 'Company' in details and details['Company']:
                    message += f"Company: {details['Company']}\n"
                if 'Hashes' in details and details['Hashes']:
                    message += f"Hashes: {details['Hashes']}\n"
                message += f"Signed: {details.get('Signed', 'N/A')}\n"
                if 'Signature' in details and details['Signature'] != 'N/A':
                    message += f"Signature: {details['Signature']}\n"
            
            elif sysmon_event_id == 11:  # File Created
                fields = [
                    "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                    "TargetFilename", "CreationUtcTime", "User"
                ]
                details = {}
                for i in range(1, len(event.StringInserts)):  # Skip first field (event ID)
                    if i-1 < len(fields):
                        details[fields[i-1]] = event.StringInserts[i]
                
                message += f"Process: {details.get('Image', 'N/A')} (PID: {details.get('ProcessId', 'N/A')})\n"
                message += f"File Created: {details.get('TargetFilename', 'N/A')}\n"
                if 'CreationUtcTime' in details:
                    message += f"Creation Time: {details['CreationUtcTime']}\n"
                if 'User' in details:
                    message += f"User: {details['User']}\n"
            else:
                # Default handling for other event types
                message += "Event Data:\n"
                for i, value in enumerate(event.StringInserts):
                    if i == 0:
                        message += f"  Event ID: {value}\n"
                    # Try to get field names for known event types
                    field_names = []
                    if sysmon_event_id in [1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]:
                        field_names = self._get_sysmon_field_names(sysmon_event_id)
                    
                    if i-1 < len(field_names) and i > 0:  # i-1 because we skip event ID
                        message += f"  {field_names[i-1]}: {value}\n"
                    elif i > 0:  # Only show non-event ID fields
                        message += f"  Field {i}: {value}\n"
            
            return message.strip()
            
        except Exception as e:
            import traceback
            return f"{name} - Error formatting: {str(e)}\n{traceback.format_exc()}"
    
    def _get_sysmon_field_names(self, event_id):
        """Return field names for known Sysmon event types"""
        field_map = {
            1: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "FileVersion", "Description", "Product", "Company", "OriginalFileName",
                "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId",
                "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid",
                "ParentProcessId", "ParentImage", "ParentCommandLine"],
            2: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "User"],
            3: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp",
                "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6",
                "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"],
            4: ["RuleName", "UtcTime", "State", "Version", "SchemaVersion",
                "HashAlgorithms"],
            5: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "User"],
            6: ["RuleName", "UtcTime", "ImageLoaded", "Hashes", "Signed",
                "Signature"],
            7: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "ImageLoaded", "FileVersion", "Description", "Product", "Company",
                "OriginalFileName", "Hashes", "Signed", "Signature"],
            8: ["RuleName", "UtcTime", "SourceProcessGuid", "SourceProcessId",
                "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage",
                "NewThreadId", "StartAddress", "StartModule", "StartFunction"],
            9: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                "Device"],
            10: ["RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId",
                 "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId",
                 "TargetImage", "GrantedAccess", "CallTrace"],
            11: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                 "TargetFilename", "CreationUtcTime", "User"],
            12: ["RuleName", "UtcTime", "EventType", "ProcessGuid", "ProcessId",
                 "Image", "TargetObject", "Details"],
            13: ["RuleName", "UtcTime", "EventType", "ProcessGuid", "ProcessId",
                 "Image", "TargetObject", "Details"],
            14: ["RuleName", "UtcTime", "EventType", "ProcessGuid", "ProcessId",
                 "Image", "TargetObject", "NewName"],
            15: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image",
                 "TargetFilename", "Hashes", "Contents"],
            16: ["RuleName", "UtcTime", "Configuration", "ConfigurationFileHash"]
        }
        
        return field_map.get(event_id, [])

    def _enable_firewall_logging(self, profile_path: str, profile_name: str) -> bool:
        """Enable firewall logging for a specific profile.
        
        Args:
            profile_path: Registry path to the firewall profile
            profile_name: Name of the profile (for logging)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import winreg
            
            # Open the registry key with write access
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                profile_path,
                0,  # Default access
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
            )
            
            # Enable logging for dropped packets and successful connections
            winreg.SetValueEx(key, 'EnableLogDroppedPackets', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'EnableLogSuccessfulConnections', 0, winreg.REG_DWORD, 1)
            
            # Set log file path and size (50MB max)
            log_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 
                                  'System32', 'LogFiles', 'Firewall', 'pfirewall.log')
            winreg.SetValueEx(key, 'LogFilePath', 0, winreg.REG_EXPAND_SZ, log_path)
            winreg.SetValueEx(key, 'LogFileSize', 0, winreg.REG_DWORD, 51200)  # 50MB
            
            # Close the key
            winreg.CloseKey(key)
            
            logger.info(f"Enabled firewall logging for {profile_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable firewall logging for {profile_name}: {e}")
            return False
            
    def _is_firewall_logging_enabled(self) -> bool:
        """Check and enable Windows Firewall logging if needed.
        
        Returns:
            bool: True if logging is enabled for any profile, False otherwise
        """
        try:
            import winreg
            
            # Define firewall profiles
            profiles = {
                'DomainProfile': r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile',
                'PrivateProfile': r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile',
                'PublicProfile': r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile'
            }
            
            logging_enabled = False
            
            for profile_name, profile_path in profiles.items():
                try:
                    # Try to open the profile key
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profile_path, 
                                          0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    except FileNotFoundError:
                        continue
                    
                    try:
                        # Check current logging settings
                        dropped_enabled = winreg.QueryValueEx(key, 'EnableLogDroppedPackets')[0]
                        success_enabled = winreg.QueryValueEx(key, 'EnableLogSuccessfulConnections')[0]
                        
                        if dropped_enabled == 1 or success_enabled == 1:
                            logging_enabled = True
                            logger.info(f"Firewall logging is enabled for {profile_name}")
                        
                        winreg.CloseKey(key)
                        
                    except FileNotFoundError:
                        # Logging values don't exist, try to enable them
                        if self._enable_firewall_logging(profile_path, profile_name):
                            logging_enable = True
                    
                except Exception as e:
                    logger.warning(f"Error checking {profile_name} logging status: {e}")
            
            if not logging_enabled:
                logger.warning("Firewall logging is not enabled for any profile")
                self._show_firewall_logging_instructions()
            
            return logging_enabled
            
        except Exception as e:
            logger.error(f"Error checking firewall logging status: {e}")
            return False

    def _get_firewall_log_path(self) -> str:
        """Get or create the path to the Windows Firewall log file.
        
        Returns:
            str: Path to the firewall log file, or None if not found/accessible
        """
        # Default log directory and file path
        log_dir = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'LogFiles', 'Firewall')
        log_file = os.path.join(log_dir, 'pfirewall.log')
        
        try:
            # Create the log directory if it doesn't exist
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Created firewall log directory: {log_dir}")
            
            # Check if we can access the log file
            if os.path.exists(log_file):
                # Check if we have write permissions
                try:
                    with open(log_file, 'a'):
                        pass
                    return log_file
                except IOError:
                    logger.warning(f"No write permissions for firewall log: {log_file}")
            else:
                # Try to create the log file
                try:
                    with open(log_file, 'a'):
                        pass
                    logger.info(f"Created empty firewall log file: {log_file}")
                    return log_file
                except IOError as e:
                    logger.error(f"Failed to create firewall log file: {e}")
            
            # Fallback to checking other possible locations
            possible_paths = [
                # Default location for Windows 10/11
                log_file,
                # Alternate locations
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'pfirewall.log'),
                os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 'Microsoft', 'Windows', 'Firewall', 'pfirewall.log'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Logs', 'Firewall', 'pfirewall.log'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'LogFiles', 'Firewall', 'pfirewall.log.old'),
            ]
            
            for path in possible_paths:
                if os.path.exists(path):
                    try:
                        with open(path, 'a'):
                            pass
                        logger.info(f"Using firewall log file: {path}")
                        return path
                    except IOError:
                        continue
        
        except Exception as e:
            logger.error(f"Error determining firewall log path: {e}")
        
        logger.error("Could not access or create firewall log file")
        return None

    def _show_firewall_logging_instructions(self) -> None:
        """Display instructions for enabling Windows Firewall logging via command line."""
        logger.warning("\n" + "="*80)
        logger.warning("WINDOWS FIREWALL LOGGING IS NOT ENABLED")
        logger.warning("="*80)
        
        instructions = """
To enable Windows Firewall logging, you can use the following PowerShell commands:

# 1. Run PowerShell as Administrator
# 2. Execute these commands:

# Enable logging for all profiles
$profiles = @('DomainProfile', 'PrivateProfile', 'PublicProfile')
foreach ($profile in $profiles) {
    # Enable logging for dropped packets and successful connections
    Set-NetFirewallProfile -Profile $profile -LogAllowed True -LogBlocked True -LogIgnored False -LogMaxSizeKilobytes 51200 -LogFileName "%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log"
    
    # Verify the settings
    Get-NetFirewallProfile -Profile $profile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, LogIgnored
}

# If the above fails, you can also try the registry method:
$regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"
$profiles = @('DomainProfile', 'StandardProfile', 'PublicProfile')
foreach ($profile in $profiles) {
    $keyPath = "$regPath\\$profile\\Logging"
    if (-not (Test-Path $keyPath)) {
        New-Item -Path $keyPath -Force | Out-Null
    }
    Set-ItemProperty -Path $keyPath -Name "LogDroppedPackets" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $keyPath -Name "LogSuccessfulConnections" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $keyPath -Name "LogFile" -Value "%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log" -Type ExpandString -Force
    Set-ItemProperty -Path $keyPath -Name "LogFileSize" -Value 51200 -Type DWord -Force  # 50MB
}

# Restart the Windows Firewall service
Restart-Service -Name "mpssvc" -Force

Note: Logging all connections may impact performance on busy networks.
"""
        logger.warning(instructions)
        
        # Also log to a file for reference
        try:
            log_dir = os.path.join(os.environ.get('TEMP', 'C:\\Temp'))
            log_file = os.path.join(log_dir, 'enable_firewall_logging.ps1')
            with open(log_file, 'w') as f:
                f.write("# Run this script as Administrator to enable Windows Firewall logging\n\n")
                f.write("# Enable logging for all profiles\n")
                f.write("$profiles = @('DomainProfile', 'PrivateProfile', 'PublicProfile')\n")
                f.write("foreach ($profile in $profiles) {\n")
                f.write("    Set-NetFirewallProfile -Profile $profile -LogAllowed True -LogBlocked True -LogIgnored False -LogMaxSizeKilobytes 51200 -LogFileName \"%SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log\"\n")
                f.write("    Get-NetFirewallProfile -Profile $profile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked, LogIgnored\n")
                f.write("}\n\n")
                f.write("# Restart Windows Firewall service\n")
                f.write("Restart-Service -Name \"mpssvc\" -Force\n")
                
            logger.info(f"\nFirewall logging instructions saved to: {log_file}")
            logger.info("Right-click the file and select 'Run with PowerShell' (as Administrator)")
            logger.warning("="*80 + "\n")
        except Exception as e:
            logger.error(f"Failed to save firewall logging instructions: {e}")

    def _collect_firewall_logs(self) -> None:
        """
        Collect Windows Firewall log events.
        
        This method monitors the Windows Firewall log file for new events.
        """
        logger.info("Starting Windows Firewall log collector")
        
        # Check if firewall logging is enabled
        if not self._is_firewall_logging_enabled():
            self._show_firewall_logging_instructions()
            # Continue anyway in case the registry check failed but logging is enabled
        
        # Get the firewall log path
        log_path = self._get_firewall_log_path()
        
        if not log_path:
            self._show_firewall_logging_instructions()
            return
        
        # Track the last position in the file
        last_position = 0
        consecutive_errors = 0
        max_consecutive_errors = 5
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Check if the log file still exists
                    if not os.path.exists(log_path):
                        logger.warning(f"Firewall log file not found: {log_path}")
                        log_path = self._get_firewall_log_path()
                        if not log_path:
                            self._show_firewall_logging_instructions()
                            time.sleep(60)  # Wait a minute before checking again
                            continue
                    
                    # Open the log file and seek to the last position
                    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Move to the last known position
                        f.seek(0, 2)
                        file_size = f.tell()
                        
                        # If file was rotated or truncated, reset position
                        if file_size < last_position:
                            logger.info("Firewall log file was rotated or truncated, resetting position")
                            last_position = 0
                        
                        # If we have new content to read
                        if file_size > last_position:
                            f.seek(last_position)
                            
                            # Process each new line
                            line_count = 0
                            for line in f:
                                self._process_firewall_log(line.strip())
                                line_count += 1
                            
                            if line_count > 0:
                                logger.debug(f"Processed {line_count} new firewall log entries")
                            
                            # Update the last position
                            last_position = f.tell()
                    
                    # Reset error counter on successful read
                    consecutive_errors = 0
                    
                    # Sleep before checking for new content
                    time.sleep(5)
                    
                except PermissionError as e:
                    consecutive_errors += 1
                    error_msg = f"Permission denied accessing firewall log: {e}"
                    if consecutive_errors == 1:  # Only log the full error on first occurrence
                        logger.error(error_msg)
                        logger.info("Please run the SIEM application as Administrator to access firewall logs.")
                    elif consecutive_errors % 10 == 0:  # Log periodically to avoid log spam
                        logger.warning(f"Still cannot access firewall log (attempt {consecutive_errors})")
                    
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error("Too many consecutive errors, giving up on firewall log collection")
                        break
                        
                    time.sleep(30)  # Wait longer after errors
                    
                except IOError as e:
                    consecutive_errors += 1
                    error_msg = f"I/O error reading firewall log: {e}"
                    if consecutive_errors == 1:  # Only log the full error on first occurrence
                        logger.error(error_msg)
                    
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error("Too many consecutive errors, giving up on firewall log collection")
                        break
                        
                    time.sleep(30)  # Wait longer after errors
                    
                except Exception as e:
                    consecutive_errors += 1
                    logger.error(f"Unexpected error in firewall collector: {e}", exc_info=True)
                    
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error("Too many consecutive errors, giving up on firewall log collection")
                        break
                        
                    time.sleep(30)  # Wait longer after errors
                    
        except Exception as e:
            logger.critical(f"Critical error in firewall collector: {e}", exc_info=True)
            raise
        finally:
            logger.info("Windows Firewall log collector stopped")

    def _process_firewall_log(self, line):
        """
        Process a single line from the Windows Firewall log.
        
        Args:
            line: A line from the firewall log file
        """
        if not line or line.startswith('#'):
            return
            
        try:
            parts = line.split()
            if len(parts) < 6:
                return
                
            # Parse the date and time
            date_str = f"{parts[0]} {parts[1]}"
            try:
                # Convert to ISO format for consistency
                timestamp = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').isoformat()
            except ValueError:
                timestamp = datetime.now().isoformat()
                
            action = parts[2]
            protocol = parts[3]
            src_ip = parts[4]
            dst_ip = parts[5]
            
            # Set severity based on action
            if action in ["DROP", "BLOCK"]:
                severity = 3  # High severity for blocked connections
            elif action in ["ALLOW"]:
                severity = 1  # Low severity for allowed connections
            else:
                severity = 2  # Medium severity for other actions
            
            # Create the event
            self.event_model.queue_event({
                'timestamp': timestamp,
                'source': 'Windows Firewall',
                'event_type': f'Firewall {action}',
                'severity': severity,
                'description': f"{protocol} connection from {src_ip} to {dst_ip}",
                'ip_address': src_ip,
                'details': {
                    'protocol': protocol,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'action': action
                }
            })
            
        except Exception as e:
            logger.warning(f"Error processing firewall log line: {e}")

    def _extract_ip_from_event(self, event):
        try:
            if hasattr(event, 'EventID') and event.EventID in [4624, 4625, 4648]:
                if event.StringInserts and len(event.StringInserts) >= 19:
                    ip = event.StringInserts[18]
                    if ip and ip != '-':
                        return ip
            
            if hasattr(event, 'StringInserts'):
                for item in event.StringInserts:
                    if isinstance(item, str) and re.match(r'\d+\.\d+\.\d+\.\d+', item):
                        return item
        except:
            pass
        
        return None