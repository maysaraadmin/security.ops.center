"""
Sysmon Event Collector for SIEM

This module collects and processes Windows Sysmon events for security monitoring.
"""
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Any

import psutil
import win32con
import win32evtlog
import win32evtlogutil
from win32evtlog import OpenEventLog, ReadEventLog, CloseEventLog

logger = logging.getLogger(__name__)

class SysmonCollector:
    """Collects and processes Sysmon events from Windows Event Log."""

    def __init__(self, server: str = None, log_name: str = "Microsoft-Windows-Sysmon/Operational"):
        """Initialize the Sysmon collector.
        
        Args:
            server: The server to connect to (local machine if None)
            log_name: The name of the Sysmon event log (default: Microsoft-Windows-Sysmon/Operational)
        """
        self.server = server
        self.log_name = log_name
        self.handles = {}
        self.last_event_time = {}
        self._initialize_handles()

    def _initialize_handles(self) -> None:
        """Initialize event log handles for reading."""
        try:
            # Check if the log exists and is accessible
            try:
                import win32evtlog
                h = win32evtlog.OpenEventLog(self.server, self.log_name)
                win32evtlog.CloseEventLog(h)
            except Exception as e:
                logger.error(f"Cannot access {self.log_name} log. Please ensure Sysmon is properly installed and running. Error: {str(e)}")
                # Try to find available logs
                try:
                    logs = [log for log in win32evtlog.EvtChannelEnum() if 'sysmon' in log.lower()]
                    if logs:
                        logger.warning(f"Found these Sysmon-related logs: {', '.join(logs)}")
                    else:
                        logger.warning("No Sysmon logs found. Is Sysmon installed?")
                except Exception as e:
                    logger.error(f"Error enumerating event logs: {str(e)}")
                raise
                
            # Open the Sysmon event log
            self.handles['sysmon'] = OpenEventLog(self.server, self.log_name)
            logger.info(f"Successfully connected to {self.log_name} event log")
            
            # Store the initial last event time
            self.last_event_time = {
                'sysmon': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to initialize Sysmon collector: {str(e)}")
            raise

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve new Sysmon events since the last check.
        
        Args:
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        events = []
        try:
            if 'sysmon' not in self.handles or not self.handles['sysmon']:
                logger.error("No valid Sysmon event log handle found. Reinitializing...")
                self._initialize_handles()
                if 'sysmon' not in self.handles or not self.handles['sysmon']:
                    logger.error("Failed to initialize Sysmon event log handle")
                    return []
            
            # Read events in chunks
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            max_attempts = 3
            attempt = 0
            
            while len(events) < limit and attempt < max_attempts:
                try:
                    events_batch = win32evtlog.ReadEventLog(
                        self.handles['sysmon'],
                        flags,
                        0,  # Read from the beginning
                        50  # Read 50 events at a time
                    )
                    
                    if not events_batch:
                        logger.info("No more events in the log")
                        break
                    
                    logger.debug(f"Read {len(events_batch)} events in batch")
                    
                    for event in events_batch:
                        if len(events) >= limit:
                            break
                            
                        event_data = self._parse_event(event)
                        if event_data:
                            events.append(event_data)
                            # Update the last event time
                            event_time = event_data.get('timestamp')
                            if event_time:
                                self.last_event_time['sysmon'] = event_time
                            
                except Exception as e:
                    logger.error(f"Error reading Sysmon events: {e}")
                    # Try to reinitialize the handle on error
                    attempt += 1
                    if attempt < max_attempts:
                        logger.info(f"Retrying... (attempt {attempt}/{max_attempts})")
                        self._initialize_handles()
                    continue
                    
                # If we got here, we had a successful read
                attempt = 0
                
            return events
            
        except Exception as e:
            logger.error(f"Unexpected error in get_events: {e}")
            return []
            
        except Exception as e:
            logger.error(f"Error reading Sysmon events: {str(e)}")
            return []

    def _parse_event(self, event: Any) -> Optional[Dict[str, Any]]:
        """Parse a Sysmon event into a dictionary.
        
        Args:
            event: The Windows event object
            
        Returns:
            Dictionary containing parsed event data, or None if parsing fails
        """
        try:
            event_id = event.EventID
            self.last_event_id = event_id  # Store for field mapping
            event_time = event.TimeGenerated.Format()
            
            # Basic event structure
            event_data = {
                'event_id': event_id,
                'timestamp': event_time,
                'source': 'sysmon',
                'computer_name': event.ComputerName,
                'process_id': event.ProcessId,
                'thread_id': event.ThreadId,
                'level': self._get_event_level(event.EventType),
                'event_data': {}
            }
            
            # Parse event data
            if hasattr(event, 'StringInserts'):
                event_data['event_data'] = self._parse_event_data(event.StringInserts)
            
            # Format for GUI display
            return self._format_for_gui(event_data)
            
        except Exception as e:
            logger.error(f"Error parsing Sysmon event: {str(e)}")
            return None
    
    def _parse_event_data(self, string_inserts: List[str]) -> Dict[str, str]:
        """Parse the string inserts from a Sysmon event.
        
        Args:
            string_inserts: List of strings from the event data
            
        Returns:
            Dictionary of parsed event data
        """
        if not string_inserts:
            return {}
            
        # Map of event IDs to their field names
        event_field_maps = {
            1: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"],
            2: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "Hashes", "Signed", "Signature", "SignatureStatus"],
            3: ["RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceImage", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"],
            5: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"],
            7: ["RuleName", "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"],
            8: ["RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction"],
            9: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "Hashes", "Signed", "Signature", "SignatureStatus"],
            10: ["RuleName", "UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace"],
            11: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "Hashes", "User"],
            12: ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "User"],
            13: ["RuleName", "EventType", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details", "User"],
            14: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "TargetObject", "EventType", "Details"],
            15: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "UtcTime", "Destination"],
            16: ["RuleName", "UtcTime", "Config", "ConfigFile"],
            17: ["RuleName", "UtcTime", "PipeName", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"],
            18: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"],
            19: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"],
            20: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"],
            21: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"],
            22: ["RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "User", "LogonGuid", "LogonId", "SourceModuleGUID", "SourceModuleName", "SourceModuleType", "EventType", "Source"]
        }
        
        # Get the field map for this event ID
        event_id = int(self.last_event_id) if hasattr(self, 'last_event_id') else 0
        field_map = event_field_maps.get(event_id, [])
        
        # Create a dictionary with the field names as keys
        event_data = {}
        for i, value in enumerate(string_inserts):
            if i < len(field_map):
                field_name = field_map[i]
                event_data[field_name] = value
            else:
                event_data[f'extra_field_{i}'] = value
                
        return event_data
    
    @staticmethod
    def _get_event_level(event_type: int) -> str:
        """Convert Windows event type to a standard level.
        
        Args:
            event_type: Windows event type constant
            
        Returns:
            String representation of the event level
        """
        if event_type == win32con.EVENTLOG_ERROR_TYPE:
            return 'error'
        elif event_type == win32con.EVENTLOG_WARNING_TYPE:
            return 'warning'
        elif event_type == win32con.EVENTLOG_INFORMATION_TYPE:
            return 'info'
        elif event_type == win32con.EVENTLOG_AUDIT_SUCCESS:
            return 'audit_success'
        elif event_type == win32con.EVENTLOG_AUDIT_FAILURE:
            return 'audit_failure'
        return 'unknown'
    
    def _format_for_gui(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format event data for display in the GUI.
        
        Args:
            event_data: The parsed event data
            
        Returns:
            Formatted event data for the GUI
        """
        event_id = event_data.get('event_id', 0)
        event_time = event_data.get('timestamp', '')
        event_data = event_data.get('event_data', {})
        
        # Default values
        event_type = f"Sysmon Event {event_id}"
        details = ""
        
        # Format based on event type
        if event_id == 1:  # Process creation
            event_type = "Process Create"
            details = f"Image: {event_data.get('Image', 'N/A')} | " \
                     f"CommandLine: {event_data.get('CommandLine', 'N/A')} | " \
                     f"User: {event_data.get('User', 'N/A')}"
        elif event_id == 3:  # Network connection
            event_type = "Network Connection"
            details = f"Source: {event_data.get('SourceImage', 'N/A')} | " \
                     f"Destination: {event_data.get('DestinationIp', 'N/A')}:{event_data.get('DestinationPort', 'N/A')} | " \
                     f"Process: {event_data.get('SourceImage', 'N/A')}"
        elif event_id == 7:  # Image loaded
            event_type = "Image Loaded"
            details = f"Image: {event_data.get('ImageLoaded', 'N/A')} | " \
                     f"Process: {event_data.get('SourceImage', 'N/A')}"
        elif event_id == 8:  # CreateRemoteThread
            event_type = "Remote Thread Created"
            details = f"Source: {event_data.get('SourceImage', 'N/A')} | " \
                     f"Target: {event_data.get('TargetImage', 'N/A')} | " \
                     f"StartModule: {event_data.get('StartModule', 'N/A')}"
        elif event_id == 10:  # ProcessAccess
            event_type = "Process Access"
            details = f"Source: {event_data.get('SourceImage', 'N/A')} | " \
                     f"Target: {event_data.get('TargetImage', 'N/A')} | " \
                     f"Access: {event_data.get('GrantedAccess', 'N/A')}"
        else:
            # Generic format for other event types
            details = " | ".join(f"{k}: {v}" for k, v in event_data.items() if v and len(str(v)) < 100)
        
        return {
            'timestamp': event_time,
            'source': event_data.get('Computer', 'Unknown'),
            'event_id': str(event_id),
            'type': event_type,
            'details': details,
            'raw_data': event_data
        }
    
    def close(self) -> None:
        """Close all open event log handles."""
        for handle in self.handles.values():
            try:
                CloseEventLog(handle)
            except Exception as e:
                logger.error(f"Error closing event log handle: {str(e)}")
        self.handles = {}

    def __del__(self):
        """Ensure resources are cleaned up."""
        self.close()


def collect_sysmon_events() -> List[Dict[str, Any]]:
    """Convenience function to collect Sysmon events.
    
    Returns:
        List of collected events
    """
    collector = None
    try:
        logger.info("Initializing Sysmon collector...")
        collector = SysmonCollector()
        
        # Try to get events with a timeout
        logger.info("Attempting to collect events...")
        events = collector.get_events(limit=100)
        
        if not events:
            logger.warning("No events were returned by get_events()")
            return []
            
        logger.info(f"Successfully collected {len(events)} events")
        return events
        
    except Exception as e:
        import traceback
        error_msg = f"Failed to collect Sysmon events: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_msg)
        
        # Try to get more specific error information
        try:
            import win32api
            error_code = win32api.GetLastError()
            logger.error(f"Windows error code: {error_code}")
        except Exception as win_err:
            logger.error(f"Could not get Windows error code: {str(win_err)}")
            
        return []
        
    finally:
        if collector:
            try:
                collector.close()
            except Exception as e:
                logger.error(f"Error closing collector: {str(e)}")


if __name__ == "__main__":
    # Example usage
    import pprint
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Collecting Sysmon events...")
    collector = SysmonCollector()
    
    try:
        while True:
            events = collector.get_events(limit=10)
            if events:
                print(f"\nCollected {len(events)} new events:")
                for event in events:
                    pprint.pprint(event, width=120)
            else:
                print(".", end="", flush=True)
                
            time.sleep(5)  # Check for new events every 5 seconds
            
    except KeyboardInterrupt:
        print("\nStopping Sysmon event collection...")
    finally:
        collector.close()
