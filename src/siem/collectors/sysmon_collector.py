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
            # Read events in chunks
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while len(events) < limit:
                events_batch = win32evtlog.ReadEventLog(
                    self.handles['sysmon'],
                    flags,
                    0,
                    50  # Read 50 events at a time
                )
                
                if not events_batch:
                    break
                    
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
            
            return events
            
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
                
            return event_data
            
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
            
        # The structure depends on the event ID
        # This is a simplified version - you may need to customize based on your needs
        event_data = {}
        
        for i, value in enumerate(string_inserts, 1):
            event_data[f'data_{i}'] = value
            
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
    try:
        collector = SysmonCollector()
        events = collector.get_events(limit=100)
        collector.close()
        return events
    except Exception as e:
        logger.error(f"Failed to collect Sysmon events: {str(e)}")
        return []


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
