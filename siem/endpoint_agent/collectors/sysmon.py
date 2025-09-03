"""
Sysmon Collector
---------------
Collects logs from the Windows Sysmon service.
"""
import os
import re
import time
import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

from .base import BaseCollector
from ...endpoint_agent.agent import LogSeverity

logger = logging.getLogger('siem_agent.collector.sysmon')

# Try to import Windows-specific modules
try:
    import win32evtlog
    import win32con
    import win32api
    import win32security
    import pywintypes
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

class SysmonCollector(BaseCollector):
    """Collects logs from the Windows Sysmon service."""
    
    def __init__(self, **kwargs):
        """Initialize the Sysmon collector.
        
        Args:
            **kwargs: Additional arguments passed to the base class
        """
        # Set default values before calling parent's __init__
        max_events = kwargs.pop('max_events', 1000)
        self.max_events_per_log = kwargs.pop('max_events_per_log', max_events)
        self.max_event_age = kwargs.pop('max_event_age', 3600)  # 1 hour by default
        
        # Call parent's __init__ with remaining kwargs
        super().__init__(name="Sysmon", **kwargs)
        
        # Initialize instance variables
        self.events = []
        self.last_event_time = datetime.utcnow() - timedelta(minutes=5)
        self._seen_events = set()
        self._last_cleanup = time.time()
        self.logger = logging.getLogger('siem_agent.collector.sysmon')
        self.name = "SysmonCollector"
        self.running = False
        self.last_record_num = 0
        self._initialized = False
        
        # Log initialization
        self.logger.info(f"Initialized {self.name} with max_events_per_log={self.max_events_per_log}, max_event_age={self.max_event_age}s")
        
        # Try to initialize the collector
        self._initialize()
    
    def _parse_sysmon_event(self, event):
        """Parse a Sysmon event.
        
        Args:
            event: The raw Windows event log record
            
        Returns:
            LogEntry: Parsed event data or None if parsing fails
        """
        if not event:
            return None
            
        # Import LogEntry and LogSeverity here to avoid circular imports
        from ..agent import LogEntry, LogSeverity
            
        try:
            # Safely get event properties with defaults
            timestamp = (
                event.TimeGenerated.Format('%Y-%m-%d %H:%M:%S') 
                if hasattr(event, 'TimeGenerated') and event.TimeGenerated 
                else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
            )
            
            # Create a basic event structure
            event_data = {
                'event_id': getattr(event, 'EventID', 0),
                'event_type': self.SYSMON_EVENT_IDS.get(
                    getattr(event, 'EventID', 0), 
                    f'Unknown({getattr(event, "EventID", "N/A")})'
                ),
                'computer': getattr(event, 'ComputerName', 'N/A'),
                'raw': str(event) if event else 'No event data'
            }
            
            # Safely get StringInserts if available
            string_inserts = getattr(event, 'StringInserts', None)
            if not string_inserts or not isinstance(string_inserts, (list, tuple)):
                # Return a basic LogEntry if no StringInserts
                return LogEntry(
                    timestamp=timestamp,
                    source='sysmon',
                    hostname=event_data['computer'],
                    log_type='sysmon',
                    severity=LogSeverity.INFO,
                    message=f"Sysmon Event {event_data['event_id']}",
                    data=event_data
                )
            
            # Parse event-specific data based on EventID
            try:
                if event.EventID == 1 and len(string_inserts) >= 10:  # Process creation
                    event_data.update({
                        'process_id': string_inserts[3] if len(string_inserts) > 3 else 'N/A',
                        'process_guid': string_inserts[1] if len(string_inserts) > 1 else 'N/A',
                        'process_name': string_inserts[8] if len(string_inserts) > 8 else 'N/A',
                        'command_line': string_inserts[9] if len(string_inserts) > 9 else 'N/A',
                        'parent_process_id': string_inserts[4] if len(string_inserts) > 4 else 'N/A',
                        'parent_process_name': string_inserts[5] if len(string_inserts) > 5 else 'N/A'
                    })
                    message = f"Process created: {event_data.get('process_name', 'N/A')} (PID: {event_data.get('process_id', 'N/A')})"
                elif event.EventID == 3 and len(string_inserts) >= 14:  # Network connection
                    event_data.update({
                        'process_id': string_inserts[3] if len(string_inserts) > 3 else 'N/A',
                        'process_name': string_inserts[8] if len(string_inserts) > 8 else 'N/A',
                        'source_ip': string_inserts[9] if len(string_inserts) > 9 else 'N/A',
                        'source_port': string_inserts[10] if len(string_inserts) > 10 else 'N/A',
                        'destination_ip': string_inserts[11] if len(string_inserts) > 11 else 'N/A',
                        'destination_port': string_inserts[12] if len(string_inserts) > 12 else 'N/A',
                        'protocol': string_inserts[13] if len(string_inserts) > 13 else 'N/A'
                    })
                    message = f"Network connection: {event_data.get('source_ip', 'N/A')}:{event_data.get('source_port', 'N/A')} -> {event_data.get('destination_ip', 'N/A')}:{event_data.get('destination_port', 'N/A')} ({event_data.get('protocol', 'N/A')})"
                elif event.EventID == 7 and len(string_inserts) >= 10:  # Image loaded
                    event_data.update({
                        'process_id': string_inserts[3] if len(string_inserts) > 3 else 'N/A',
                        'process_name': string_inserts[8] if len(string_inserts) > 8 else 'N/A',
                        'image_loaded': string_inserts[9] if len(string_inserts) > 9 else 'N/A'
                    })
                    message = f"Image loaded by {event_data.get('process_name', 'N/A')}: {event_data.get('image_loaded', 'N/A')}"
                elif event.EventID == 11 and len(string_inserts) >= 10:  # File creation
                    event_data.update({
                        'process_id': string_inserts[3] if len(string_inserts) > 3 else 'N/A',
                        'process_name': string_inserts[8] if len(string_inserts) > 8 else 'N/A',
                        'target_filename': string_inserts[9] if len(string_inserts) > 9 else 'N/A'
                    })
                    message = f"File created by {event_data.get('process_name', 'N/A')}: {event_data.get('target_filename', 'N/A')}"
                else:
                    # Default message for other event types
                    message = f"Sysmon Event {event_data['event_id']}: {event_data['event_type']}"
                    
            except IndexError as ie:
                self.logger.warning(f"Insufficient data in StringInserts for event {event.EventID}: {ie}")
                message = f"Sysmon Event {event_data['event_id']}: {event_data['event_type']} (Incomplete data)"
            
            # Create and return a LogEntry object
            return LogEntry(
                timestamp=timestamp,
                source='sysmon',
                hostname=event_data['computer'],
                log_type='sysmon',
                severity=LogSeverity.INFO,  # Default to INFO, can be overridden based on event type
                message=message,
                data=event_data
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing Sysmon event: {e}", exc_info=True)
            # Return a minimal LogEntry with error information
            return LogEntry(
                timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                source='sysmon',
                hostname=getattr(event, 'ComputerName', 'N/A') if event else 'N/A',
                log_type='error',
                severity=LogSeverity.ERROR,
                message=f'Error parsing Sysmon event: {str(e)}',
                data={
                    'event_id': getattr(event, 'EventID', 0) if event else 0,
                    'event_type': 'Error',
                    'raw': str(event) if event else 'No event data',
                    'error': str(e)
                }
            )
            
    def _get_sysmon_events(self):
        """Retrieve Sysmon events from the Windows Event Log."""
        if not WINDOWS_AVAILABLE:
            return []
            
        events = []
        hand = None
        
        try:
            # Open the Sysmon event log
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            if not hand:
                logger.warning("Could not open Sysmon event log. Is Sysmon installed?")
                return []
                
            # Get the number of records
            num_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            if num_records == 0:
                return []
                
            # Set up the flags for reading events
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Set a reasonable limit for events to collect
            max_events = getattr(self, 'max_events_per_log', 1000)
            
            # Read events in chunks
            chunk_size = min(100, num_records)
            events_read = 0
            
            while events_read < num_records and len(events) < max_events:
                try:
                    # Read a chunk of events
                    event_chunk = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not event_chunk:
                        break
                        
                    for event in event_chunk:
                        # Skip if we've reached our limit
                        if len(events) >= max_events:
                            break
                            
                        # Skip if we've already seen this event
                        event_id = (event.RecordNumber, event.TimeGenerated.timestamp())
                        if event_id in self._seen_events:
                            continue
                            
                        # Parse the event into a LogEntry object
                        log_entry = self._parse_sysmon_event(event)
                        if log_entry:
                            events.append(log_entry)
                            self._seen_events.add(event_id)
                            
                    events_read += len(event_chunk)
                    
                except pywintypes.error as e:
                    if e.winerror == 1702:  # No more events
                        break
                    logger.warning(f"Error reading Sysmon events: {e}")
                    break
                    
            return events
            
        except Exception as e:
            logger.error(f"Error getting Sysmon events: {e}", exc_info=True)
            return []
            
        finally:
            if hand:
                try:
                    win32evtlog.CloseEventLog(hand)
                except:
                    pass

    def collect(self):
        """Collect Sysmon events."""
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows-specific modules not available. Cannot collect Sysmon events.")
            return []
            
        try:
            # Initialize last_event_time if not set
            if not hasattr(self, 'last_event_time'):
                self.last_event_time = datetime.utcnow() - timedelta(minutes=5)
                
            # Clear previous events
            self.events = []
            
            # Get new events
            new_events = self._get_sysmon_events()
            
            # Update last event time if we got new events
            if new_events:
                # Use the timestamp from the first event (most recent)
                first_event = new_events[0]
                if hasattr(first_event, 'timestamp'):
                    event_time = first_event.timestamp
                    if isinstance(event_time, str):
                        try:
                            # Try to parse the timestamp string to a datetime object
                            event_time = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')
                        except (ValueError, TypeError):
                            # If parsing fails, use current time
                            event_time = datetime.utcnow()
                    self.last_event_time = event_time
                
            # Process and store the events (which are LogEntry objects)
            self.events.extend(new_events)
            
            logger.info(f"Collected {len(self.events)} new Sysmon events")
            return self.events
            
        except Exception as e:
            logger.error(f"Error collecting Sysmon events: {e}", exc_info=True)
            return []
    
    # Sysmon event IDs and their corresponding names
    SYSMON_EVENT_IDS = {
        1: "ProcessCreate",
        2: "FileCreationTime",
        3: "NetworkConnect",
        4: "SysmonServiceStateChange",
        5: "ProcessTerminate",
        6: "DriverLoad",
        7: "ImageLoad",
        8: "CreateRemoteThread",
        9: "RawAccessRead",
        10: "ProcessAccess",
        11: "FileCreate",
        12: "RegistryEventObjectCreateAndDelete",
        13: "RegistryEventValueSet",
        14: "RegistryEventKeyValueRename",
        15: "FileCreateStreamHash",
        16: "SysmonConfigStateChange",
        17: "PipeCreated",
        18: "PipeConnected",
        19: "WmiEventFilter",
        20: "WmiEventConsumer",
        21: "WmiEventConsumerToFilter",
        22: "DNSEvent",
        23: "FileDelete",
        24: "ClipboardChange",
        25: "ProcessTampering",
        26: "FileDeleteDetected",
        27: "FileBlockExecutable",
        28: "FileBlockShredding",
        29: "FileExecutableDetected",
        255: "Error"
    }
    
    # Initialize the event severity mapping in __init__ to avoid circular imports
    def _init_event_severity(self):
        """Initialize the event severity mapping with LogSeverity enums."""
        from ..agent import LogSeverity
        
        self.EVENT_SEVERITY = {
            "NetworkConnect": LogSeverity.INFO,
            "ProcessCreate": LogSeverity.INFO,
            "FileCreate": LogSeverity.INFO,
            "FileDelete": LogSeverity.WARNING,
            "ProcessTerminate": LogSeverity.INFO,
            "ImageLoad": LogSeverity.INFO,
            "CreateRemoteThread": LogSeverity.WARNING,
            "RawAccessRead": LogSeverity.WARNING,
            "ProcessAccess": LogSeverity.WARNING,
            "RegistryEvent": LogSeverity.INFO,
            "FileCreateStreamHash": LogSeverity.INFO,
            "PipeCreated": LogSeverity.INFO,
            "PipeConnected": LogSeverity.INFO,
            "WmiEvent": LogSeverity.WARNING,
            "DNSEvent": LogSeverity.INFO,
            "FileDeleteDetected": LogSeverity.WARNING,
            "FileBlockExecutable": LogSeverity.WARNING,
            "FileBlockShredding": LogSeverity.WARNING,
            "FileExecutableDetected": LogSeverity.WARNING,
            "Error": LogSeverity.ERROR
        }
    
    def __init__(self, **kwargs):
        """Initialize the Sysmon collector."""
        super().__init__(name="Sysmon", **kwargs)
        
        # Set to track seen events to avoid duplicates
        self._seen_events: Set[Tuple[str, int]] = set()
        self._last_cleanup = time.time()
        
        # Maximum number of events to collect per cycle
        self.max_events = kwargs.get('max_events', 1000)
        
        # Maximum age of events to collect (in seconds)
        self.max_event_age = kwargs.get('max_event_age', 3600)  # 1 hour by default
        
        # Last record number processed
        self.last_record_num = 0
        
        # Flag to track if we've successfully connected to the Sysmon log
        self._initialized = False
        
        # Initialize the event severity mapping
        self._init_event_severity()
        
        # Try to initialize the collector
        self._initialize()
    
    def _initialize(self):
        """Initialize the Sysmon collector."""
        if not WINDOWS_AVAILABLE:
            logger.warning("Windows libraries not available. Install pywin32 to enable this collector.")
            return
        
        try:
            # Check if Sysmon is installed and running
            try:
                hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
                win32evtlog.CloseEventLog(hand)
                self._initialized = True
                logger.info("Initialized Sysmon collector")
            except Exception as e:
                logger.warning(f"Sysmon log not found or not accessible: {e}")
                
        except Exception as e:
            logger.error(f"Failed to initialize Sysmon collector: {e}", exc_info=True)
    
    def start(self):
        """Start the collector."""
        if not self._initialized:
            logger.warning("Sysmon collector not properly initialized")
            return
            
        super().start()
        
        # Get the current maximum record number
        try:
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if events:
                self.last_record_num = events[0].RecordNumber
            win32evtlog.CloseEventLog(hand)
            logger.debug(f"Initialized Sysmon collector at record {self.last_record_num}")
        except Exception as e:
            logger.error(f"Failed to get initial Sysmon record number: {e}")
    
    def _collect(self):
        """Collect events from the Sysmon log."""
        if not self._initialized or not self.running:
            return
        
        try:
            # Clean up the seen events set periodically to prevent memory leaks
            self._cleanup_seen_events()
            
            # Open the Sysmon event log
            hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
            
            # Set up the flags for reading new events
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            
            # Read events starting from the last record we processed
            events = win32evtlog.ReadEventLog(hand, flags, self.last_record_num)
            if not events:
                win32evtlog.CloseEventLog(hand)
                return
            
            # Process the events
            events_collected = 0
            for event in events:
                # Skip if we've already seen this event
                event_id = ("sysmon", event.RecordNumber)
                if event_id in self._seen_events:
                    continue
                
                # Skip if we've reached our limit for this collection cycle
                if events_collected >= self.max_events:
                    logger.warning("Reached maximum events per cycle limit for Sysmon")
                    break
                
                # Parse the event into a LogEntry object
                log_entry = self._parse_sysmon_event(event)
                if log_entry:
                    # Add the log entry's dictionary representation to the buffer
                    self._add_log(log_entry.to_dict())
                    events_collected += 1
                
                # Update the last record number
                self.last_record_num = max(self.last_record_num, event.RecordNumber)
                
                # Add to seen events
                self._seen_events.add(event_id)
            
            if events_collected > 0:
                logger.debug(f"Collected {events_collected} new events from Sysmon")
                
        except Exception as e:
            logger.error(f"Error collecting Sysmon events: {e}", exc_info=True)
            
        finally:
            if hand:
                try:
                    win32evtlog.CloseEventLog(hand)
                except:
                    pass
    
    def _parse_sysmon_event(self, event) -> Optional['LogEntry']:
        """Parse a Sysmon event into a LogEntry object.
        
        Args:
            event: The Windows Event Log event from Sysmon
            
        Returns:
            LogEntry containing the parsed event data, or None if the event should be skipped
        """
        # Import LogEntry and LogSeverity here to avoid circular imports
        from ..agent import LogEntry, LogSeverity
        
        try:
            # Get the event ID and name
            event_id = event.EventID
            event_name = self.SYSMON_EVENT_IDS.get(event_id, f"Event_{event_id}")
            
            # Get the event data
            event_data = self._parse_event_data(event)
            if not event_data:
                return None
            
            # Get the event time
            event_time = self._filetime_to_iso8601(event.TimeGenerated)
            
            # Get the computer name
            computer = getattr(event, 'ComputerName', 'Unknown')
            
            # Get the event severity
            severity = self._get_event_severity(event_name)
            if not isinstance(severity, LogSeverity):
                severity = LogSeverity.INFO  # Default to INFO if severity is not a LogSeverity
            
            # Create the log message
            message = f"[{event_name}] {self._get_event_summary(event_name, event_data)}"
            
            # Create the data dictionary
            data = {
                'event_id': event_id,
                'event_name': event_name,
                'record_number': event.RecordNumber,
                'source_name': 'Microsoft-Windows-Sysmon',
                'computer': computer,
                'event_data': event_data
            }
            
            # Create and return a LogEntry object
            return LogEntry(
                timestamp=event_time,
                source='sysmon',
                hostname=computer,
                log_type='security',
                severity=severity,
                message=message,
                data=data
            )
            
        except Exception as e:
            logger.error(f"Error parsing Sysmon event: {e}", exc_info=True)
            return None
    
    def _parse_event_data(self, event) -> Optional[Dict[str, Any]]:
        """Parse the event data from a Sysmon event."""
        try:
            # Check if this is an event with XML data
            if hasattr(event, 'StringInserts') and event.StringInserts:
                # For Sysmon events, the event data is in the StringInserts
                data = {}
                for i, value in enumerate(event.StringInserts):
                    if value is not None:
                        data[f'param{i+1}'] = str(value)
                return data
            
            # Try to parse the event data as XML
            if hasattr(event, 'StringInserts') and len(event.StringInserts) > 0:
                # Some Sysmon events have XML data in the first string insert
                try:
                    xml_data = event.StringInserts[0]
                    if xml_data and '<EventData>' in xml_data:
                        root = ET.fromstring(f"<root>{xml_data}</root>")
                        data = {}
                        for elem in root.findall('.//Data'):
                            name = elem.get('Name')
                            if name:
                                data[name] = elem.text or ''
                        return data
                except Exception as e:
                    logger.debug(f"Failed to parse XML data: {e}")
            
            # Fall back to basic event data
            return {
                'EventID': event.EventID,
                'EventType': event.EventType,
                'EventCategory': getattr(event, 'EventCategory', None),
                'SourceName': getattr(event, 'SourceName', ''),
                'Strings': [str(s) for s in getattr(event, 'StringInserts', []) if s is not None]
            }
            
        except Exception as e:
            logger.error(f"Error parsing event data: {e}", exc_info=True)
            return None
    
    def _get_event_summary(self, event_name: str, event_data: Dict[str, Any]) -> str:
        """Generate a summary message for a Sysmon event."""
        try:
            if event_name == 'ProcessCreate' and 'CommandLine' in event_data:
                return f"Process created: {event_data.get('CommandLine', '')}"
            
            elif event_name == 'NetworkConnect' and 'DestinationIp' in event_data:
                return (f"Network connection to {event_data.get('DestinationIp', '')}:"
                        f"{event_data.get('DestinationPort', '')} "
                        f"({event_data.get('Protocol', '')})")
            
            elif event_name == 'FileCreate' and 'TargetFilename' in event_data:
                return f"File created: {event_data.get('TargetFilename', '')}"
            
            elif event_name == 'FileDelete' and 'TargetFilename' in event_data:
                return f"File deleted: {event_data.get('TargetFilename', '')}"
            
            elif event_name == 'ImageLoad' and 'ImageLoaded' in event_data:
                return f"Image loaded: {event_data.get('ImageLoaded', '')}"
            
            elif event_name == 'CreateRemoteThread' and 'TargetProcessId' in event_data:
                return (f"Remote thread created in process {event_data.get('TargetProcessId', '')} "
                        f"({event_data.get('TargetProcess', '')})")
            
            # Default summary
            return f"{event_name} event occurred"
            
        except Exception as e:
            logger.warning(f"Error generating event summary: {e}")
            return f"{event_name} event (details unavailable)"
    
    def _get_event_severity(self, event_name: str) -> 'LogSeverity':
        """Get the severity level for a Sysmon event.
        
        Args:
            event_name: The name of the event to get the severity for
            
        Returns:
            LogSeverity: The severity level for the event
        """
        # Import LogSeverity here to avoid circular imports
        from ..agent import LogSeverity
        
        # Try to find a matching severity for this event
        for key, severity in self.EVENT_SEVERITY.items():
            if key in event_name:
                if isinstance(severity, LogSeverity):
                    return severity
                return LogSeverity.INFO  # Default to INFO if severity is not a LogSeverity
        
        # Default to INFO for unknown events
        return LogSeverity.INFO
    
    def _cleanup_seen_events(self):
        """Clean up the set of seen events to prevent memory leaks."""
        now = time.time()
        if now - self._last_cleanup < 300:  # Clean up every 5 minutes
            return
            
        logger.debug("Cleaning up seen events set in Sysmon collector")
        self._last_cleanup = now
        
        # If the set is getting too large, clear it and reset the last record number
        if len(self._seen_events) > 50000:  # 50K events
            logger.warning("Seen events set too large in Sysmon collector, resetting")
            self._seen_events.clear()
            self.last_record_num = 0
    
    @staticmethod
    def _filetime_to_iso8601(filetime) -> str:
        """Convert a Windows filetime to an ISO 8601 formatted string."""
        if not filetime:
            return ''
            
        if hasattr(filetime, 'timetuple'):
            # Already a datetime object
            return filetime.isoformat() + 'Z'
            
        try:
            # Convert from Windows filetime (100-nanosecond intervals since 1601-01-01)
            # to Unix timestamp (seconds since 1970-01-01)
            timestamp = (filetime - 116444736000000000) // 10000000
            dt = datetime.utcfromtimestamp(timestamp)
            return dt.isoformat() + 'Z'
        except (ValueError, OverflowError):
            return ''
