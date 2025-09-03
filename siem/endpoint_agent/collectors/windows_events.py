"""
Windows Event Log Collector
--------------------------
Collects logs from the Windows Event Log.
"""
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from .base import BaseCollector

logger = logging.getLogger('siem_agent.collector.windows_events')

try:
    import win32evtlog
    import win32con
    import win32security
    import pywintypes
    WINDOWS_EVENT_LOGS_AVAILABLE = True
except ImportError:
    WINDOWS_EVENT_LOGS_AVAILABLE = False

class WindowsEventCollector(BaseCollector):
    """Collects logs from Windows Event Log."""
    
    def __init__(self, log_types: Optional[List[str]] = None, **kwargs):
        """Initialize the Windows Event Log collector.
        
        Args:
            log_types: List of event log types to collect (e.g., ['Security', 'System', 'Application'])
            **kwargs: Additional arguments passed to the base class
        """
        super().__init__(name="WindowsEventLog", **kwargs)
        
        # Default log types to collect if not specified
        self.log_types = log_types or ['Security', 'System', 'Application']
        
        # Store collected events
        self.events = []
        
        # Dictionary to store the last event ID for each log type
        self.last_event_ids = {log_type: 0 for log_type in self.log_types}
        
        # Dictionary to store the last record number for each log type
        self.last_record_nums = {log_type: 0 for log_type in self.log_types}
        
        # Dictionary to store the last time we queried each log type
        self.last_query_times = {log_type: 0 for log_type in self.log_types}
        
        # Set to track seen events to avoid duplicates
        self._seen_events = set()
        self._last_cleanup = time.time()
        
        # Maximum number of events to collect per log type per collection cycle
        self.max_events_per_log = kwargs.get('max_events_per_log', 1000)
        
        # Maximum age of events to collect (in seconds)
        self.max_event_age = kwargs.get('max_event_age', 3600)  # 1 hour by default
        
        # Flag to track if we've successfully connected to the event log
        self._initialized = False
        
        # Try to initialize the collector
        self._initialize()
    
    def collect(self):
        """Collect Windows Event Logs."""
        if not WINDOWS_EVENT_LOGS_AVAILABLE:
            logger.warning("Windows Event Log modules not available. Cannot collect Windows events.")
            return []
            
        try:
            # Clear previous events
            self.events = []
            
            # Process each log type
            for log_type in self.log_types:
                try:
                    self._process_log_type(log_type)
                except Exception as e:
                    logger.error(f"Error processing {log_type} log: {e}", exc_info=True)
            
            # Clean up old seen events periodically
            self._cleanup_seen_events()
            
            logger.info(f"Collected {len(self.events)} new Windows events")
            return self.events
            
        except Exception as e:
            logger.error(f"Error collecting Windows Event Logs: {e}", exc_info=True)
            return []
        
        # Maximum number of events to collect per log type per collection cycle
        self.max_events_per_log = kwargs.get('max_events_per_log', 1000)
        
        # Maximum age of events to collect (in seconds)
        self.max_event_age = kwargs.get('max_event_age', 3600)  # 1 hour by default
        
        # Flag to track if we've successfully connected to the event log
        self._initialized = False
        
        # Try to initialize the collector
        self._initialize()
    
    def _initialize(self):
        """Initialize the Windows Event Log collector."""
        if not WINDOWS_EVENT_LOGS_AVAILABLE:
            logger.warning("Windows Event Log libraries not available. Install pywin32 to enable this collector.")
            return
        
        try:
            # Test access to the event log
            for log_type in self.log_types[:]:
                try:
                    hand = win32evtlog.OpenEventLog(None, log_type)
                    win32evtlog.CloseEventLog(hand)
                except Exception as e:
                    logger.warning(f"Cannot access {log_type} log: {e}")
                    self.log_types.remove(log_type)
            
            if not self.log_types:
                logger.error("No accessible Windows Event Logs found")
                return
                
            self._initialized = True
            logger.info(f"Initialized Windows Event Log collector for logs: {', '.join(self.log_types)}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Windows Event Log collector: {e}", exc_info=True)
    
    def start(self):
        """Start the collector."""
        if not self._initialized:
            logger.warning("Windows Event Log collector not properly initialized")
            return
            
        super().start()
        
        # Initialize last query times to now
        now = time.time()
        self.last_query_times = {log_type: now for log_type in self.log_types}
        
        # Get the current maximum record number for each log type
        for log_type in self.log_types:
            try:
                hand = win32evtlog.OpenEventLog(None, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    self.last_record_nums[log_type] = events[0].RecordNumber
                win32evtlog.CloseEventLog(hand)
            except Exception as e:
                logger.warning(f"Failed to get initial record number for {log_type}: {e}")
    
    def _collect(self):
        """Collect events from Windows Event Logs."""
        if not self._initialized or not self.running:
            return
        
        try:
            # Clean up the seen events set periodically to prevent memory leaks
            self._cleanup_seen_events()
            
            # Process each log type
            for log_type in self.log_types:
                self._process_log_type(log_type)
                
        except Exception as e:
            logger.error(f"Error collecting Windows Event Logs: {e}", exc_info=True)
    
    def _process_log_type(self, log_type: str):
        """Process events from a specific log type.
        
        Args:
            log_type: The type of log to process (e.g., 'Security', 'System')
        """
        hand = None
        events_collected = 0
        events = []
        
        try:
            # Open the event log
            hand = win32evtlog.OpenEventLog(None, log_type)
            
            # Get the oldest and newest record numbers
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            newest = win32evtlog.GetNumberOfEventLogRecords(hand) + oldest - 1
            
            # If we haven't seen any records yet, start from the newest
            if self.last_record_nums[log_type] == 0:
                self.last_record_nums[log_type] = oldest
                logger.debug(f"Initialized {log_type} log at record {self.last_record_nums[log_type]}")
                return
                
            # If we're already at the newest record, nothing to do
            if self.last_record_nums[log_type] > newest:
                return
                
            # Read events in chunks
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            
            try:
                # Read events in chunks of 100 or less
                chunk_size = min(100, newest - self.last_record_nums[log_type] + 1)
                if chunk_size <= 0:
                    return
                    
                # Read the events
                events = []
                while len(events) < chunk_size:
                    try:
                        # Try to read a single event at a time to avoid buffer issues
                        event_chunk = win32evtlog.ReadEventLog(
                            hand, 
                            win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ,
                            self.last_record_nums[log_type] + len(events)
                        )
                        
                        if not event_chunk:
                            break
                            
                        events.extend(event_chunk)
                        
                        # Safety check to prevent infinite loops
                        if len(events) >= 1000:
                            logger.warning(f"Reached maximum event chunk size for {log_type}")
                            break
                            
                    except pywintypes.error as e:
                        if e.winerror == 1702:  # No more events
                            break
                        logger.warning(f"Error reading events from {log_type}: {e}")
                        break
                
                if not events:
                    return
                    
                # Update the last record number
                self.last_record_nums[log_type] = events[-1].RecordNumber + 1
                
            except pywintypes.error as e:
                if e.winerror == 1702:  # No more events
                    return
                logger.warning(f"Error reading {log_type} log: {e}")
                return
            
            # Process the events
            for event in events:
                # Skip if we've already seen this event
                event_id = (log_type, event.RecordNumber)
                if event_id in self._seen_events:
                    continue
                
                # Skip if we've reached our limit for this collection cycle
                if events_collected >= self.max_events_per_log:
                    logger.warning(f"Reached maximum events per log limit for {log_type}")
                    break
                
                # Skip if the event is too old
                event_time = self._filetime_to_datetime(event.TimeGenerated)
                if (datetime.now() - event_time).total_seconds() > self.max_event_age:
                    continue
                
                # Parse the event
                log_entry = self._parse_event(event, log_type)
                if log_entry:
                    # Add the log entry's dictionary representation to the buffer
                    self._add_log(log_entry.to_dict())
                    events_collected += 1
                
                # Update the last record number
                self.last_record_nums[log_type] = max(
                    self.last_record_nums[log_type],
                    event.RecordNumber
                )
                
                # Add to seen events
                self._seen_events.add(event_id)
            
            # Update the last query time
            self.last_query_times[log_type] = time.time()
            
            if events_collected > 0:
                logger.debug(f"Collected {events_collected} new events from {log_type} log")
                
        except Exception as e:
            logger.error(f"Error processing {log_type} log: {e}", exc_info=True)
            
        finally:
            if hand:
                try:
                    win32evtlog.CloseEventLog(hand)
                except:
                    pass
    
    def _parse_event(self, event, log_type: str) -> Optional[Dict[str, Any]]:
        """Parse a Windows Event Log event into a LogEntry object.
        
        Args:
            event: The Windows Event Log event
            log_type: The type of log the event came from
            
        Returns:
            LogEntry object containing the parsed event data, or None if the event should be skipped
        """
        try:
            # Import LogEntry and LogSeverity here to avoid circular imports
            from ..agent import LogEntry, LogSeverity
            
            # Get the event data
            event_data = {}
            
            # Basic event information
            event_data['event_id'] = event.EventID & 0xFFFF  # Lower 16 bits only
            event_data['event_type'] = self._get_event_type_name(event.EventType)
            event_data['source_name'] = event.SourceName
            event_data['computer'] = event.ComputerName
            event_data['record_number'] = event.RecordNumber
            event_data['time_generated'] = self._filetime_to_iso8601(event.TimeGenerated)
            event_data['time_written'] = self._filetime_to_iso8601(event.TimeWritten)
            
            # Event category and strings
            if hasattr(event, 'Category') and event.Category:
                event_data['category'] = str(event.Category)
                
            if hasattr(event, 'CategoryString') and event.CategoryString:
                event_data['category_string'] = event.CategoryString
                
            if hasattr(event, 'EventCategory') and event.EventCategory:
                event_data['event_category'] = event.EventCategory
            
            # Event data
            if hasattr(event, 'Data') and event.Data:
                if isinstance(event.Data, bytes):
                    try:
                        event_data['data'] = event.Data.hex()
                    except:
                        event_data['data'] = str(event.Data)
                else:
                    event_data['data'] = str(event.Data)
            
            # Event strings
            if hasattr(event, 'StringInserts') and event.StringInserts:
                event_data['strings'] = [str(s) for s in event.StringInserts if s is not None]
            
            # SID information
            if hasattr(event, 'Sid') and event.Sid:
                try:
                    sid_name, sid_domain, sid_type = win32security.LookupAccountSid(None, event.Sid)
                    event_data['sid'] = {
                        'sid': win32security.ConvertSidToStringSid(event.Sid),
                        'name': sid_name,
                        'domain': sid_domain,
                        'type': sid_type
                    }
                except Exception as e:
                    event_data['sid'] = str(event.Sid)
            
            # Create the message
            message = f"[{event_data['source_name']}] Event ID {event_data['event_id']}"
            if 'strings' in event_data and event_data['strings']:
                message = ' | '.join(str(s) for s in event_data['strings'] if s)
            
            # Create the LogEntry object
            log_entry = LogEntry(
                timestamp=event_data['time_generated'],
                source='windows_event_log',
                hostname=event_data['computer'],
                log_type=log_type.lower(),
                severity=LogSeverity.INFO,  # Default to INFO, will be updated below
                message=message,
                data=event_data
            )
            
            # Set the appropriate severity
            severity_map = {
                'ERROR': LogSeverity.ERROR,
                'WARNING': LogSeverity.WARNING,
                'INFORMATION': LogSeverity.INFO,
                'SUCCESS': LogSeverity.INFO,
                'AUDIT_SUCCESS': LogSeverity.INFO,
                'AUDIT_FAILURE': LogSeverity.ERROR
            }
            
            log_entry.severity = severity_map.get(event_data['event_type'], LogSeverity.INFO)
            
            return log_entry
            
        except Exception as e:
            logger.error(f"Error parsing event: {e}", exc_info=True)
            return None
    
    def _cleanup_seen_events(self):
        """Clean up the set of seen events to prevent memory leaks."""
        now = time.time()
        if now - self._last_cleanup < 300:  # Clean up every 5 minutes
            return
            
        logger.debug("Cleaning up seen events set")
        self._last_cleanup = now
        
        # If the set is getting too large, clear it and reset the last record numbers
        if len(self._seen_events) > 100000:  # 100K events
            logger.warning("Seen events set too large, resetting")
            self._seen_events.clear()
            self.last_record_nums = {log_type: 0 for log_type in self.log_types}
    
    @staticmethod
    def _get_event_type_name(event_type: int) -> str:
        """Get the name of an event type."""
        event_types = {
            win32con.EVENTLOG_SUCCESS: 'SUCCESS',
            win32con.EVENTLOG_ERROR_TYPE: 'ERROR',
            win32con.EVENTLOG_WARNING_TYPE: 'WARNING',
            win32con.EVENTLOG_INFORMATION_TYPE: 'INFORMATION',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'AUDIT_SUCCESS',
            win32con.EVENTLOG_AUDIT_FAILURE: 'AUDIT_FAILURE'
        }
        return event_types.get(event_type, f'UNKNOWN ({event_type})')
    
    @staticmethod
    def _get_severity(event_type: str) -> str:
        """Map Windows event type to SIEM severity."""
        severity_map = {
            'ERROR': 'ERROR',
            'WARNING': 'WARNING',
            'AUDIT_FAILURE': 'WARNING',
            'AUDIT_SUCCESS': 'INFO',
            'INFORMATION': 'INFO',
            'SUCCESS': 'INFO'
        }
        return severity_map.get(event_type.upper(), 'INFO')
    
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
    
    @staticmethod
    def _filetime_to_datetime(filetime) -> datetime:
        """Convert a Windows filetime to a datetime object."""
        if not filetime:
            return datetime.min
            
        if hasattr(filetime, 'timetuple'):
            # Already a datetime object
            return filetime
            
        try:
            # Convert from Windows filetime to datetime
            timestamp = (filetime - 116444736000000000) // 10000000
            return datetime.utcfromtimestamp(timestamp)
        except (ValueError, OverflowError):
            return datetime.min
