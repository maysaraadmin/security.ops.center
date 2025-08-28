"""
Windows Event Log Collector for SIEM.
Collects logs from Windows Event Log.
"""
import logging
import time
from typing import Dict, List, Any, Optional, Generator
from datetime import datetime
import xml.etree.ElementTree as ET

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    from pywintypes import error as pywinerror
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

from .base import BaseCollector

class WindowsEventLogCollector(BaseCollector):
    """Collects logs from Windows Event Log."""
    
    def _setup(self) -> None:
        """Set up the Windows Event Log collector."""
        if not WINDOWS_AVAILABLE:
            raise ImportError("Windows Event Log collection requires pywin32 package")
            
        self.config.setdefault('log_names', ['Application', 'Security', 'System'])
        self.config.setdefault('event_types', ['Error', 'Warning', 'Information', 'Success Audit', 'Failure Audit'])
        self.config.setdefault('poll_interval', 5)  # seconds
        self.config.setdefault('bookmark_file', 'winevt_bookmark.xml')
        
        self.handles = {}
        self.bookmarks = {}
        self.last_run = {}
        self._setup_event_handles()
    
    def _setup_event_handles(self) -> None:
        """Set up handles for each event log."""
        for log_name in self.config['log_names']:
            try:
                # Open the event log
                handle = win32evtlog.OpenEventLog(None, log_name)
                self.handles[log_name] = handle
                self.last_run[log_name] = 0
                
                # Try to load bookmark
                self._load_bookmark(log_name)
                
                self.logger.info(f"Successfully opened event log: {log_name}")
                
            except Exception as e:
                self.logger.error(f"Failed to open event log {log_name}: {e}")
    
    def _load_bookmark(self, log_name: str) -> None:
        """Load bookmark for a log to resume from last position."""
        try:
            with open(f"{self.config['bookmark_file']}.{log_name}", 'r') as f:
                bookmark_xml = f.read()
                if bookmark_xml:
                    self.bookmarks[log_name] = win32evtlog.EvtCreateBookmark(bookmark_xml)
                    self.logger.info(f"Loaded bookmark for {log_name}")
        except (FileNotFoundError, pywinerror) as e:
            self.logger.debug(f"No bookmark found for {log_name}, starting from current events")
    
    def _save_bookmark(self, log_name: str, event_handle: int) -> None:
        """Save bookmark for a log to resume later."""
        try:
            bookmark = win32evtlog.EvtCreateBookmark(None)
            win32evtlog.EvtUpdateBookmark(bookmark, event_handle)
            bookmark_xml = win32evtlog.EvtRender(bookmark, win32evtlog.EvtRenderBookmark)
            
            with open(f"{self.config['bookmark_file']}.{log_name}", 'w') as f:
                f.write(bookmark_xml)
                
        except Exception as e:
            self.logger.error(f"Failed to save bookmark for {log_name}: {e}")
    
    def collect(self) -> Generator[Dict[str, Any], None, None]:
        """Collect events from Windows Event Logs."""
        while True:
            try:
                for log_name, handle in list(self.handles.items()):
                    try:
                        # Get new events
                        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                        
                        if log_name in self.bookmarks:
                            # Use bookmark to get events since last read
                            events = win32evtlog.EvtNext(handle, 1000, self.bookmarks[log_name])
                        else:
                            # No bookmark, get recent events
                            events = win32evtlog.ReadEventLog(handle, flags, 0)
                        
                        event_count = 0
                        for event in events:
                            event_count += 1
                            try:
                                # Convert event to a structured format
                                event_data = self._parse_event(event, log_name)
                                if event_data:
                                    yield event_data
                                
                                # Update bookmark after successful processing
                                self._save_bookmark(log_name, event)
                                
                            except Exception as e:
                                self.logger.error(f"Error processing event: {e}", exc_info=True)
                        
                        if event_count > 0:
                            self.logger.debug(f"Processed {event_count} events from {log_name}")
                            
                    except pywinerror as e:
                        if e.winerror == 15007:  # No more events
                            pass
                        else:
                            self.logger.error(f"Error reading from {log_name}: {e}")
                    except Exception as e:
                        self.logger.error(f"Unexpected error processing {log_name}: {e}", exc_info=True)
                
                # Wait before next poll
                time.sleep(self.config['poll_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in collection loop: {e}", exc_info=True)
                time.sleep(10)  # Wait before retrying
    
    def _parse_event(self, event: Any, log_name: str) -> Optional[Dict[str, Any]]:
        """Parse a Windows Event Log entry into a structured format."""
        try:
            # Get event data
            event_id = win32evtlogutil.SafeFormatMessage(event, log_name)
            event_xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            
            # Parse XML
            root = ET.fromstring(event_xml)
            ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Extract event data
            system = root.find('evt:System', ns)
            if system is None:
                return None
                
            event_data = {
                '@timestamp': datetime.utcnow().isoformat() + 'Z',
                'log': {
                    'level': self._get_event_level(system.find('evt:Level', ns).text),
                    'logger': log_name,
                    'original': event_xml
                },
                'event': {
                    'kind': 'event',
                    'category': ['host'],
                    'type': ['info'],
                    'code': system.find('evt:EventID', ns).text if system.find('evt:EventID', ns) is not None else None,
                    'provider': system.find('evt:Provider', ns).get('Name') if system.find('evt:Provider', ns) is not None else None,
                    'created': system.find('evt:TimeCreated', ns).get('SystemTime') if system.find('evt:TimeCreated', ns) is not None else None
                },
                'winlog': {
                    'channel': log_name,
                    'event_id': system.find('evt:EventID', ns).text if system.find('evt:EventID', ns) is not None else None,
                    'provider_name': system.find('evt:Provider', ns).get('Name') if system.find('evt:Provider', ns) is not None else None,
                    'record_id': system.find('evt:EventRecordID', ns).text if system.find('evt:EventRecordID', ns) is not None else None,
                    'computer_name': system.find('evt:Computer', ns).text if system.find('evt:Computer', ns) is not None else None,
                    'level': system.find('evt:Level', ns).text if system.find('evt:Level', ns) is not None else None,
                },
                'message': event_id.strip() if event_id else None
            }
            
            # Add event data
            event_data_nodes = root.findall('.//evt:EventData/evt:Data', ns)
            if event_data_nodes:
                event_data['winlog']['event_data'] = {}
                for data in event_data_nodes:
                    name = data.get('Name')
                    value = data.text
                    if name:
                        event_data['winlog']['event_data'][name] = value
            
            # Add user data if available
            security = system.find('evt:Security', ns)
            if security is not None:
                user_sid = security.get('UserID')
                if user_sid:
                    event_data['user'] = {
                        'identifier': user_sid
                    }
            
            return event_data
            
        except Exception as e:
            self.logger.error(f"Error parsing event: {e}", exc_info=True)
            return None
    
    def _get_event_level(self, level: str) -> str:
        """Convert Windows Event Log level to standard log level."""
        level_map = {
            '0': 'fatal',
            '1': 'error',
            '2': 'warn',
            '3': 'info',
            '4': 'debug',
            '5': 'trace'
        }
        return level_map.get(level, 'info')
    
    def cleanup(self) -> None:
        """Clean up resources."""
        for handle in self.handles.values():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                self.logger.error(f"Error closing event log handle: {e}")
        
        self.handles = {}
        self.bookmarks = {}
