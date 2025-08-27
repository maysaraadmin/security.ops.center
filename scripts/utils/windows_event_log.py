"""
Windows Event Log Source for Enhanced Log Collector.
"""

import os
import time
import logging
import win32evtlog
import win32evtlogutil
import win32con
import pythoncom
import pywintypes
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from threading import Thread, Event

from ..core.enhanced_log_collector import LogSource, LogSourceType, LogFormat

class WindowsEventLogSource(LogSource):
    """Log source for Windows Event Logs."""
    
    def __init__(self, source_id: str, log_name: str = "Security", **kwargs):
        """Initialize the Windows Event Log source.
        
        Args:
            source_id: Unique identifier for this source
            log_name: Name of the Windows Event Log (e.g., 'Security', 'System', 'Application')
            **kwargs: Additional configuration options
        """
        config = {
            'log_name': log_name,
            'event_id_filters': kwargs.get('event_id_filters', []),  # List of event IDs to include (empty for all)
            'level_filters': kwargs.get('level_filters', []),  # List of levels to include (e.g., [win32con.EVENTLOG_INFORMATION_TYPE])
            'query': kwargs.get('query', '*'),  # XPath query for filtering events
            'bookmark': kwargs.get('bookmark', True),  # Whether to use bookmarks to resume from last position
            'bookmark_file': kwargs.get('bookmark_file', f'bookmark_{log_name.lower()}.json')
        }
        super().__init__(source_id, LogSourceType.WINDOWS_EVENT, config)
        
        self.log_name = log_name
        self.handles = {}
        self.bookmark = None
        self._stop_event = Event()
        self._bookmark_modified = False
        self._bookmark_lock = Lock()
        
        # Initialize COM for MTA (Multi-Threaded Apartment)
        pythoncom.CoInitialize()
    
    def start(self):
        """Start collecting Windows Event Logs."""
        super().start()
        
        try:
            # Load bookmark if exists
            if self.config['bookmark']:
                self._load_bookmark()
            
            # Start the event log reader thread
            self.reader_thread = Thread(
                target=self._read_events_loop,
                name=f"WinEventLog-{self.log_name}",
                daemon=True
            )
            self.reader_thread.start()
            
            # Start bookmark saver thread if using bookmarks
            if self.config['bookmark']:
                self.bookmark_thread = Thread(
                    target=self._bookmark_saver_loop,
                    name=f"BookmarkSaver-{self.log_name}",
                    daemon=True
                )
                self.bookmark_thread.start()
                
            self.logger.info(f"Started Windows Event Log source for {self.log_name}")
            
        except Exception as e:
            self.logger.error(f"Failed to start Windows Event Log source: {e}")
            self.stop()
    
    def stop(self):
        """Stop collecting Windows Event Logs."""
        self._stop_event.set()
        
        # Save final bookmark
        if self.config['bookmark'] and self._bookmark_modified:
            self._save_bookmark()
        
        # Close all handles
        for handle in self.handles.values():
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception as e:
                self.logger.warning(f"Error closing event log handle: {e}")
        
        # Uninitialize COM
        pythoncom.CoUninitialize()
        
        super().stop()
    
    def _get_handle(self, log_name: str = None):
        """Get or create a handle to an event log.
        
        Args:
            log_name: Name of the event log
            
        Returns:
            Handle to the event log
        """
        log_name = log_name or self.log_name
        
        if log_name not in self.handles:
            try:
                self.handles[log_name] = win32evtlog.OpenEventLog(None, log_name)
                self.logger.debug(f"Opened handle to {log_name} event log")
            except Exception as e:
                self.logger.error(f"Failed to open {log_name} event log: {e}")
                return None
                
        return self.handles[log_name]
    
    def _read_events_loop(self):
        """Main loop for reading events."""
        while not self._stop_event.is_set():
            try:
                # Get new events
                events = self._read_new_events()
                
                # Process events
                for event in events:
                    self._process_event(event)
                
                # Sleep to prevent high CPU usage
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error in event reader loop: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _read_new_events(self):
        """Read new events from the event log."""
        events = []
        
        try:
            # If using bookmarks and we have a saved position, use it
            if self.config['bookmark'] and self.bookmark:
                events = self._read_events_with_bookmark()
            else:
                # Otherwise, just get the most recent events
                handle = self._get_handle()
                if not handle:
                    return []
                    
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = list(win32evtlog.ReadEventLog(handle, flags, 0))
                
                # Only keep the most recent event if we're not using bookmarks
                events = [events[0]] if events else []
                
        except pywintypes.error as e:
            if e.winerror == 1500:  # Event log has been cleared
                self.logger.warning(f"Event log {self.log_name} has been cleared, resetting position")
                self.bookmark = None
            else:
                self.logger.error(f"Error reading from event log: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error reading events: {e}")
            
        return events
    
    def _read_events_with_bookmark(self):
        """Read events using a bookmark to resume from the last position."""
        if not self.bookmark:
            return []
            
        # Create a new event log query
        query = f'<QueryList>\
            <Query Id="0" Path="{self.log_name}">\
                <Select Path="{self.log_name}">{self.config["query"]}</Select>\
            </Query>\
        </QueryList>'
        
        # Create a new event log subscription
        subscription = None
        try:
            # Use the bookmark to resume from the last position
            subscription = win32evtlog.EvtSubscribe(
                self.log_name,
                win32evtlog.EvtSubscribeStartAfterBookmark,
                Bookmark=self.bookmark,
                Query=query
            )
            
            # Read events
            events = []
            while True:
                try:
                    events.extend(win32evtlog.EvtNext(subscription, 10, 1000))
                except pywintypes.error as e:
                    if e.winerror == 0x1038B:  # ERROR_NO_MORE_ITEMS
                        break
                    raise
                    
            return events
            
        finally:
            if subscription:
                win32evtlog.EvtClose(subscription)
    
    def _process_event(self, event):
        """Process a single Windows Event Log event.
        
        Args:
            event: The Windows Event Log event
        """
        try:
            # Convert the event to a dictionary
            event_dict = self._event_to_dict(event)
            
            # Create the log entry
            entry = {
                '@timestamp': datetime.utcnow().isoformat(),
                'source': self.source_id,
                'log_name': self.log_name,
                'event': event_dict,
                'raw': str(event)
            }
            
            # Update bookmark if enabled
            if self.config['bookmark']:
                self._update_bookmark(event)
            
            # Notify callbacks
            self._notify_callbacks(entry)
            
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
    
    def _event_to_dict(self, event):
        """Convert a Windows Event Log event to a dictionary.
        
        Args:
            event: The Windows Event Log event
            
        Returns:
            Dictionary representation of the event
        """
        try:
            # Get basic event properties
            event_dict = {
                'record_id': event.RecordNumber,
                'time_generated': event.TimeGenerated.Format(),
                'time_written': event.TimeWritten.Format(),
                'event_id': event.EventID & 0xFFFF,  # Mask off the high word for the event ID
                'event_type': self._get_event_type_name(event.EventType),
                'event_category': event.EventCategory,
                'source_name': event.SourceName,
                'computer_name': event.ComputerName,
                'user': event.StringInserts[0] if event.StringInserts and len(event.StringInserts) > 0 else None,
                'strings': event.StringInserts,
                'data': event.Data
            }
            
            # Try to get the event message
            try:
                event_dict['message'] = win32evtlogutil.SafeFormatMessage(event, self.log_name)
            except (AttributeError, TypeError, ValueError, WindowsError) as e:
                self.logger.debug(f"Could not format event message: {e}")
                event_dict['message'] = ' '.join(str(s) for s in event.StringInserts) if event.StringInserts else ''
            
            return event_dict
            
        except Exception as e:
            self.logger.warning(f"Error converting event to dictionary: {e}")
            return {'error': str(e), 'raw_event': str(event)}
    
    def _get_event_type_name(self, event_type):
        """Get the name of an event type."""
        event_types = {
            win32con.EVENTLOG_SUCCESS: 'SUCCESS',
            win32con.EVENTLOG_ERROR_TYPE: 'ERROR',
            win32con.EVENTLOG_WARNING_TYPE: 'WARNING',
            win32con.EVENTLOG_INFORMATION_TYPE: 'INFORMATION',
            win32con.EVENTLOG_AUDIT_SUCCESS: 'AUDIT_SUCCESS',
            win32con.EVENTLOG_AUDIT_FAILURE: 'AUDIT_FAILURE'
        }
        return event_types.get(event_type, f'UNKNOWN({event_type})')
    
    def _update_bookmark(self, event):
        """Update the bookmark to the current event."""
        try:
            # Create a new bookmark
            self.bookmark = win32evtlog.EvtCreateBookmark(None)
            
            # Update the bookmark to point to this event
            win32evtlog.EvtUpdateBookmark(self.bookmark, event)
            self._bookmark_modified = True
            
        except Exception as e:
            self.logger.error(f"Error updating bookmark: {e}")
    
    def _bookmark_saver_loop(self):
        """Periodically save the bookmark to disk."""
        while not self._stop_event.is_set():
            try:
                # Save bookmark every 60 seconds if modified
                time.sleep(60)
                
                if self._bookmark_modified:
                    self._save_bookmark()
                    
            except Exception as e:
                self.logger.error(f"Error in bookmark saver loop: {e}")
    
    def _load_bookmark(self):
        """Load the bookmark from disk."""
        try:
            if os.path.exists(self.config['bookmark_file']):
                with open(self.config['bookmark_file'], 'rb') as f:
                    bookmark_xml = f.read().decode('utf-8')
                    self.bookmark = win32evtlog.EvtCreateBookmark(bookmark_xml)
                    self.logger.info(f"Loaded bookmark from {self.config['bookmark_file']}")
                    
        except Exception as e:
            self.logger.error(f"Error loading bookmark: {e}")
            self.bookmark = None
    
    def _save_bookmark(self):
        """Save the bookmark to disk."""
        if not self.bookmark or not self._bookmark_modified:
            return
            
        try:
            # Get the bookmark XML
            bookmark_xml = win32evtlog.EvtRender(self.bookmark, win32evtlog.EvtRenderBookmark)
            
            # Save to file
            with open(self.config['bookmark_file'], 'wb') as f:
                f.write(bookmark_xml)
                
            self._bookmark_modified = False
            self.logger.debug(f"Saved bookmark to {self.config['bookmark_file']}")
            
        except Exception as e:
            self.logger.error(f"Error saving bookmark: {e}")

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a Windows Event Log source
    source = WindowsEventLogSource(
        source_id='security_events',
        log_name='Security',
        bookmark=True,
        query='*[System[(Level=4)]]'  # Only include warnings and errors
    )
    
    # Register a callback to print events
    def print_event(entry):
        event = entry.get('event', {})
        print(f"[{event.get('time_generated')}] [{event.get('event_type')}] {event.get('message', '')}")
    
    source.register_callback(print_event)
    
    # Start the source
    source.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Windows Event Log source...")
        source.stop()
