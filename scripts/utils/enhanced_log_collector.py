"""
Enhanced Log Collector with support for multiple log sources and formats.
"""

import os
import json
import time
import queue
import socket
import gzip
import bz2
import zlib
import logging
from enum import Enum
from typing import Dict, List, Optional, Callable, Union, Any, Tuple
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Event
from queue import Queue

# Third-party imports
try:
    import pygtail
    from watchgod import watch, PythonWatcher
    HAS_WATCHGOD = True
except ImportError:
    HAS_WATCHGOD = False

class LogSourceType(Enum):
    """Types of log sources."""
    FILE = "file"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"
    CLOUD = "cloud"
    DATABASE = "database"

class LogFormat(Enum):
    """Supported log formats."""
    JSON = "json"
    CSV = "csv"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"
    TEXT = "text"

class LogSource:
    """Base class for all log sources."""
    
    def __init__(self, source_id: str, source_type: LogSourceType, config: dict):
        """Initialize the log source.
        
        Args:
            source_id: Unique identifier for the source
            source_type: Type of the log source
            config: Configuration dictionary
        """
        self.source_id = source_id
        self.source_type = source_type
        self.config = config
        self.logger = logging.getLogger(f'siem.logsource.{source_id}')
        self.running = False
        self._lock = Lock()
        self._callbacks = []
        
    def start(self):
        """Start collecting logs."""
        with self._lock:
            if not self.running:
                self.running = True
                self.logger.info(f"Started log source: {self.source_id}")
                
    def stop(self):
        """Stop collecting logs."""
        with self._lock:
            if self.running:
                self.running = False
                self.logger.info(f"Stopped log source: {self.source_id}")
    
    def register_callback(self, callback: Callable[[dict], None]):
        """Register a callback to receive log entries.
        
        Args:
            callback: Function that will be called with each log entry
        """
        with self._lock:
            if callback not in self._callbacks:
                self._callbacks.append(callback)
    
    def _notify_callbacks(self, entry: dict):
        """Notify all registered callbacks with the log entry.
        
        Args:
            entry: Log entry to send to callbacks
        """
        with self._lock:
            for callback in self._callbacks:
                try:
                    callback(entry)
                except Exception as e:
                    self.logger.error(f"Error in callback: {e}")

class FileLogSource(LogSource):
    """Log source that reads from files."""
    
    def __init__(self, source_id: str, file_path: str, **kwargs):
        """Initialize the file log source.
        
        Args:
            source_id: Unique identifier for the source
            file_path: Path to the log file
            **kwargs: Additional configuration options
        """
        config = {
            'file_path': file_path,
            'encoding': kwargs.get('encoding', 'utf-8'),
            'format': kwargs.get('format', LogFormat.TEXT),
            'follow': kwargs.get('follow', True),
            'buffer_size': kwargs.get('buffer_size', 8192),
            'backup_count': kwargs.get('backup_count', 5),
        }
        super().__init__(source_id, LogSourceType.FILE, config)
        self.file_path = Path(file_path)
        self.position = 0
        self.watcher = None
        self._stop_event = Event()
    
    def start(self):
        """Start watching the log file."""
        super().start()
        
        if not self.file_path.exists():
            self.logger.error(f"Log file not found: {self.file_path}")
            return
            
        if self.config['follow'] and HAS_WATCHGOD:
            self._start_watcher()
        else:
            self._read_file()
    
    def stop(self):
        """Stop watching the log file."""
        self._stop_event.set()
        if self.watcher:
            self.watcher.stop()
        super().stop()
    
    def _start_watcher(self):
        """Start watching the file for changes."""
        def callback(changes):
            for change in changes:
                if change[0] == 'modified':
                    self._read_file()
        
        self.watcher = watch(
            str(self.file_path.parent),
            watcher_cls=PythonWatcher,
            normal_sleep=1000,  # Check every second
            recursive=False
        )
        
        # Start the watcher in a separate thread
        import threading
        threading.Thread(
            target=lambda: self._watch_loop(callback),
            daemon=True
        ).start()
    
    def _watch_loop(self, callback):
        """Watch for file changes and call the callback."""
        for changes in self.watcher:
            if self._stop_event.is_set():
                break
            callback(changes)
    
    def _read_file(self):
        """Read new lines from the file."""
        try:
            with open(self.file_path, 'r', encoding=self.config['encoding'], errors='replace') as f:
                # Seek to the last read position
                if self.position > 0:
                    f.seek(self.position)
                
                # Read new lines
                while True:
                    line = f.readline()
                    if not line:
                        break
                    
                    # Process the log entry
                    self._process_line(line.strip())
                
                # Update the position
                self.position = f.tell()
                
        except Exception as e:
            self.logger.error(f"Error reading log file: {e}")
    
    def _process_line(self, line: str):
        """Process a single log line.
        
        Args:
            line: The log line to process
        """
        if not line:
            return
            
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source': self.source_id,
            'raw': line,
            'parsed': self._parse_line(line)
        }
        
        self._notify_callbacks(entry)
    
    def _parse_line(self, line: str) -> dict:
        """Parse a log line based on the configured format.
        
        Args:
            line: The log line to parse
            
        Returns:
            Parsed log entry as a dictionary
        """
        try:
            if self.config['format'] == LogFormat.JSON:
                return json.loads(line)
            elif self.config['format'] == LogFormat.CSV:
                # Simple CSV parsing - can be enhanced with csv module
                return {f'col_{i}': v for i, v in enumerate(line.split(','))}
            elif self.config['format'] == LogFormat.CEF:
                return self._parse_cef(line)
            elif self.config['format'] == LogFormat.LEEF:
                return self._parse_leef(line)
            else:
                # Default to returning the raw line
                return {'message': line}
        except Exception as e:
            self.logger.warning(f"Failed to parse log line: {e}")
            return {'message': line, 'parse_error': str(e)}
    
    def _parse_cef(self, line: str) -> dict:
        """Parse a CEF formatted log line.
        
        Args:
            line: CEF formatted log line
            
        Returns:
            Parsed CEF data as a dictionary
        """
        # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
        parts = line.split('|', 7)
        if len(parts) < 7:
            return {'raw': line, 'parse_error': 'Invalid CEF format'}
            
        result = {
            'cef_version': parts[0].replace('CEF:', ''),
            'device_vendor': parts[1],
            'device_product': parts[2],
            'device_version': parts[3],
            'signature_id': parts[4],
            'name': parts[5],
            'severity': parts[6],
        }
        
        # Parse extensions if present
        if len(parts) > 7:
            extensions = {}
            for ext in parts[7].split(' '):
                if '=' in ext:
                    k, v = ext.split('=', 1)
                    extensions[k] = v.strip('"')
            result['extensions'] = extensions
            
        return result
    
    def _parse_leef(self, line: str) -> dict:
        """Parse a LEEF formatted log line.
        
        Args:
            line: LEEF formatted log line
            
        Returns:
            Parsed LEEF data as a dictionary
        """
        # LEEF:Version|Vendor|Product|Version|EventID|[Key1=Value1]...[KeyN=ValueN]
        parts = line.split('|', 5)
        if len(parts) < 5:
            return {'raw': line, 'parse_error': 'Invalid LEEF format'}
            
        result = {
            'leef_version': parts[0].replace('LEEF:', ''),
            'vendor': parts[1],
            'product': parts[2],
            'version': parts[3],
            'event_id': parts[4],
        }
        
        # Parse key-value pairs if present
        if len(parts) > 5:
            extensions = {}
            for kv in parts[5].split('\t'):
                if '=' in kv:
                    k, v = kv.split('=', 1)
                    extensions[k] = v.strip('"')
            result['extensions'] = extensions
            
        return result

class SyslogSource(LogSource):
    """Log source that listens for syslog messages."""
    
    def __init__(self, source_id: str, **kwargs):
        """Initialize the syslog source.
        
        Args:
            source_id: Unique identifier for the source
            **kwargs: Additional configuration options
        """
        config = {
            'host': kwargs.get('host', '0.0.0.0'),
            'port': kwargs.get('port', 514),
            'protocol': kwargs.get('protocol', 'udp'),  # 'udp' or 'tcp'
            'format': kwargs.get('format', LogFormat.SYSLOG),
        }
        super().__init__(source_id, LogSourceType.SYSLOG, config)
        self.socket = None
        self._stop_event = Event()
    
    def start(self):
        """Start the syslog server."""
        super().start()
        
        try:
            if self.config['protocol'].lower() == 'udp':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind((self.config['host'], self.config['port']))
                self.socket.settimeout(1.0)
                
                # Start the receiver thread
                import threading
                threading.Thread(
                    target=self._udp_receive_loop,
                    daemon=True
                ).start()
                
            else:  # TCP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.bind((self.config['host'], self.config['port']))
                self.socket.listen(5)
                self.socket.settimeout(1.0)
                
                # Start the acceptor thread
                import threading
                threading.Thread(
                    target=self._tcp_accept_loop,
                    daemon=True
                ).start()
                
            self.logger.info(f"Started syslog server on {self.config['host']}:{self.config['port']} "
                           f"({self.config['protocol'].upper()})")
            
        except Exception as e:
            self.logger.error(f"Failed to start syslog server: {e}")
            self.stop()
    
    def stop(self):
        """Stop the syslog server."""
        self._stop_event.set()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        super().stop()
    
    def _udp_receive_loop(self):
        """Receive UDP syslog messages."""
        while not self._stop_event.is_set():
            try:
                data, addr = self.socket.recvfrom(8192)
                self._process_message(data.decode('utf-8', errors='replace'), addr)
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error receiving UDP message: {e}")
    
    def _tcp_accept_loop(self):
        """Accept TCP connections and handle them in separate threads."""
        while not self._stop_event.is_set():
            try:
                conn, addr = self.socket.accept()
                import threading
                threading.Thread(
                    target=self._handle_tcp_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                self.logger.error(f"Error accepting TCP connection: {e}")
    
    def _handle_tcp_connection(self, conn, addr):
        """Handle a single TCP connection."""
        try:
            with conn:
                while not self._stop_event.is_set():
                    data = conn.recv(8192)
                    if not data:
                        break
                    self._process_message(data.decode('utf-8', errors='replace'), addr)
        except Exception as e:
            self.logger.error(f"Error handling TCP connection from {addr}: {e}")
    
    def _process_message(self, message: str, addr: tuple):
        """Process a received syslog message.
        
        Args:
            message: The syslog message
            addr: Source address (ip, port)
        """
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source': self.source_id,
            'remote_addr': addr[0],
            'remote_port': addr[1],
            'raw': message,
            'parsed': self._parse_syslog(message)
        }
        
        self._notify_callbacks(entry)
    
    def _parse_syslog(self, message: str) -> dict:
        """Parse a syslog message.
        
        Args:
            message: The syslog message to parse
            
        Returns:
            Parsed syslog data as a dictionary
        """
        # This is a simplified parser - can be enhanced with a proper syslog parser
        # like syslog-rfc5424-parser for full RFC 5424 compliance
        
        # Check for RFC 5424 format
        if message.startswith('<'):
            # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
            parts = message.split(' ', 7)
            if len(parts) >= 7:
                pri = parts[0][1:]  # Remove leading <
                version = parts[1]
                timestamp = parts[2] + ' ' + parts[3]
                hostname = parts[4]
                app = parts[5]
                procid = parts[6]
                msg = parts[7] if len(parts) > 7 else ''
                
                return {
                    'format': 'rfc5424',
                    'priority': pri,
                    'version': version,
                    'timestamp': timestamp,
                    'hostname': hostname,
                    'app_name': app,
                    'procid': procid,
                    'msgid': '',  # Not in this simplified parser
                    'message': msg
                }
        
        # Check for BSD (RFC 3164) format
        # <PRI>TIMESTAMP HOSTNAME MESSAGE
        parts = message.split(' ', 4)
        if len(parts) >= 4 and parts[0].startswith('<'):
            pri = parts[0][1:]  # Remove leading <
            timestamp = parts[1] + ' ' + parts[2]
            hostname = parts[3]
            msg = parts[4] if len(parts) > 4 else ''
            
            return {
                'format': 'rfc3164',
                'priority': pri,
                'timestamp': timestamp,
                'hostname': hostname,
                'message': msg
            }
        
        # Fallback to returning the raw message
        return {'message': message}

class EnhancedLogCollector:
    """Enhanced log collector that manages multiple log sources."""
    
    def __init__(self, config: Optional[dict] = None):
        """Initialize the log collector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger('siem.logcollector')
        self.sources: Dict[str, LogSource] = {}
        self.callbacks = []
        self._lock = Lock()
        self._running = False
        self._stop_event = Event()
        
        # Thread pool for processing log entries
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 5),
            thread_name_prefix='log_processor_'
        )
        
        # Queue for log entries
        self.queue = Queue(maxsize=self.config.get('queue_size', 10000))
        
        # Start processor thread
        self.processor_thread = None
    
    def add_source(self, source: LogSource):
        """Add a log source.
        
        Args:
            source: The log source to add
        """
        with self._lock:
            if source.source_id in self.sources:
                raise ValueError(f"Source with ID '{source.source_id}' already exists")
                
            # Register our callback to receive entries from this source
            source.register_callback(self._on_log_entry)
            self.sources[source.source_id] = source
            
            # Start the source if we're running
            if self._running:
                source.start()
    
    def remove_source(self, source_id: str):
        """Remove a log source.
        
        Args:
            source_id: ID of the source to remove
        """
        with self._lock:
            if source_id in self.sources:
                self.sources[source_id].stop()
                del self.sources[source_id]
    
    def register_callback(self, callback: Callable[[dict], None]):
        """Register a callback to receive log entries.
        
        Args:
            callback: Function that will be called with each log entry
        """
        with self._lock:
            if callback not in self.callbacks:
                self.callbacks.append(callback)
    
    def start(self):
        """Start the log collector."""
        with self._lock:
            if self._running:
                self.logger.warning("Log collector is already running")
                return
                
            self._running = True
            self._stop_event.clear()
            
            # Start the processor thread
            self.processor_thread = threading.Thread(
                target=self._process_queue,
                name='log_processor',
                daemon=True
            )
            self.processor_thread.start()
            
            # Start all sources
            for source in self.sources.values():
                try:
                    source.start()
                except Exception as e:
                    self.logger.error(f"Failed to start source {source.source_id}: {e}")
            
            self.logger.info("Log collector started")
    
    def stop(self):
        """Stop the log collector."""
        with self._lock:
            if not self._running:
                return
                
            self._running = False
            self._stop_event.set()
            
            # Stop all sources
            for source in self.sources.values():
                try:
                    source.stop()
                except Exception as e:
                    self.logger.error(f"Error stopping source {source.source_id}: {e}")
            
            # Shutdown the executor
            self.executor.shutdown(wait=False)
            
            # Clear the queue
            while not self.queue.empty():
                try:
                    self.queue.get_nowait()
                except queue.Empty:
                    break
            
            self.logger.info("Log collector stopped")
    
    def _on_log_entry(self, entry: dict):
        """Handle a log entry from a source.
        
        Args:
            entry: The log entry
        """
        try:
            # Add metadata
            entry['@timestamp'] = datetime.utcnow().isoformat()
            entry['@version'] = '1'
            
            # Add to queue for processing
            self.queue.put(entry, block=True, timeout=1.0)
            
        except queue.Full:
            self.logger.warning("Log queue is full, dropping entry")
        except Exception as e:
            self.logger.error(f"Error processing log entry: {e}")
    
    def _process_queue(self):
        """Process entries from the queue."""
        while not self._stop_event.is_set():
            try:
                # Get an entry from the queue with a timeout to allow checking _stop_event
                try:
                    entry = self.queue.get(block=True, timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process the entry in a thread pool
                self.executor.submit(self._process_entry, entry)
                
            except Exception as e:
                self.logger.error(f"Error in queue processor: {e}")
                time.sleep(1)  # Prevent tight loop on error
    
    def _process_entry(self, entry: dict):
        """Process a single log entry.
        
        Args:
            entry: The log entry to process
        """
        try:
            # Apply any transformations or enrichment
            self._enrich_entry(entry)
            
            # Call all registered callbacks
            with self._lock:
                for callback in self.callbacks:
                    try:
                        callback(entry)
                    except Exception as e:
                        self.logger.error(f"Error in callback: {e}")
                        
        except Exception as e:
            self.logger.error(f"Error processing log entry: {e}")
        finally:
            self.queue.task_done()
    
    def _enrich_entry(self, entry: dict):
        """Enrich a log entry with additional data.
        
        Args:
            entry: The log entry to enrich
        """
        # Add host information if not present
        if 'host' not in entry:
            entry['host'] = {
                'name': socket.gethostname(),
                'ip': socket.gethostbyname(socket.gethostname())
            }
        
        # Add timestamp if not present
        if '@timestamp' not in entry:
            entry['@timestamp'] = datetime.utcnow().isoformat()
        
        # Add any additional enrichment here (e.g., geoip, threat intel, etc.)
        
        return entry

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a log collector
    collector = EnhancedLogCollector({
        'max_workers': 10,
        'queue_size': 10000
    })
    
    # Add a file source
    file_source = FileLogSource(
        source_id='auth_log',
        file_path='/var/log/auth.log',
        format=LogFormat.SYSLOG,
        follow=True
    )
    collector.add_source(file_source)
    
    # Add a syslog source
    syslog_source = SyslogSource(
        source_id='syslog_udp',
        host='0.0.0.0',
        port=5514,
        protocol='udp'
    )
    collector.add_source(syslog_source)
    
    # Register a callback to print log entries
    def print_entry(entry):
        print(f"[{entry.get('@timestamp')}] [{entry.get('source')}] {entry.get('raw', '')}")
    
    collector.register_callback(print_entry)
    
    # Start the collector
    collector.start()
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping log collector...")
        collector.stop()
