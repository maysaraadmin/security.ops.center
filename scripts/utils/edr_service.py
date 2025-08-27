import os
import psutil
import platform
import hashlib
import logging
import json
import time
import socket
import threading
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager

# Database types for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from sqlite3 import Connection, Cursor

import sys
import os
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Import after path setup
from src.models.security_models import EDREvent, Severity, AlertStatus

# Configure logging to use the root logger
logger = logging.getLogger('siem.edr')

class EDRService:
    """
    Endpoint Detection and Response (EDR) service for monitoring and analyzing
    endpoint activities in real-time.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, db_connection=None):
        """Initialize the EDR service.
        
        Args:
            config: Configuration dictionary (typically from siem_config['edr'])
            db_connection: Database connection or connection pool
        """
        # Default configuration
        self.config = {
            'enabled': True,
            'agent': {
                'check_interval': 60,
                'log_level': 'INFO',
                'log_file': 'logs/edr_agent.log'
            },
            'detection': {
                'monitor_processes': True,
                'suspicious_keywords': [
                    'powershell -nop -enc',
                    'iex(new-object net.webclient).downloadstring',
                    'invoke-expression',
                    'invoke-webrequest',
                    'invoke-shellcode',
                    'meterpreter',
                    'regsvr32 /s /n /u /i:'
                ],
                'monitor_network': True,
                'suspicious_ports': [4444, 8080, 9001, 22, 23, 3389],
                'monitor_files': False,
                'watch_directories': [
                    'C:\\Windows\\System32',
                    'C:\\Program Files',
                    'C:\\ProgramData'
                ]
            },
            'whitelist': {
                'processes': [
                    'svchost.exe', 'explorer.exe', 'winlogon.exe', 'lsass.exe',
                    'services.exe', 'wininit.exe', 'csrss.exe', 'smss.exe'
                ],
                'ips': [],
                'domains': []
            }
        }
        
        # Update with provided config
        if config:
            self._update_config(config)
            
        # Set up logging
        self._setup_logging()
            
        # Initialize service state
        self.db = db_connection
        self.running = False
        self.thread = None
        self.executor = ThreadPoolExecutor(
            max_workers=5,
            thread_name_prefix='EDRWorker'
        )
        self.known_processes = set()  # Track known processes
        self.suspicious_hashes = set()  # Known malicious hashes
        
        # Initialize monitoring state
        self.process_events = []
        self.last_scan = datetime.now()
        
    def _update_config(self, config: Dict[str, Any]) -> None:
        """Update configuration with new settings.
        
        Args:
            config: Configuration dictionary to update with
        """
        def deep_update(target: Dict, update: Dict) -> None:
            """Recursively update a dictionary."""
            for key, value in update.items():
                if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                    deep_update(target[key], value)
                else:
                    target[key] = value
                    
        deep_update(self.config, config)
        
    def _setup_logging(self) -> None:
        """Set up logging based on configuration."""
        log_level = getattr(
            logging,
            self.config['agent'].get('log_level', 'INFO').upper(),
            logging.INFO
        )
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.config['agent'].get('log_file', '/var/log/edr_agent.log'))
            ]
        )
        
    def start(self):
        """Start the EDR service."""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("EDR service started")
    
    def stop(self):
        """Stop the EDR service."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.executor.shutdown(wait=False)
        logger.info("EDR service stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop for the EDR service."""
        if not self.config.get('enabled', True):
            logger.info("EDR monitoring is disabled in configuration")
            return
            
        check_interval = self.config['agent'].get('check_interval', 5)
        logger.info(f"Starting EDR monitoring loop (check_interval={check_interval}s)")
        
        # Initial process scan
        self._scan_processes()
        
        # Main monitoring loop
        while self.running:
            try:
                current_time = datetime.now()
                
                # Scan processes at configured interval
                if (current_time - self.last_scan).total_seconds() >= check_interval:
                    self._scan_processes()
                    self.last_scan = current_time
                
                # Process any pending events
                self._process_events()
                
                # Sleep briefly to prevent high CPU usage
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                time.sleep(5)  # Prevent tight loop on error
    
    def _scan_processes(self):
        """Scan running processes for suspicious activity."""
        if not self.config['detection'].get('monitor_processes', True):
            return
            
        current_processes = set()
        whitelist = set(self.config['whitelist'].get('processes', []))
        suspicious_keywords = self.config['detection'].get('suspicious_keywords', [])
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                process_info = proc.info
                pid = process_info['pid']
                name = process_info['name'].lower()
                cmdline = ' '.join(process_info['cmdline'] or []) if process_info['cmdline'] else ''
                username = process_info['username']
                
                # Skip whitelisted processes
                if name in whitelist:
                    continue
                
                # Check for suspicious processes
                is_suspicious = False
                reason = ''
                
                # Check command line for suspicious patterns
                for pattern in suspicious_keywords:
                    if pattern.lower() in cmdline.lower():
                        is_suspicious = True
                        reason = f'Suspicious command line pattern: {pattern}'
                        break
                
                if is_suspicious:
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'suspicious_process',
                        'severity': 'high',
                        'process': {
                            'pid': pid,
                            'name': name,
                            'cmdline': cmdline,
                            'username': username
                        },
                        'reason': reason,
                        'source': 'edr',
                        'status': 'new'
                    }
                    self.process_events.append(event)
                    logger.warning(f"Suspicious process detected: {name} (PID: {pid}) - {reason}")
                
                current_processes.add(pid)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logger.debug(f"Error accessing process: {e}")
                continue
        
        # Check for terminated processes
        terminated = self.known_processes - current_processes
        if terminated:
            logger.debug(f"Processes terminated: {len(terminated)}")
        
        self.known_processes = current_processes
    
    def _process_events(self):
        """Process any pending events."""
        if not self.process_events:
            return
            
        # Process events in batches
        batch_size = self.config.get('batch_size', 100)
        events = self.process_events[:batch_size]
        self.process_events = self.process_events[batch_size:]
        
        # Process events in thread pool
        futures = []
        for event in events:
            future = self.executor.submit(self._process_event, event)
            futures.append(future)
            
        # Wait for all events to be processed with timeout
        for future in as_completed(futures, timeout=30):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error processing event: {e}", exc_info=True)
        
        logger.debug(f"Processed {len(events)} events")
    
    def _process_event(self, event):
        """Process a single event."""
        try:
            # Skip if event processing is disabled
            if not self.config.get('enabled', True):
                return
                
            # Add timestamp if not present
            if 'timestamp' not in event:
                event['timestamp'] = datetime.now().isoformat()
            
            # Store event in database if configured
            if self.db and self.config.get('store_events', True):
                self._store_event(event)
                
            # Generate alert if needed
            min_severity = self.config.get('alerting', {}).get('min_severity', 'medium')
            severity_levels = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            
            if (severity_levels.get(event.get('severity', 'low').lower(), 0) >= 
                severity_levels.get(min_severity.lower(), 1)):
                self._generate_alert(event)
                
            logger.debug(f"Processed event: {event.get('event_type')} - {event.get('reason', '')}")
            
        except Exception as e:
            logger.error(f"Error processing event: {e}", exc_info=True)
            # Optionally re-queue failed events for retry
            if 'retry_count' not in event:
                event['retry_count'] = 1
                self.process_events.append(event)
            elif event['retry_count'] < 3:  # Max 3 retries
                event['retry_count'] += 1
                self.process_events.append(event)
                raise
    
    def _get_process_name(self, pid):
        """Get process name by PID."""
        try:
            if not pid:
                return "Unknown"
            p = psutil.Process(pid)
            return p.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "Unknown"
    
    def _ensure_edr_events_table(self, conn: 'Connection') -> None:
        """Ensure the edr_events table exists.
        
        Args:
            conn: Database connection
        """
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS edr_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                endpoint_id TEXT NOT NULL,
                process_name TEXT NOT NULL,
                process_id INTEGER NOT NULL,
                parent_process TEXT,
                command_line TEXT,
                user TEXT,
                severity TEXT NOT NULL,
                detection_type TEXT NOT NULL,
                details TEXT,
                status TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create indexes for better query performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_edr_events_timestamp 
            ON edr_events(timestamp)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_edr_events_process_name 
            ON edr_events(process_name)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_edr_events_severity 
            ON edr_events(severity)
        ''')
        
        conn.commit()
    
    def _store_event(self, event) -> None:
        """Store EDR event in the database.
        
        Args:
            event: The event to store
            
        Raises:
            RuntimeError: If database is not initialized
        """
        try:
            # Prepare event data
            event_dict = {
                'timestamp': datetime.now().isoformat(),
                'endpoint_id': socket.gethostname(),
                'process_name': event['process']['name'],
                'process_id': event['process']['pid'],
                'parent_process': self._get_process_name(event['process'].get('ppid')),
                'command_line': event['process']['cmdline'][:4000] if event['process']['cmdline'] else None,  # Limit size
                'user': event['process']['username'],
                'severity': event.get('severity', 'low'),
                'detection_type': event.get('event_type', 'unknown'),
                'details': json.dumps(event.get('details', {})),
                'status': event.get('status', 'new')
            }
            
            if not self.db:
                logger.warning("No database connection available, skipping event storage")
                return
                
            try:
                # Use the database's execute method directly if available
                if hasattr(self.db, 'execute'):
                    # Ensure table exists first
                    with self._get_db_connection() as conn:
                        self._ensure_edr_events_table(conn)
                    
                    # Insert the event
                    self.db.execute('''
                        INSERT INTO edr_events 
                        (timestamp, endpoint_id, process_name, process_id, parent_process, 
                         command_line, user, severity, detection_type, details, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        event_dict['timestamp'],
                        event_dict['endpoint_id'],
                        event_dict['process_name'],
                        event_dict['process_id'],
                        event_dict['parent_process'],
                        event_dict['command_line'],
                        event_dict['user'],
                        event_dict['severity'],
                        event_dict['detection_type'],
                        event_dict['details'],
                        event_dict['status']
                    ))
                    logger.debug(f"Stored EDR event: {event_dict['process_name']} ({event_dict['process_id']})")
                else:
                    # Fallback to direct connection if execute method not available
                    with self._get_db_connection() as conn:
                        # Ensure table exists
                        self._ensure_edr_events_table(conn)
                        
                        # Insert the event
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO edr_events 
                            (timestamp, endpoint_id, process_name, process_id, parent_process, 
                             command_line, user, severity, detection_type, details, status)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            event_dict['timestamp'],
                            event_dict['endpoint_id'],
                            event_dict['process_name'],
                            event_dict['process_id'],
                            event_dict['parent_process'],
                            event_dict['command_line'],
                            event_dict['user'],
                            event_dict['severity'],
                            event_dict['detection_type'],
                            event_dict['details'],
                            event_dict['status']
                        ))
                        conn.commit()
                        logger.debug(f"Stored EDR event: {event_dict['process_name']} ({event_dict['process_id']})")
                    
            except Exception as e:
                logger.error(f"Error storing EDR event: {e}", exc_info=True)
                raise
            
        except Exception as e:
            logger.error(f"Unexpected error in _store_event: {e}", exc_info=True)
            raise
    
    @contextmanager
    def _get_db_connection(self) -> 'Connection':
        """Get a database connection from the pool or use direct connection.
        
        This method handles different database connection patterns:
        1. Database class with get_connection() method (connection pool)
        2. Direct sqlite3.Connection object
        3. Database class with direct execute() method
        
        Yields:
            sqlite3.Connection: A database connection
            
        Raises:
            RuntimeError: If database is not properly initialized
        """
        if not self.db:
            raise RuntimeError("Database connection not initialized")
            
        # Case 1: Database class with get_connection() method (connection pool)
        if hasattr(self.db, 'get_connection'):
            conn = self.db.get_connection()
            try:
                # Get the actual connection object (handles wrappers)
                if hasattr(conn, 'connection'):
                    yield conn.connection
                else:
                    yield conn
            finally:
                # Ensure connection is properly closed/returned to pool
                if hasattr(conn, 'close'):
                    conn.close()
        # Case 2: Direct sqlite3.Connection object
        elif hasattr(self.db, 'cursor'):
            yield self.db
        # Case 3: Database class with direct execute() method
        elif hasattr(self.db, 'execute'):
            yield self.db
        else:
            raise RuntimeError("Unsupported database connection type")
