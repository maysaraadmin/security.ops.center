import time
import concurrent.futures
import sqlite3
import uuid
import re
import json
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Tuple, Optional, Union, Generator, Iterable
from dateutil import parser
from .database import Database
import queue
import threading
import logging
import hashlib
import psutil
from dataclasses import dataclass, asdict, field
from enum import Enum

# Configure logger
logger = logging.getLogger('siem.event')

class EventStatus(str, Enum):
    NEW = 'New'
    IN_PROGRESS = 'In Progress'
    RESOLVED = 'Resolved'
    FALSE_POSITIVE = 'False Positive'
    IGNORED = 'Ignored'

class EventSeverity(int, Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

@dataclass
class Event:
    """Data class representing a security event.
    
    Attributes:
        source: The source of the event (e.g., 'Windows Security', 'Firewall')
        event_type: Type/category of the event (e.g., 'Login', 'File Access')
        description: Detailed description of the event
        severity: Severity level of the event (from EventSeverity enum)
        timestamp: When the event occurred (defaults to current UTC time)
        ip_address: Source IP address associated with the event
        status: Current status of the event (from EventStatus enum)
        raw_data: Raw event data as a string
        metadata: Additional event metadata as key-value pairs
        event_id: Database ID of the event (set when saved)
        category: Category of the event (e.g., 'Security', 'System')
        computer: Name of the computer where the event originated
        user: User associated with the event
    """
    source: str
    event_type: str
    description: str
    severity: EventSeverity
    timestamp: datetime = field(default_factory=datetime.utcnow)
    ip_address: Optional[str] = None
    status: EventStatus = EventStatus.NEW
    raw_data: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: Optional[int] = None
    category: Optional[str] = None
    computer: Optional[str] = None
    user: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Validate and normalize field values after initialization."""
        # Handle raw_data serialization if it's a dict or list
        if isinstance(self.raw_data, (dict, list)):
            try:
                self.raw_data = json.dumps(self.raw_data, default=str)
            except (TypeError, ValueError) as e:
                logger.warning(f"Failed to serialize raw_data: {e}")
                self.raw_data = str(self.raw_data)
        
        # Convert severity if it's an integer or string
        if isinstance(self.severity, int):
            try:
                self.severity = EventSeverity(self.severity)
            except ValueError:
                logger.warning(f"Invalid severity value: {self.severity}, defaulting to INFO")
                self.severity = EventSeverity.INFO
        elif isinstance(self.severity, str):
            try:
                self.severity = EventSeverity[self.severity.upper()]
            except (KeyError, AttributeError):
                logger.warning(f"Invalid severity string: {self.severity}, defaulting to INFO")
                self.severity = EventSeverity.INFO
                
        # Convert status if it's a string
        if isinstance(self.status, str):
            try:
                self.status = EventStatus[self.status.upper().replace(' ', '_')]
            except (KeyError, AttributeError):
                logger.warning(f"Invalid status: {self.status}, defaulting to NEW")
                self.status = EventStatus.NEW
                        # Convert timestamp if it's a string, int, or float
        if not isinstance(self.timestamp, datetime):
            try:
                if isinstance(self.timestamp, (int, float)):
                    # Handle Unix timestamps (both seconds and milliseconds)
                    if self.timestamp > 1e12:  # Likely in milliseconds
                        self.timestamp = datetime.fromtimestamp(self.timestamp / 1000.0, tz=timezone.utc)
                    else:
                        self.timestamp = datetime.fromtimestamp(self.timestamp, tz=timezone.utc)
                elif isinstance(self.timestamp, str):
                    # Clean up the timestamp string
                    ts_str = self.timestamp.strip()
                    
                    # Log the original timestamp for debugging
                    logger.debug(f"Parsing timestamp: {ts_str}")
                    
                    # Common timestamp format patterns
                    patterns = [
                        # ISO 8601 with timezone (e.g., '2025-08-19T11:11:44+00:00' or '2025-08-19T11:11:44Z')
                        r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?',
                        # Common log format (e.g., '19/Aug/2025:11:11:44 +0000')
                        r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}',
                        # Windows Event Log format (e.g., '8/19/2025 11:11:44 AM')
                        r'\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?: [AP]M)?',
                        # Day of week format (e.g., 'Tue Aug 19 11:11:57 2025')
                        r'[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}'
                    ]
                    
                    # Try to match known patterns first
                    matched = False
                    for pattern in patterns:
                        if re.fullmatch(pattern, ts_str):
                            matched = True
                            break
                    
                    if not matched:
                        logger.warning(f"Timestamp format not recognized, attempting fuzzy parse: {ts_str}")
                    
                    # Handle specific formats explicitly
                    try:
                        # Handle 'Z' timezone indicator
                        if ts_str.endswith('Z'):
                            ts_str = ts_str[:-1] + '+00:00'
                        
                        # Try ISO format first (fastest for standard formats)
                        try:
                            self.timestamp = datetime.fromisoformat(ts_str)
                        except ValueError:
                            # Handle common log format (e.g., '19/Aug/2025:11:11:44 +0000')
                            if re.match(r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}', ts_str):
                                dt_str, tz_str = ts_str.split()
                                day, month, year = dt_str.split('/')
                                month_num = datetime.strptime(month, '%b').month
                                dt = datetime(int(year), month_num, int(day), tzinfo=timezone.utc)
                                # Apply timezone offset if present
                                if tz_str != '+0000':
                                    tz_hours = int(tz_str[:3])
                                    tz_mins = int(tz_str[0] + tz_str[3:])
                                    tz_offset = timedelta(hours=tz_hours, minutes=tz_mins)
                                    dt = dt - tz_offset
                                self.timestamp = dt
                            # Handle day of week format (e.g., 'Tue Aug 19 11:11:57 2025')
                            elif re.match(r'[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}', ts_str):
                                # Remove day of week and parse the rest
                                parts = ts_str.split()
                                ts_str = ' '.join(parts[1:])
                                parsed = parser.parse(ts_str, fuzzy=True)
                                self.timestamp = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
                            else:
                                # Fall back to dateutil's parser for other formats
                                parsed = parser.parse(ts_str, fuzzy=True)
                                self.timestamp = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
                        
                        # Ensure timezone awareness
                        if self.timestamp.tzinfo is None:
                            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
                            
                    except Exception as parse_error:
                        logger.warning(f"Failed to parse timestamp '{ts_str}': {parse_error}")
                        logger.debug(f"Traceback for timestamp parsing error:", exc_info=True)
                        raise ValueError(f"Invalid timestamp format: {ts_str}")
                        
                else:
                    raise ValueError(f"Unsupported timestamp type: {type(self.timestamp)}")
                
                logger.debug(f"Successfully parsed timestamp: {self.timestamp.isoformat()}")
                    
            except Exception as e:
                logger.warning(f"Error parsing timestamp '{self.timestamp}': {str(e)}, using current time")
                logger.debug("Traceback for timestamp parsing error:", exc_info=True)
                self.timestamp = datetime.now(timezone.utc)
        
        # Ensure timestamp is timezone-aware (use UTC if no timezone specified)
        if self.timestamp.tzinfo is None:
            logger.debug("Timestamp is timezone-naive, assuming UTC")
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        
        self._validate_fields()
        
    def _validate_fields(self) -> None:
        """Validate field values and raise ValueError if invalid."""
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Source must be a non-empty string")
            
        if not isinstance(self.event_type, str) or not self.event_type.strip():
            raise ValueError("Event type must be a non-empty string")
            
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("Description must be a non-empty string")
            
        if not isinstance(self.severity, EventSeverity):
            raise ValueError("Severity must be an EventSeverity enum")
            
        if not isinstance(self.timestamp, datetime):
            raise ValueError("Timestamp must be a datetime object")
            
        if self.ip_address is not None and not isinstance(self.ip_address, str):
            raise ValueError("IP address must be a string or None")
            
        if not isinstance(self.metadata, dict):
            raise ValueError("Metadata must be a dictionary")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization.
        
        Returns:
            Dictionary containing all event attributes with proper type conversion.
            Enum values are converted to their primitive types, and timestamps are
            converted to ISO format strings.
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            # Create a dictionary with all fields, including None values
            result = {}
            for field in self.__dataclass_fields__:
                value = getattr(self, field)
                # Skip None values to keep the output clean
                if value is not None:
                    if field == 'severity':
                        result[field] = value.value
                    elif field == 'status':
                        result[field] = value.value
                    elif field == 'timestamp':
                        result[field] = value.isoformat()
                    elif field == 'metadata' and value:
                        # Create a copy to avoid modifying the original
                        result[field] = value.copy()
                    else:
                        result[field] = value
            
            return result
            
        except Exception as e:
            logger.error(f"Error converting event to dict: {e}", exc_info=True)
            raise ValueError(f"Failed to convert event to dictionary: {e}")
    
    def generate_fingerprint(self) -> str:
        """Generate a unique fingerprint for the event to detect duplicates.
        
        The fingerprint is a SHA-256 hash of the event's key attributes that
        should be unique for distinct events. This helps in detecting and
        preventing duplicate events from being processed multiple times.
        
        Returns:
            str: A hexadecimal string representing the SHA-256 hash of the event's
                 key attributes.
                 
        Raises:
            ValueError: If required fields for fingerprinting are missing or invalid
        """
        try:
            # Include key attributes that should be unique for each event
            fingerprint_parts = [
                str(self.source).lower().strip(),
                str(self.event_type).lower().strip(),
                str(self.description).strip()
            ]
            
            # Include IP address if available
            if self.ip_address:
                fingerprint_parts.append(str(self.ip_address).strip())
                
            # Include computer name if available
            if self.computer:
                fingerprint_parts.append(str(self.computer).lower().strip())
                
            # Join parts with null byte to prevent collisions
            fingerprint_data = '\x00'.join(part for part in fingerprint_parts if part)
            
            # Generate and return SHA-256 hash
            return hashlib.sha256(fingerprint_data.encode('utf-8', errors='ignore')).hexdigest()
            
        except Exception as e:
            logger.error(f"Error generating event fingerprint: {e}", exc_info=True)
            raise ValueError(f"Failed to generate event fingerprint: {e}")

class EventModel:
    def __init__(self, db: Database, root=None, batch_size: int = 500, dedupe_window: int = 3600, max_workers: int = 4):
        """Initialize the EventModel with database connection and configuration.
        
        Args:
            db: Database instance (not raw connection)
            root: Reference to root Tk instance for main thread callbacks
            batch_size: Number of events to process in a single batch (default: 500)
            dedupe_window: Time window in seconds to check for duplicate events
            max_workers: Maximum number of worker threads for parallel processing
        """
        if not isinstance(db, Database):
            raise ValueError("db parameter must be an instance of Database class, not a raw connection")
        self.db = db
        self.root = root
        self.batch_size = batch_size
        self.dedupe_window = dedupe_window
        self.max_workers = max_workers
        
        # Increased queue size and added priority queue support with larger buffer
        self._event_queue = queue.PriorityQueue(maxsize=batch_size * 20)  # Increased from 10x to 20x
        self._processing_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._recent_events = set()  # For duplicate detection
        self._recent_events_lock = threading.Lock()
        self._queue_stats = {
            'total_queued': 0,
            'total_processed': 0,
            'total_dropped': 0,
            'last_drop_time': None
        }
        self._stats_lock = threading.Lock()
        
        # Thread pool for parallel processing
        self._thread_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='EventWorker'
        )
        
        # Start background processing threads
        for i in range(max_workers):
            thread = threading.Thread(
                target=self._process_events_background,
                name=f"EventProcessor-{i}",
                daemon=True
            )
            thread.start()
        
        # Start cleanup thread for recent events cache
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_recent_events,
            name="RecentEventsCleaner",
            daemon=True
        )
        self._cleanup_thread.start()
        
        # Start stats logging thread
        self._stats_thread = threading.Thread(
            target=self._log_queue_stats,
            name="QueueStatsLogger",
            daemon=True
        )
        self._stats_thread.start()
        
        logger.info(f"EventModel initialized with batch_size={batch_size}, dedupe_window={dedupe_window}s")
        
    def queue_event(self, event: Union[Event, Dict[str, Any]], priority: int = 1) -> bool:
        """Add an event to the processing queue with priority.
        
        Args:
            event: Either an Event object or a dictionary containing event data
            priority: Priority level (1=highest, 5=lowest)
            
        Returns:
            bool: True if event was queued, False if dropped
            
        Note:
            - Priority 1: Critical security events (e.g., authentication failures)
            - Priority 2: High severity events
            - Priority 3: Medium severity events
            - Priority 4: Low severity events
            - Priority 5: Informational events
        """
        try:
            # Convert dict to Event object if needed
            if isinstance(event, dict):
                # Only keep valid fields for Event constructor
                valid_fields = {
                    'source', 'event_type', 'description', 'severity',
                    'timestamp', 'ip_address', 'status', 'raw_data',
                    'metadata', 'event_id', 'category', 'computer', 'user'
                }
                
                # Filter out invalid fields and handle None values
                filtered_event = {}
                for k, v in event.items():
                    if k in valid_fields and v is not None:
                        # Convert severity to enum if needed
                        if k == 'severity' and isinstance(v, (str, int)):
                            try:
                                if isinstance(v, str):
                                    v = EventSeverity[v.upper()]
                                else:
                                    v = EventSeverity(v)
                            except (KeyError, ValueError):
                                logger.warning(f"Invalid severity value: {v}, defaulting to INFO")
                                v = EventSeverity.INFO
                        filtered_event[k] = v
                
                # Ensure required fields are present
                if not filtered_event.get('source') or not filtered_event.get('event_type') or not filtered_event.get('description'):
                    logger.warning("Dropping event with missing required fields")
                    self._update_stats(dropped=1)
                    return False
                
                try:
                    event = Event(**filtered_event)
                except Exception as e:
                    logger.error(f"Error creating Event object: {e}")
                    self._update_stats(dropped=1)
                    return False
            
            # Validate the event object
            if not isinstance(event, Event):
                logger.error("Invalid event type, expected Event object or dict")
                self._update_stats(dropped=1)
                return False
                
            # Check for duplicates before queuing
            if self._is_duplicate_event(event):
                logger.debug(f"Dropping duplicate event: {event.generate_fingerprint()}")
                return False
            
            # Add to queue with priority (lower number = higher priority)
            try:
                # Create a unique ID for this event
                unique_id = str(uuid.uuid4())
                # Use a tuple of (priority, timestamp, unique_id, event) for proper ordering
                self._event_queue.put((priority, time.time(), unique_id, event), block=False)
                self._update_stats(queued=1)
                return True
                
            except queue.Full:
                logger.warning(f"Event queue full, dropping event (priority {priority})")
                self._update_stats(dropped=1)
                return False
                
        except Exception as e:
            logger.error(f"Error queuing event: {e}", exc_info=True)
            self._update_stats(dropped=1)
            return False
    
    def _update_stats(self, queued: int = 0, processed: int = 0, dropped: int = 0) -> None:
        """Update queue statistics in a thread-safe manner."""
        with self._stats_lock:
            self._queue_stats['total_queued'] += queued
            self._queue_stats['total_processed'] += processed
            self._queue_stats['total_dropped'] += dropped
            if dropped > 0:
                self._queue_stats['last_drop_time'] = time.time()
    
    def _log_queue_stats(self) -> None:
        """Periodically log queue statistics."""
        while not self._shutdown_event.is_set():
            try:
                time.sleep(60)  # Log every minute
                with self._stats_lock:
                    qsize = self._event_queue.qsize()
                    stats = self._queue_stats.copy()
                
                logger.info(
                    f"Queue Stats: size={qsize}, "
                    f"queued={stats['total_queued']}, "
                    f"processed={stats['total_processed']}, "
                    f"dropped={stats['total_dropped']}"
                )
                
            except Exception as e:
                logger.error(f"Error in stats logger: {e}", exc_info=True)
                time.sleep(5)
    
    def _process_events_background(self) -> None:
        """Background thread for processing events in batches."""
        batch = []
        last_process_time = time.time()
        
        while not self._shutdown_event.is_set():
            try:
                # Get next event with timeout to allow for shutdown check
                try:
                    # Unpack priority, timestamp, unique_id, and event from queue
                    # Using *_ to ignore the unique_id which was added for tie-breaking
                    priority, timestamp, _, event = self._event_queue.get(timeout=1.0)
                except queue.Empty:
                    # Process any remaining events in the batch if we've been waiting too long
                    if batch and (time.time() - last_process_time) > 0.5:  # 500ms max batch delay
                        self._process_batch(batch)
                        batch = []
                        last_process_time = time.time()
                    continue
                
                # Add to current batch if we're not shutting down
                if not self._shutdown_event.is_set():
                    batch.append(event)
                    self._event_queue.task_done()
                    
                    # Process batch if we've reached the batch size or it's been a while
                    if len(batch) >= self.batch_size or (time.time() - last_process_time) > 0.5:
                        try:
                            self._process_batch(batch)
                        except Exception as e:
                            logger.error(f"Error processing batch: {e}", exc_info=True)
                        batch = []
                        last_process_time = time.time()
                else:
                    self._event_queue.task_done()
                    break
                    
            except Exception as e:
                logger.error(f"Error in event processing thread: {e}", exc_info=True)
                # Prevent tight loop on error
                time.sleep(1)
                
        # Process any remaining events in the batch before shutting down
        if batch and not self._shutdown_event.is_set():
            try:
                self._process_batch(batch)
            except Exception as e:
                logger.error(f"Error processing final batch: {e}", exc_info=True)
    
    def _execute_batch_operations(self, cursor, events: List[Event]) -> None:
        """Execute batch operations for events using the provided cursor.
        
        Args:
            cursor: Database cursor to use for operations
            events: List of Event objects to process
        """
        # Prepare the batch insert query
        query = """
            INSERT INTO events (
                timestamp, source, event_type, severity, 
                description, ip_address, status, raw_data, metadata,
                fingerprint, computer, user, category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
            
        # Prepare batch data
        batch_data = []
        for event in events:
            # Skip duplicate events
            if self._is_duplicate_event(event):
                logger.debug(f"Skipping duplicate event: {event}")
                self._update_stats(dropped=1)
                continue
                
            # Prepare event data for insertion
            event_data = (
                event.timestamp,
                event.source,
                event.event_type,
                event.severity.value if hasattr(event.severity, 'value') else event.severity,
                event.description,
                event.ip_address,
                event.status.value if hasattr(event.status, 'value') else event.status,
                event.raw_data,
                json.dumps(event.metadata) if event.metadata else None,
                getattr(event, 'fingerprint', None) or str(uuid.uuid4()),
                getattr(event, 'computer', None),
                getattr(event, 'user', None),
                getattr(event, 'category', None)
            )
            batch_data.append(event_data)
            
        if not batch_data:
            return
            
        # Execute batch insert
        cursor.executemany(query, batch_data)
        
        # Update statistics
        self._update_stats(processed=len(batch_data))
        
    def _process_batch(self, events: List[Event]) -> None:
        """Process a batch of events in a single transaction.
        
        Args:
            events: List of Event objects to process
        """
        if not events:
            return
            
        # Handle both connection pool and raw connection
        if hasattr(self.db, 'get_connection'):
            # This is a connection pool - use context manager
            with self.db.get_connection() as conn:
                try:
                    cursor = conn.cursor()
                    self._execute_batch_operations(cursor, events)
                    conn.commit()
                    
                    # Add to recent events for deduplication
                    current_time = time.time()
                    with self._recent_events_lock:
                        for event in events:
                            fingerprint = event.generate_fingerprint()
                            self._recent_events.add((fingerprint, current_time))
                    
                    logger.info(f"Processed batch of {len(events)} events")
                    
                    # Update metrics if available
                    if hasattr(self, 'metrics'):
                        try:
                            self.metrics.increment_counter('events.processed', len(events))
                        except Exception as e:
                            logger.error(f"Failed to update metrics: {e}")
                            
                except Exception as e:
                    logger.error(f"Error processing batch: {e}", exc_info=True)
                    raise
                finally:
                    if cursor:
                        try:
                            cursor.close()
                        except Exception as e:
                            logger.error(f"Error closing cursor: {e}")
        else:
            # This is a raw connection
            cursor = None
            try:
                cursor = self.db.cursor()
                self._execute_batch_operations(cursor, events)
                self.db.commit()
                
                # Add to recent events for deduplication
                current_time = time.time()
                with self._recent_events_lock:
                    for event in events:
                        fingerprint = event.generate_fingerprint()
                        self._recent_events.add((fingerprint, current_time))
                
                logger.info(f"Processed batch of {len(events)} events")
                
                # Update metrics if available
                if hasattr(self, 'metrics'):
                    try:
                        self.metrics.increment_counter('events.processed', len(events))
                    except Exception as e:
                        logger.error(f"Failed to update metrics: {e}")
                        
            except Exception as e:
                logger.error(f"Error processing batch: {e}", exc_info=True)
                raise
            finally:
                if cursor:
                    try:
                        cursor.close()
                    except Exception as e:
                        logger.error(f"Error closing cursor: {e}")
    
    def _update_ui_with_events(self, events_with_ids):
        """
        Update the UI with new events in a thread-safe manner.
        
        Args:
            events_with_ids: List of tuples containing (event_id, event_data)
        """
        if not events_with_ids or not hasattr(self, 'root') or not self.root:
            return
            
        try:
            if hasattr(self, '_shutdown_event') and self._shutdown_event.is_set():
                return
                
            # Create a thread-safe copy of the events
            events_copy = list(events_with_ids)
            
            # Define the actual UI update function
            def do_ui_update():
                try:
                    if (hasattr(self, '_shutdown_event') and self._shutdown_event.is_set()) or \
                       not hasattr(self, 'root') or not self.root:
                        return
                        
                    if hasattr(self.root, 'update_ui_with_new_events'):
                        try:
                            self.root.update_ui_with_new_events(events_copy)
                        except Exception as e:
                            logger.error(f"Error in custom UI update: {e}", exc_info=True)
                    else:
                        # Fallback to event generation
                        try:
                            self.root.event_generate('<<NewEvents>>', when='tail')
                        except Exception as e:
                            logger.error(f"Error generating UI event: {e}", exc_info=True)
                except Exception as e:
                    logger.error(f"Error in UI update handler: {e}", exc_info=True)
            
            # Schedule the update on the main thread
            try:
                if hasattr(self.root, 'after') and callable(self.root.after):
                    self.root.after(0, do_ui_update)
                else:
                    logger.warning("Root object does not support 'after' method for UI updates")
            except RuntimeError as e:
                if 'main thread is not in main loop' in str(e):
                    logger.debug("UI update skipped - main thread not in main loop")
                else:
                    logger.error(f"RuntimeError scheduling UI update: {e}")
            except Exception as e:
                logger.error(f"Unexpected error scheduling UI update: {e}", exc_info=True)
                
        except Exception as e:
            logger.error(f"Error in _update_ui_with_events: {e}", exc_info=True)
        """Update the UI with new events in a thread-safe manner."""
        try:
            # Call the UI update method if it exists
            if hasattr(self.root, 'update_ui_with_new_events'):
                self.root.update_ui_with_new_events(events_with_ids)
        except Exception as e:
            logger.error(f"Error in UI update: {e}", exc_info=True)
                
        except Exception as e:
            logger.error(f"Error processing event batch: {e}", exc_info=True)
            if 'conn' in locals() and conn:
                conn.rollback()
    
    def _is_duplicate_event(self, event: Event) -> bool:
        """Check if a similar event was recently processed.
        
        Args:
            event: Event to check
            
        Returns:
            bool: True if a similar event was recently processed, False otherwise
        """
        fingerprint = event.generate_fingerprint()
        now = time.time()
        
        with self._recent_events_lock:
            # First clean up old entries
            self._recent_events = {
                (fp, timestamp) for (fp, timestamp) in self._recent_events
                if now - timestamp < self.dedupe_window
            }
            
            # Check for duplicate
            for fp, _ in self._recent_events:
                if fp == fingerprint:
                    return True
                    
        return False
    
    def _cleanup_recent_events(self) -> None:
        """Background thread to clean up old entries from recent_events."""
        while not self._shutdown_event.is_set():
            try:
                with self._recent_events_lock:
                    now = time.time()
                    self._recent_events = {
                        (fp, timestamp) for (fp, timestamp) in self._recent_events
                        if now - timestamp < self.dedupe_window
                    }
            except Exception as e:
                logger.error(f"Error cleaning up recent events: {e}", exc_info=True)
            
            # Sleep for a while before next cleanup
            self._shutdown_event.wait(self.dedupe_window / 2)
    
    def shutdown(self) -> None:
        """Shut down the event processor gracefully."""
        if not self._shutdown_event.is_set():
            logger.info("Shutting down event processor...")
            self._shutdown_event.set()
            
            # Wait for event queue to be processed with timeout
            max_wait_time = 5.0  # seconds
            start_time = time.time()
            
            while not self._event_queue.empty() and (time.time() - start_time) < max_wait_time:
                try:
                    self._event_queue.get_nowait()
                    self._event_queue.task_done()
                except queue.Empty:
                    break
                time.sleep(0.1)  # Small sleep to prevent busy waiting
            
            # Shut down thread pool with timeout and cancel pending futures
            try:
                self._thread_pool.shutdown(wait=True, cancel_futures=True)
            except Exception as e:
                logger.warning(f"Error during thread pool shutdown: {e}")
            
            # Clear recent events
            with self._recent_events_lock:
                self._recent_events.clear()
                
            logger.info("Event processor shut down gracefully")
            self._processor_thread.join(timeout=5.0)
        if self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=5.0)
        logger.info("Event processor shut down")
    
    def get_events_by_source(self, source: str, limit: int = 100) -> List[Tuple]:
        """
        Get events filtered by source
        
        Args:
            source: The source to filter by (e.g., 'Sysmon', 'Windows Security')
            limit: Maximum number of events to return
            
        Returns:
            List of event tuples (id, timestamp, source, event_type, severity, description, ip_address, status)
        """
        query = """
            SELECT id, timestamp, source, event_type, severity, description, ip_address, status
            FROM events
            WHERE source = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """
        try:
            return self.db.execute_query(query, (source, limit))
        except Exception as e:
            print(f"Error in get_events_by_source: {e}")
            return []
    
    def get_events_over_time(self, time_delta: timedelta) -> List[Tuple[str, int]]:
        """Get event counts grouped by time intervals"""
        try:
            if time_delta <= timedelta(hours=24):
                # Hourly grouping for 24 hours
                query = """
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_interval, 
                           COUNT(*) as count 
                    FROM events 
                    WHERE timestamp >= datetime('now', ?) 
                    GROUP BY time_interval 
                    ORDER BY time_interval
                """
                param = f"-{int(time_delta.total_seconds()/3600)} hours"
            elif time_delta <= timedelta(days=7):
                # Daily grouping for 7 days
                query = """
                    SELECT strftime('%Y-%m-%d', timestamp) as time_interval, 
                           COUNT(*) as count 
                    FROM events 
                    WHERE timestamp >= datetime('now', ?) 
                    GROUP BY time_interval 
                    ORDER BY time_interval
                """
                param = f"-{time_delta.days} days"
            else:
                # Weekly grouping for longer ranges
                query = """
                    SELECT strftime('%Y-%m-%d', date(timestamp, 'weekday 0', '-6 days')) as time_interval, 
                           COUNT(*) as count 
                    FROM events 
                    WHERE timestamp >= datetime('now', ?) 
                    GROUP BY time_interval 
                    ORDER BY time_interval
                """
                param = f"-{time_delta.days} days"
            
            return self.db.execute_query(query, (param,))
        except Exception as e:
            print(f"Error in get_events_over_time: {e}")
            return []
    
    def get_event_sources(self, time_delta: timedelta) -> List[Tuple[str, int]]:
        """Get event counts by source"""
        try:
            query = """
                SELECT source, COUNT(*) as count 
                FROM events 
                WHERE timestamp >= datetime('now', ?) 
                GROUP BY source 
                ORDER BY count DESC
            """
            param = f"-{int(time_delta.total_seconds()/3600)} hours" if time_delta <= timedelta(hours=24) else f"-{time_delta.days} days"
            return self.db.execute_query(query, (param,))
        except Exception as e:
            print(f"Error in get_event_sources: {e}")
            return []
    
    def get_severity_trends(self, time_delta: timedelta) -> List[Tuple[str, int, int]]:
        """Get severity counts over time"""
        try:
            if time_delta <= timedelta(hours=24):
                # Hourly grouping
                query = """
                    SELECT strftime('%Y-%m-%d %H:00', timestamp) as time_interval,
                           severity,
                           COUNT(*) as count
                    FROM events
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY time_interval, severity
                    ORDER BY time_interval, severity
                """
                param = f"-{int(time_delta.total_seconds()/3600)} hours"
            else:
                # Daily grouping
                query = """
                    SELECT strftime('%Y-%m-%d', timestamp) as time_interval,
                           severity,
                           COUNT(*) as count
                    FROM events
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY time_interval, severity
                    ORDER BY time_interval, severity
                """
                param = f"-{time_delta.days} days"
            
            return self.db.execute_query(query, (param,))
        except Exception as e:
            print(f"Error in get_severity_trends: {e}")
            return []

    def get_events(
        self,
        source_filter: str = None,
        severity_filter: int = None,
        time_range: str = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Retrieve events with optional filters"""
        query = "SELECT * FROM events"
        conditions = []
        params = []
        
        if source_filter and source_filter != 'All':
            conditions.append("source = ?")
            params.append(source_filter)
            
        if severity_filter and severity_filter != 'All':
            conditions.append("severity >= ?")
            params.append(int(severity_filter.split(' ')[0]))
            
        if time_range and time_range != 'All':
            if time_range == 'Last 24 hours':
                conditions.append("timestamp >= datetime('now', '-1 day')")
            elif time_range == 'Last 7 days':
                conditions.append("timestamp >= datetime('now', '-7 days')")
            elif time_range == 'Last 30 days':
                conditions.append("timestamp >= datetime('now', '-30 days')")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        results = self.db.execute_query(query, tuple(params))
        
        events = []
        for row in results:
            events.append({
                'id': row[0],
                'timestamp': row[1],
                'source': row[2],
                'event_type': row[3],
                'severity': row[4],
                'description': row[5],
                'ip_address': row[6],
                'status': row[7]
            })
            
        return events
    
    def get_event_stats(self) -> Dict[str, int]:
        """Get statistics about events"""
        stats = {}
        
        # Total events
        result = self.db.execute_query("SELECT COUNT(*) FROM events")
        stats['total'] = result[0][0]
        
        # Critical events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity >= 4")
        stats['critical'] = result[0][0]
        
        # Warning events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity = 3")
        stats['warning'] = result[0][0]
        
        # Normal events
        result = self.db.execute_query("SELECT COUNT(*) FROM events WHERE severity <= 2")
        stats['normal'] = result[0][0]
        
        return stats
    
    def mark_event_resolved(self, event_id: int) -> bool:
        """Mark an event as resolved"""
        query = "UPDATE events SET status = 'Resolved' WHERE id = ?"
        self.db.execute_update(query, (event_id,))
        return True
    
    def get_events_with_query(self, query: str, params: tuple = ()) -> List[tuple]:
        """Execute a custom query to get events"""
        return self.db.execute_query(query, params)
    
    def get_event_by_id(self, event_id: int) -> Optional[Dict]:
        """Get a single event by its ID"""
        query = """
            SELECT id, timestamp, source, event_type, severity, 
                   description, ip_address, status 
            FROM events 
            WHERE id = ?
        """
        result = self.db.execute_query(query, (event_id,))
        if result:
            return {
                'id': result[0][0],
                'timestamp': result[0][1],
                'source': result[0][2],
                'event_type': result[0][3],
                'severity': result[0][4],
                'description': result[0][5],
                'ip_address': result[0][6],
                'status': result[0][7]
            }
        return None
    
    def update_event_status(self, event_id: int, new_status: str) -> bool:
        """Update an event's status"""
        query = "UPDATE events SET status = ? WHERE id = ?"
        self.db.execute_update(query, (new_status, event_id))
        return True
        
    def get_events_by_time_range(self, start_time: datetime, end_time: datetime) -> List[Tuple]:
        """Get events within a specific time range"""
        query = """
            SELECT id, timestamp, source, event_type, severity, description, ip_address, status
            FROM events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp DESC
        """
        try:
            return self.db.execute_query(query, (start_time, end_time))
        except Exception as e:
            print(f"Error in get_events_by_time_range: {e}")
            return []
    
    def get_severity_distribution(self) -> List[Tuple[str, int]]:
        """Get count of events grouped by severity"""
        query = """
            SELECT 
                CASE 
                    WHEN severity >= 4 THEN 'Critical'
                    WHEN severity = 3 THEN 'Warning'
                    ELSE 'Info'
                END as severity_group,
                COUNT(*) as count
            FROM events
            WHERE timestamp >= datetime('now', '-24 hours')
            GROUP BY severity_group
            ORDER BY 
                CASE 
                    WHEN severity_group = 'Critical' THEN 1
                    WHEN severity_group = 'Warning' THEN 2
                    ELSE 3
                END
        """
        try:
            return self.db.execute_query(query)
        except Exception as e:
            print(f"Error in get_severity_distribution: {e}")
            return []
    
    def get_recent_alerts(self, limit: int = 10) -> List[Tuple]:
        """Get most recent alerts"""
        query = """
            SELECT id, timestamp, source, event_type, severity, description, ip_address, status
            FROM events
            WHERE severity >= 3  # Only include warnings and critical
            ORDER BY timestamp DESC
            LIMIT ?
        """
        try:
            return self.db.execute_query(query, (limit,))
        except Exception as e:
            print(f"Error in get_recent_alerts: {e}")
            return []