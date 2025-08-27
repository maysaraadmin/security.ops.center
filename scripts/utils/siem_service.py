"""
SIEM Service

This service handles the integration with various SIEM solutions to forward
security events and alerts from the EDR system.
"""
import os
import yaml
import logging
import queue
import threading
import time
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta

from ..integrations.siem_integration import (
    SIEMIntegration,
    SIEMIntegrationFactory,
    SIEMEvent
)

logger = logging.getLogger(__name__)

class SIEMService:
    """Service for managing SIEM integrations and event forwarding"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the SIEM service.
        
        Args:
            config_path: Path to the SIEM configuration file
        """
        self.config = self._load_config(config_path)
        self.integrations: Dict[str, SIEMIntegration] = {}
        self.event_queue = queue.Queue(maxsize=self.config.get('queue_size', 10000))
        self.running = False
        self.worker_threads: List[threading.Thread] = []
        self.health_check_thread: Optional[threading.Thread] = None
        self._initialize_integrations()
    
    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load SIEM configuration from file"""
        if not config_path:
            # Default config path
            config_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                '..', 'config', 'siem_integration.yaml'
            )
        
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
                # Apply environment variable substitution
                config_str = yaml.dump(config)
                config_str = os.path.expandvars(config_str)
                config = yaml.safe_load(config_str)
                
                # Apply environment-specific overrides
                env = os.environ.get('ENVIRONMENT', 'production')
                if env in config.get('environment_overrides', {}):
                    config.update(config['environment_overrides'][env])
                
                return config
                
        except Exception as e:
            logger.error(f"Failed to load SIEM configuration: {str(e)}")
            # Return default config if loading fails
            return {
                'enabled': False,
                'integrations': {},
                'batch_processing': {
                    'enabled': True,
                    'max_batch_size': 1000,
                    'flush_interval': 60,
                },
                'queue_size': 10000,
                'logging': {
                    'level': 'INFO',
                    'log_file': 'logs/siem_service.log'
                }
            }
    
    def _initialize_integrations(self) -> None:
        """Initialize all configured SIEM integrations"""
        if not self.config.get('enabled', False):
            logger.info("SIEM integration is disabled in configuration")
            return
        
        integrations_config = self.config.get('integrations', {})
        if not integrations_config:
            logger.warning("No SIEM integrations configured")
            return
        
        for name, config in integrations_config.items():
            if not config.get('enabled', False):
                logger.debug(f"SIEM integration {name} is disabled")
                continue
                
            try:
                siem_type = config.get('type')
                if not siem_type:
                    logger.error(f"Missing 'type' in SIEM integration config: {name}")
                    continue
                
                # Create the SIEM integration
                integration = SIEMIntegrationFactory.create_siem_integration(siem_type, config)
                if integration:
                    self.integrations[name] = integration
                    logger.info(f"Initialized SIEM integration: {name} ({siem_type})")
                    
                    # Test the connection
                    if integration.test_connection():
                        logger.info(f"Successfully connected to {name} SIEM")
                    else:
                        logger.warning(f"Failed to connect to {name} SIEM")
                
            except Exception as e:
                logger.error(f"Failed to initialize SIEM integration {name}: {str(e)}", exc_info=True)
    
    def start(self) -> None:
        """Start the SIEM service and worker threads"""
        if not self.config.get('enabled', False) or not self.integrations:
            logger.info("SIEM service is disabled or no integrations configured")
            return
        
        if self.running:
            logger.warning("SIEM service is already running")
            return
        
        self.running = True
        
        # Start worker threads
        num_workers = min(len(self.integrations) * 2, 10)  # Max 10 workers
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"SIEM-Worker-{i+1}",
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)
        
        # Start batch processing thread if enabled
        if self.config.get('batch_processing', {}).get('enabled', False):
            batch_worker = threading.Thread(
                target=self._batch_worker_loop,
                name="SIEM-BatchWorker",
                daemon=True
            )
            batch_worker.start()
            self.worker_threads.append(batch_worker)
        
        # Start health check thread
        self.health_check_thread = threading.Thread(
            target=self._health_check_loop,
            name="SIEM-HealthCheck",
            daemon=True
        )
        self.health_check_thread.start()
        
        logger.info(f"SIEM service started with {len(self.worker_threads)} worker threads")
    
    def stop(self) -> None:
        """Stop the SIEM service and all worker threads"""
        if not self.running:
            return
        
        logger.info("Stopping SIEM service...")
        self.running = False
        
        # Wait for worker threads to finish
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Flush any remaining events
        self._flush_events()
        
        logger.info("SIEM service stopped")
    
    def send_event(
        self,
        event: Union[SIEMEvent, Dict[str, Any]],
        siem_names: Optional[List[str]] = None,
        **kwargs
    ) -> bool:
        """
        Send an event to the specified SIEM integrations.
        
        Args:
            event: The event to send (either SIEMEvent or dict)
            siem_names: List of SIEM integration names to send to (None for all)
            **kwargs: Additional arguments to pass to the event
            
        Returns:
            bool: True if the event was queued successfully, False otherwise
        """
        if not self.running or not self.integrations:
            logger.debug("SIEM service not running or no integrations configured")
            return False
        
        try:
            # Convert dict to SIEMEvent if needed
            if isinstance(event, dict):
                event = SIEMEvent(**{**event, **kwargs})
            elif kwargs:
                # Update event with additional fields
                for key, value in kwargs.items():
                    setattr(event, key, value)
            
            # Add default fields from config
            default_fields = self.config.get('default_fields', {})
            for key, value in default_fields.items():
                if not hasattr(event, key):
                    setattr(event, key, value)
            
            # Add global fields
            global_fields = self.config.get('global_fields', {})
            for key, value in global_fields.items():
                if not hasattr(event, 'details') or not isinstance(event.details, dict):
                    event.details = {}
                if key not in event.details:
                    event.details[key] = value
            
            # Add timestamp if not set
            if not hasattr(event, 'timestamp') or not event.timestamp:
                event.timestamp = datetime.utcnow()
            
            # Put the event in the queue for processing
            self.event_queue.put((event, siem_names), block=False)
            logger.debug(f"Queued event for SIEM: {event.event_type}")
            return True
            
        except queue.Full:
            logger.warning("SIEM event queue is full, dropping event")
            return False
        except Exception as e:
            logger.error(f"Failed to queue SIEM event: {str(e)}", exc_info=True)
            return False
            
    def send_events_batch(
        self,
        events: List[Union[SIEMEvent, Dict[str, Any]]],
        siem_names: Optional[List[str]] = None
    ) -> bool:
        """
        Send multiple events to the specified SIEM integrations.
        
        Args:
            events: List of events to send (either SIEMEvent or dict)
            siem_names: List of SIEM integration names to send to (None for all)
            
        Returns:
            bool: True if all events were queued successfully, False otherwise
        """
        if not self.running or not self.integrations:
            logger.debug("SIEM service not running or no integrations configured")
            return False
            
        success = True
        for event in events:
            if not self.send_event(event, siem_names):
                success = False
                
        return success
    
    def _worker_loop(self) -> None:
        """Worker thread loop for processing events"""
        while self.running:
            try:
                # Get an event from the queue with a timeout to allow checking self.running
                try:
                    event, siem_names = self.event_queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Process the event
                self._process_event(event, siem_names)
                
                # Mark the task as done
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in SIEM worker thread: {str(e)}", exc_info=True)
    
    def _batch_worker_loop(self) -> None:
        """Worker thread for batch processing events"""
        batch_config = self.config.get('batch_processing', {})
        max_batch_size = batch_config.get('max_batch_size', 1000)
        flush_interval = batch_config.get('flush_interval', 60)
        
        batch: List[tuple] = []
        last_flush = time.time()
        
        while self.running:
            try:
                # Calculate time until next flush
                time_until_flush = max(0, last_flush + flush_interval - time.time())
                
                # Get an event from the queue with a timeout
                try:
                    event_data = self.event_queue.get(timeout=min(1.0, time_until_flush))
                    batch.append(event_data)
                except queue.Empty:
                    pass
                
                # Check if we should flush the batch
                current_time = time.time()
                should_flush = (
                    len(batch) >= max_batch_size or
                    (current_time - last_flush) >= flush_interval and batch
                )
                
                if should_flush and batch:
                    self._process_batch(batch)
                    batch = []
                    last_flush = current_time
                
            except Exception as e:
                logger.error(f"Error in SIEM batch worker thread: {str(e)}", exc_info=True)
    
    def _process_event(
        self,
        event: Union[SIEMEvent, Dict[str, Any]],
        siem_names: Optional[List[str]] = None
    ) -> None:
        """Process a single event and send it to the appropriate SIEMs"""
        if not self.integrations:
            return
        
        # Determine which SIEMs to send to
        targets = []
        if siem_names:
            # Specific SIEMs requested
            for name in siem_names:
                if name in self.integrations:
                    targets.append((name, self.integrations[name]))
        else:
            # Send to all enabled SIEMs
            targets = list(self.integrations.items())
        
        if not targets:
            logger.warning(f"No valid SIEM targets found for event")
            return
        
        # Send the event to each target SIEM
        for name, siem in targets:
            try:
                # Check if this SIEM has any filters
                siem_config = self.config.get('integrations', {}).get(name, {})
                filters = siem_config.get('filters', {})
                
                # Apply filters if any
                if self._should_filter_event(event, filters):
                    logger.debug(f"Event filtered out by {name} SIEM filters")
                    continue
                
                # Apply field mappings if any
                mapped_event = self._apply_field_mappings(event, siem_config.get('field_mappings', {}))
                
                # Send the event
                success = siem.send_event(mapped_event)
                if not success:
                    logger.warning(f"Failed to send event to {name} SIEM")
                
            except Exception as e:
                logger.error(f"Error sending event to {name} SIEM: {str(e)}", exc_info=True)
    
    def _process_batch(self, batch: List[tuple]) -> None:
        """Process a batch of events"""
        if not batch or not self.integrations:
            return
        
        # Group events by SIEM target
        siem_events: Dict[str, List[Any]] = {}
        
        for event_data in batch:
            event, siem_names = event_data
            
            # Determine which SIEMs to send to
            targets = []
            if siem_names:
                # Specific SIEMs requested
                for name in siem_names:
                    if name in self.integrations:
                        targets.append(name)
            else:
                # Send to all enabled SIEMs
                targets = list(self.integrations.keys())
            
            # Add event to each target SIEM's batch
            for name in targets:
                if name not in siem_events:
                    siem_events[name] = []
                siem_events[name].append(event)
        
        # Send batches to each SIEM
        for name, events in siem_events.items():
            if not events:
                continue
                
            try:
                siem = self.integrations[name]
                siem_config = self.config.get('integrations', {}).get(name, {})
                
                # Apply filters and mappings
                filtered_events = []
                for event in events:
                    # Check filters
                    if not self._should_filter_event(event, siem_config.get('filters', {})):
                        # Apply field mappings
                        mapped_event = self._apply_field_mappings(
                            event,
                            siem_config.get('field_mappings', {})
                        )
                        filtered_events.append(mapped_event)
                
                if not filtered_events:
                    continue
                
                # Send the batch
                success = siem.send_events_batch(filtered_events)
                if not success:
                    logger.warning(f"Failed to send batch of {len(filtered_events)} events to {name} SIEM")
                
            except Exception as e:
                logger.error(f"Error sending batch to {name} SIEM: {str(e)}", exc_info=True)
            
            # Mark all events in this batch as done
            for _ in range(len(events)):
                self.event_queue.task_done()
    
    def _should_filter_event(
        self,
        event: Union[SIEMEvent, Dict[str, Any]],
        filters: Dict[str, Any]
    ) -> bool:
        """Check if an event should be filtered out based on the filter rules"""
        if not filters:
            return False
        
        # Convert event to dict if it's a SIEMEvent
        if isinstance(event, SIEMEvent):
            event_dict = event.to_dict()
        else:
            event_dict = event
        
        # Check severity filter
        if 'severity' in filters:
            severity_levels = filters['severity']
            if isinstance(severity_levels, str):
                severity_levels = [severity_levels]
            
            event_severity = str(event_dict.get('severity', '')).lower()
            if event_severity not in [s.lower() for s in severity_levels]:
                return True
        
        # Check other field filters
        for field, rule in filters.items():
            if field == 'severity':
                continue  # Already handled
                
            if isinstance(rule, dict):
                # Complex filter rule
                operator = rule.get('operator', 'equals')
                value = rule.get('value')
                field_value = self._get_nested_field(event_dict, field)
                
                if operator == 'equals' and field_value != value:
                    return True
                elif operator == 'not_equals' and field_value == value:
                    return True
                elif operator == 'contains' and value not in str(field_value):
                    return True
                elif operator == 'not_contains' and value in str(field_value):
                    return True
                elif operator == 'in' and field_value not in value:
                    return True
                elif operator == 'not_in' and field_value in value:
                    return True
                elif operator == 'exists' and field_value is None:
                    return True
                elif operator == 'not_exists' and field_value is not None:
                    return True
                # Add more operators as needed
            
            elif field in event_dict and event_dict[field] != rule:
                # Simple equality check
                return True
        
        return False
    
    def _apply_field_mappings(
        self,
        event: Union[SIEMEvent, Dict[str, Any]],
        mappings: Dict[str, str]
    ) -> Dict[str, Any]:
        """Apply field mappings to an event"""
        if not mappings:
            return event.to_dict() if isinstance(event, SIEMEvent) else event
        
        # Convert to dict if it's a SIEMEvent
        if isinstance(event, SIEMEvent):
            result = event.to_dict()
        else:
            result = event.copy()
        
        # Apply mappings
        mapped_result = {}
        for src_field, dest_field in mappings.items():
            if src_field in result:
                mapped_result[dest_field] = result[src_field]
            else:
                # Try to get nested field
                value = self._get_nested_field(result, src_field)
                if value is not None:
                    mapped_result[dest_field] = value
        
        # Include any unmapped fields
        for field, value in result.items():
            if field not in mappings:
                mapped_result[field] = value
        
        return mapped_result
    
    def _get_nested_field(self, obj: Any, path: str, default: Any = None) -> Any:
        """Get a nested field from a dictionary using dot notation"""
        if not obj or not path:
            return default
            
        keys = path.split('.')
        value = obj
        
        try:
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key, default)
                elif hasattr(value, key):
                    value = getattr(value, key, default)
                else:
                    return default
                
                if value is None:
                    return default
                    
            return value
        except (KeyError, AttributeError, TypeError):
            return default
    
    def _health_check_loop(self) -> None:
        """Periodically check the health of SIEM integrations"""
        check_interval = self.config.get('health_check', {}).get('interval', 300)
        
        while self.running:
            time.sleep(check_interval)
            
            for name, siem in self.integrations.items():
                try:
                    if not siem.test_connection():
                        logger.warning(f"Health check failed for {name} SIEM")
                    # else:
                    #     logger.debug(f"Health check passed for {name} SIEM")
                except Exception as e:
                    logger.error(f"Error during health check for {name} SIEM: {str(e)}")
    
    def _flush_events(self) -> None:
        """Flush any remaining events in the queue"""
        logger.info("Flushing remaining SIEM events...")
        
        # Process remaining events in the queue
        processed = 0
        while not self.event_queue.empty():
            try:
                event, siem_names = self.event_queue.get_nowait()
                self._process_event(event, siem_names)
                processed += 1
            except queue.Empty:
                break
            except Exception as e:
                logger.error(f"Error processing event during flush: {str(e)}")
        
        if processed > 0:
            logger.info(f"Flushed {processed} remaining SIEM events")
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the SIEM service"""
        return {
            'enabled': self.config.get('enabled', False),
            'running': self.running,
            'integrations': {
                name: {
                    'type': siem.__class__.__name__,
                    'enabled': True
                }
                for name, siem in self.integrations.items()
            },
            'queue_size': self.event_queue.qsize(),
            'worker_threads': len(self.worker_threads),
            'health_check_running': self.health_check_thread is not None and self.health_check_thread.is_alive()
        }


# Singleton instance
_siem_service = None

def get_siem_service(config_path: Optional[str] = None) -> SIEMService:
    """Get or create the singleton SIEM service instance"""
    global _siem_service
    
    if _siem_service is None:
        _siem_service = SIEMService(config_path)
    
    return _siem_service
