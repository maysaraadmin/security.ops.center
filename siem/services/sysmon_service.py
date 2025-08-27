"""
Sysmon Service for SIEM

This service collects, processes, and forwards Sysmon events to the SIEM.
"""
import json
import logging
import os
import signal
import sys
import threading
import time
from datetime import datetime
from queue import Queue, Empty
from typing import Dict, List, Optional, Any, Callable

import psutil
import yaml
from pykafka import KafkaClient
from pykafka.exceptions import KafkaException
import requests
import redis
from prometheus_client import start_http_server, Counter, Gauge, Summary

from src.siem.collectors.sysmon_collector import SysmonCollector

# Configure logging
logger = logging.getLogger(__name__)

# Prometheus metrics
EVENTS_PROCESSED = Counter('sysmon_events_processed_total', 'Total number of Sysmon events processed')
EVENT_PROCESSING_TIME = Summary('sysmon_event_processing_seconds', 'Time spent processing Sysmon events')
ALERTS_GENERATED = Counter('sysmon_alerts_generated_total', 'Total number of alerts generated')
QUEUE_SIZE = Gauge('sysmon_queue_size', 'Number of events waiting to be processed')

class SysmonService:
    """Service for collecting and processing Sysmon events."""
    
    def __init__(self, config_path: str = None):
        """Initialize the Sysmon service.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        self.running = False
        self.threads = []
        self.event_queue = Queue(maxsize=self.config['performance']['max_queue_size'])
        
        # Initialize components
        self.collector = SysmonCollector()
        self.outputs = self._initialize_outputs()
        self.alert_rules = self.config.get('alert_rules', [])
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self, config_path: str = None) -> dict:
        """Load the configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Configuration dictionary
            
        Raises:
            FileNotFoundError: If the configuration file does not exist
            yaml.YAMLError: If the configuration file is not valid YAML
        """
        # Try to determine the project root directory
        project_root = os.path.abspath(os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..'  # Go up 3 levels to reach the project root
        ))
        
        # List of possible config file locations
        possible_config_paths = [
            config_path,  # User-specified path
            os.path.join(project_root, 'config', 'sysmon_config.yaml'),
            os.path.join(project_root, 'src', 'config', 'sysmon_config.yaml'),
            os.path.join(os.getcwd(), 'config', 'sysmon_config.yaml'),
            os.path.join(os.getcwd(), 'src', 'config', 'sysmon_config.yaml')
        ]
        
        # Try each possible path
        config = None
        for path in possible_config_paths:
            if not path:
                continue
                
            try:
                logger.debug(f"Trying to load config from: {path}")
                with open(path, 'r') as f:
                    config = yaml.safe_load(f)
                    logger.info(f"Successfully loaded configuration from {path}")
                    return config
            except FileNotFoundError:
                logger.debug(f"Config file not found at {path}")
                continue
            except yaml.YAMLError as e:
                logger.error(f"Error parsing YAML in config file {path}: {e}")
                raise
        
        # If we get here, no config file was found
        error_msg = f"Could not find configuration file. Tried the following paths:\n"
        error_msg += "\n".join(f"- {p}" for p in possible_config_paths if p)
        logger.error(error_msg)
        raise FileNotFoundError(error_msg)
    
    def _setup_logging(self) -> None:
        """Configure logging based on the configuration."""
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        log_file = log_config.get('file')
        
        handlers = [logging.StreamHandler()]
        if log_file:
            os.makedirs(os.path.dirname(log_file) or '.', exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            handlers.append(file_handler)
        
        logging.basicConfig(
            level=log_level,
            format=log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s'),
            handlers=handlers
        )
    
    def _initialize_outputs(self) -> List[Callable[[Dict], None]]:
        """Initialize output handlers based on configuration.
        
        Returns:
            List of output handler functions
        """
        output_config = self.config.get('output', {})
        output_type = output_config.get('type', 'console')
        outputs = []
        
        if output_type == 'console':
            outputs.append(self._output_console)
        elif output_type == 'file':
            outputs.append(self._output_file)
        elif output_type == 'http':
            outputs.append(self._output_http)
        elif output_type == 'kafka':
            outputs.append(self._output_kafka)
        elif output_type == 'redis':
            outputs.append(self._output_redis)
        
        return outputs
    
    def _output_console(self, event: Dict) -> None:
        """Output event to console.
        
        Args:
            event: Event to output
        """
        print(json.dumps(event, indent=2))
    
    def _output_file(self, event: Dict) -> None:
        """Output event to file.
        
        Args:
            event: Event to output
        """
        output_config = self.config['output']['file']
        file_path = output_config['path']
        
        os.makedirs(os.path.dirname(file_path) or '.', exist_ok=True)
        
        with open(file_path, 'a') as f:
            f.write(json.dumps(event) + '\n')
    
    def _output_http(self, event: Dict) -> None:
        """Output event via HTTP.
        
        Args:
            event: Event to output
        """
        output_config = self.config['output']['http']
        url = output_config['url']
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f"Bearer {output_config.get('auth_token', '')}"
        }
        
        try:
            response = requests.post(
                url,
                json=event,
                headers=headers,
                timeout=output_config.get('timeout', 5)
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to send event via HTTP: {str(e)}")
    
    def _output_kafka(self, event: Dict) -> None:
        """Output event to Kafka.
        
        Args:
            event: Event to output
        """
        output_config = self.config['output']['kafka']
        
        try:
            client = KafkaClient(hosts=output_config['bootstrap_servers'])
            topic = client.topics[output_config['topic'].encode('utf-8')]
            with topic.get_sync_producer() as producer:
                producer.produce(json.dumps(event).encode('utf-8'))
        except KafkaException as e:
            logger.error(f"Failed to send event to Kafka: {str(e)}")
    
    def _output_redis(self, event: Dict) -> None:
        """Output event to Redis.
        
        Args:
            event: Event to output
        """
        output_config = self.config['output']['redis']
        
        try:
            r = redis.Redis(
                host=output_config['host'],
                port=output_config['port'],
                db=output_config['db']
            )
            r.rpush(output_config['key'], json.dumps(event))
        except Exception as e:
            logger.error(f"Failed to send event to Redis: {str(e)}")
    
    def _process_event(self, event: Dict) -> Dict:
        """Process a single event.
        
        Args:
            event: Event to process
            
        Returns:
            Processed event
        """
        with EVENT_PROCESSING_TIME.time():
            # Apply filters
            if not self._filter_event(event):
                return None
            
            # Enrich event
            if self.config['enrichment'].get('enabled', True):
                self._enrich_event(event)
            
            # Check for alerts
            self._check_alerts(event)
            
            # Update metrics
            EVENTS_PROCESSED.inc()
            
            return event
    
    def _filter_event(self, event: Dict) -> bool:
        """Filter events based on configuration.
        
        Args:
            event: Event to filter
            
        Returns:
            True if the event should be processed, False otherwise
        """
        filters = self.config.get('filters', {})
        
        # Filter by event ID
        include_ids = filters.get('include_event_ids', [])
        if include_ids and event.get('event_id') not in include_ids:
            return False
            
        exclude_ids = filters.get('exclude_event_ids', [])
        if event.get('event_id') in exclude_ids:
            return False
            
        # Filter by process name
        process_name = event.get('event_data', {}).get('Image', '').lower()
        if process_name:
            include_patterns = filters.get('process_include_patterns', [])
            if include_patterns and not any(p in process_name for p in include_patterns):
                return False
                
            exclude_patterns = filters.get('process_exclude_patterns', [])
            if any(p in process_name for p in exclude_patterns):
                return False
        
        return True
    
    def _enrich_event(self, event: Dict) -> None:
        """Enrich an event with additional information.
        
        Args:
            event: Event to enrich
        """
        # Add host information
        if self.config['enrichment'].get('add_host_info', True):
            event['host'] = {
                'name': os.environ.get('COMPUTERNAME', 'unknown'),
                'ip': self._get_local_ip(),
                'os': os.name,
                'platform': sys.platform,
                'processor': os.environ.get('PROCESSOR_IDENTIFIER', '')
            }
        
        # Add process information
        if self.config['enrichment'].get('add_process_info', True):
            event['process'] = {
                'pid': os.getpid(),
                'name': os.path.basename(sys.executable),
                'command_line': ' '.join(sys.argv),
                'cwd': os.getcwd()
            }
        
        # Add user information
        if self.config['enrichment'].get('add_user_info', True):
            event['user'] = {
                'name': os.environ.get('USERNAME', 'unknown'),
                'domain': os.environ.get('USERDOMAIN', ''),
                'is_admin': self._is_admin()
            }
        
        # Add network information
        if self.config['enrichment'].get('add_network_info', True):
            event['network'] = {
                'interfaces': self._get_network_interfaces()
            }
        
        # Add timestamp if not present
        if 'timestamp' not in event:
            event['timestamp'] = datetime.utcnow().isoformat()
        
        # Add event type based on mapping
        event_type = self.config['field_mappings']['event_type_mapping'].get(
            str(event.get('event_id')), 'unknown'
        )
        event['event_type'] = event_type
    
    def _check_alerts(self, event: Dict) -> None:
        """Check if an event matches any alert rules.
        
        Args:
            event: Event to check
        """
        for rule in self.alert_rules:
            if not rule.get('enabled', True):
                continue
                
            try:
                # Simple string-based condition evaluation
                # In a real implementation, use a proper expression evaluator
                if self._evaluate_condition(rule['condition'], event):
                    self._trigger_alert(rule, event)
            except Exception as e:
                logger.error(f"Error evaluating alert rule '{rule.get('name')}': {str(e)}")
    
    def _evaluate_condition(self, condition: str, event: Dict) -> bool:
        """Evaluate a condition against an event.
        
        Args:
            condition: Condition to evaluate
            event: Event to evaluate against
            
        Returns:
            True if the condition is met, False otherwise
        """
        # This is a simplified implementation
        # In a real implementation, use a proper expression evaluator
        try:
            # Convert event to a flat dictionary for easier access
            flat_event = self._flatten_dict(event)
            
            # Replace variable references with their values
            for key, value in flat_event.items():
                condition = condition.replace(key, repr(value))
            
            # Evaluate the condition
            return bool(eval(condition, {'__builtins__': None}, flat_event))
        except Exception as e:
            logger.error(f"Error evaluating condition '{condition}': {str(e)}")
            return False
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Flatten a nested dictionary.
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for nested dictionaries
            sep: Separator between keys
            
        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _trigger_alert(self, rule: Dict, event: Dict) -> None:
        """Trigger an alert.
        
        Args:
            rule: Alert rule that was triggered
            event: Event that triggered the alert
        """
        alert = {
            'alert_id': f"alert_{int(time.time())}",
            'timestamp': datetime.utcnow().isoformat(),
            'name': rule.get('name', 'Unknown Alert'),
            'description': rule.get('description', ''),
            'severity': rule.get('severity', 'medium'),
            'event': event
        }
        
        # Log the alert
        logger.warning(f"ALERT: {alert['name']} - {alert['description']}")
        
        # Update metrics
        ALERTS_GENERATED.inc()
        
        # Send the alert to outputs
        for output in self.outputs:
            try:
                output(alert)
            except Exception as e:
                logger.error(f"Failed to send alert to output: {str(e)}")
    
    def _collect_events(self) -> None:
        """Collect events from the Sysmon collector and add them to the queue."""
        while self.running:
            try:
                # Get new events
                events = self.collector.get_events(
                    limit=self.config['general'].get('max_events_per_poll', 100)
                )
                
                # Add events to the queue
                for event in events:
                    try:
                        self.event_queue.put(event, timeout=1)
                        QUEUE_SIZE.set(self.event_queue.qsize())
                    except Exception as e:
                        logger.error(f"Failed to add event to queue: {str(e)}")
                
                # Sleep before polling again
                time.sleep(self.config['general'].get('poll_interval', 10))
                
            except Exception as e:
                logger.error(f"Error collecting events: {str(e)}")
                time.sleep(5)  # Wait before retrying
    
    def _process_events(self) -> None:
        """Process events from the queue."""
        while self.running:
            try:
                # Get an event from the queue
                try:
                    event = self.event_queue.get(timeout=1)
                    QUEUE_SIZE.set(self.event_queue.qsize())
                except Empty:
                    continue
                
                # Process the event
                processed_event = self._process_event(event)
                
                # Send to outputs
                if processed_event:
                    for output in self.outputs:
                        try:
                            output(processed_event)
                        except Exception as e:
                            logger.error(f"Failed to send event to output: {str(e)}")
                
                # Mark the task as done
                self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error processing event: {str(e)}")
    
    def _start_metrics_server(self) -> None:
        """Start the Prometheus metrics server."""
        if self.config['monitoring'].get('prometheus_enabled', True):
            port = self.config['monitoring'].get('prometheus_port', 8000)
            try:
                start_http_server(port)
                logger.info(f"Started Prometheus metrics server on port {port}")
            except Exception as e:
                logger.error(f"Failed to start Prometheus metrics server: {str(e)}")
    
    def _signal_handler(self, signum, frame) -> None:
        """Handle signals to gracefully shut down the service."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self) -> None:
        """Start the Sysmon service."""
        if self.running:
            logger.warning("Sysmon service is already running")
            return
        
        logger.info("Starting Sysmon service...")
        self.running = True
        
        try:
            # Start metrics server
            self._start_metrics_server()
            
            # Start collector thread
            collector_thread = threading.Thread(
                target=self._collect_events,
                name="SysmonCollector",
                daemon=True
            )
            collector_thread.start()
            self.threads.append(collector_thread)
            
            # Start worker threads
            for i in range(self.config['performance'].get('worker_threads', 4)):
                worker_thread = threading.Thread(
                    target=self._process_events,
                    name=f"EventProcessor-{i}",
                    daemon=True
                )
                worker_thread.start()
                self.threads.append(worker_thread)
            
            logger.info("Sysmon service started")
            
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.error(f"Error in Sysmon service: {str(e)}")
            self.stop()
    
    def stop(self) -> None:
        """Stop the Sysmon service."""
        if not self.running:
            return
        
        logger.info("Stopping Sysmon service...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Clean up resources
        self.collector.close()
        
        logger.info("Sysmon service stopped")
    
    @staticmethod
    def _get_local_ip() -> str:
        """Get the local IP address."""
        try:
            # This is a simplified implementation
            # In a real implementation, you might want to get the primary IP
            return psutil.net_if_addrs()['Ethernet'][1].address
        except:
            return '127.0.0.1'
    
    @staticmethod
    def _is_admin() -> bool:
        """Check if the current user has admin privileges."""
        try:
            return os.getuid() == 0 or ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    @staticmethod
    def _get_network_interfaces() -> Dict[str, Any]:
        """Get information about network interfaces."""
        interfaces = {}
        for name, addrs in psutil.net_if_addrs().items():
            interfaces[name] = [{
                'address': addr.address,
                'netmask': addr.netmask,
                'broadcast': addr.broadcast,
                'ptp': addr.ptp
            } for addr in addrs]
        return interfaces


def run_service(config_path: str = None) -> None:
    """Run the Sysmon service.
    
    Args:
        config_path: Path to the configuration file
    """
    print("Starting Sysmon service...")
    print(f"Python executable: {sys.executable}")
    print(f"Working directory: {os.getcwd()}")
    
    try:
        print("Initializing SysmonService...")
        service = SysmonService(config_path)
        print("Service initialized. Starting...")
        service.start()
        print("Service started successfully!")
        print("Press Ctrl+C to stop the service...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping service...")
            service.stop()
            print("Service stopped.")
            sys.exit(0)
            
    except Exception as e:
        print(f"Error starting Sysmon service: {e}", file=sys.stderr)
        logging.exception("Error in run_service")
        sys.exit(1)


if __name__ == "__main__":
    run_service()
