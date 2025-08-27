"""
EDR Agent - Core functionality for the lightweight endpoint monitoring and response agent.
"""
import os
import sys
import time
import signal
import logging
import platform
import threading
import subprocess
from typing import Dict, List, Optional, Callable, Any
from dataclasses import asdict
import psutil
from .models import Platform, SystemInfo, AgentConfig
from .collectors import get_platform_collector
from .utils import get_system_info, ensure_directory, drop_privileges

logger = logging.getLogger('edr.agent')

class EDRAgent:
    """
    Lightweight EDR agent for endpoint monitoring and response.
    
    Features:
    - Cross-platform support (Windows, macOS, Linux)
    - Low resource usage
    - Real-time monitoring
    - Configurable collection intervals
    - Secure communication with management server
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the EDR agent with optional configuration."""
        self.running = False
        self.threads: List[threading.Thread] = []
        self.collectors: List[Any] = []
        self.config = self._load_config(config_path)
        self.system_info = get_system_info()
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
        # Set up logging
        self._setup_logging()
        
        logger.info(f"Initializing EDR Agent on {self.system_info.os_name}")
        
    def _load_config(self, config_path: Optional[str] = None) -> AgentConfig:
        """Load agent configuration."""
        # Default configuration
        default_config = AgentConfig(
            agent_id=os.getenv('EDR_AGENT_ID', f"agent-{os.urandom(4).hex()}"),
            server_url=os.getenv('EDR_SERVER_URL', 'https://edr-server.example.com'),
            api_key=os.getenv('EDR_API_KEY', ''),
            checkin_interval=300,  # 5 minutes
            max_cpu_percent=10,    # Max CPU usage %
            max_memory_mb=100,     # Max memory usage in MB
            debug=False,
            collectors=[
                'process',
                'file_system',
                'network',
                'system_events'
            ],
            log_level='INFO',
            log_file='/var/log/edr/agent.log',
            data_dir='/var/lib/edr',
            proxy=None,
            verify_ssl=True,
            tags=[]
        )
        
        # TODO: Load configuration from file if provided
        # For now, just return default config
        return default_config
    
    def _setup_logging(self) -> None:
        """Configure logging for the agent."""
        log_level = getattr(logging, self.config.log_level.upper(), logging.INFO)
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        
        # Create log directory if it doesn't exist
        if self.config.log_file:
            log_dir = os.path.dirname(os.path.abspath(self.config.log_file))
            ensure_directory(log_dir)
            
            # Set up file handler
            file_handler = logging.FileHandler(self.config.log_file)
            file_handler.setLevel(log_level)
            file_formatter = logging.Formatter(log_format)
            file_handler.setFormatter(file_formatter)
            logging.getLogger().addHandler(file_handler)
        
        # Set up console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(log_format)
        console_handler.setFormatter(console_formatter)
        logging.getLogger().addHandler(console_handler)
        
        # Set root logger level
        logging.getLogger().setLevel(log_level)
    
    def _check_resources(self) -> bool:
        """Check if system resources are within limits."""
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > self.config.max_cpu_percent:
                logger.warning(f"CPU usage too high: {cpu_percent}% > {self.config.max_cpu_percent}%")
                return False
            
            # Check memory usage
            process = psutil.Process()
            mem_info = process.memory_info()
            mem_mb = mem_info.rss / (1024 * 1024)  # Convert to MB
            if mem_mb > self.config.max_memory_mb:
                logger.warning(f"Memory usage too high: {mem_mb:.2f}MB > {self.config.max_memory_mb}MB")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking system resources: {e}")
            return False
    
    def _setup_collectors(self) -> None:
        """Initialize data collectors based on platform and configuration."""
        logger.info("Setting up data collectors...")
        
        # Get platform-specific collector
        collector_cls = get_platform_collector()
        
        # Initialize collectors based on configuration
        for collector_name in self.config.collectors:
            try:
                collector = collector_cls(collector_name, self.config)
                self.collectors.append(collector)
                logger.info(f"Initialized collector: {collector_name}")
            except Exception as e:
                logger.error(f"Failed to initialize collector {collector_name}: {e}")
    
    def _collect_data(self) -> Dict[str, Any]:
        """Collect data from all enabled collectors."""
        data = {
            'timestamp': time.time(),
            'agent_id': self.config.agent_id,
            'system': asdict(self.system_info),
            'data': {}
        }
        
        for collector in self.collectors:
            try:
                if self._check_resources():
                    collector_data = collector.collect()
                    data['data'][collector.name] = collector_data
            except Exception as e:
                logger.error(f"Error in collector {collector.name}: {e}")
        
        return data
    
    def _send_data(self, data: Dict[str, Any]) -> bool:
        """Send collected data to the management server."""
        # TODO: Implement secure communication with management server
        # For now, just log the data
        logger.debug(f"Collected data: {data}")
        return True
    
    def _checkin_loop(self) -> None:
        """Main check-in loop for the agent."""
        logger.info("Starting agent check-in loop")
        
        while self.running:
            try:
                # Collect data
                data = self._collect_data()
                
                # Send data to server
                success = self._send_data(data)
                
                if success:
                    logger.debug("Successfully sent check-in data")
                else:
                    logger.warning("Failed to send check-in data")
                
            except Exception as e:
                logger.error(f"Error in check-in loop: {e}")
            
            # Sleep until next check-in
            time.sleep(self.config.checkin_interval)
    
    def _handle_signal(self, signum, frame) -> None:
        """Handle OS signals for graceful shutdown."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()
    
    def start(self) -> None:
        """Start the EDR agent."""
        if self.running:
            logger.warning("Agent is already running")
            return
        
        logger.info("Starting EDR Agent")
        self.running = True
        
        try:
            # Drop privileges if running as root
            if os.name != 'nt' and os.geteuid() == 0:
                drop_privileges()
            
            # Set up collectors
            self._setup_collectors()
            
            # Start check-in thread
            checkin_thread = threading.Thread(
                target=self._checkin_loop,
                name="EDR-CheckIn",
                daemon=True
            )
            self.threads.append(checkin_thread)
            checkin_thread.start()
            
            logger.info("EDR Agent started successfully")
            
            # Keep the main thread alive
            while self.running and any(t.is_alive() for t in self.threads):
                time.sleep(1)
            
        except Exception as e:
            logger.critical(f"Fatal error in agent: {e}", exc_info=True)
            self.stop()
    
    def stop(self) -> None:
        """Stop the EDR agent."""
        if not self.running:
            return
            
        logger.info("Stopping EDR Agent")
        self.running = False
        
        # Stop all collectors
        for collector in self.collectors:
            try:
                if hasattr(collector, 'stop'):
                    collector.stop()
            except Exception as e:
                logger.error(f"Error stopping collector {collector.name}: {e}")
        
        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("EDR Agent stopped")
