""\nCollector Manager for the SIEM system.\nManages multiple log collectors and aggregates their output.\n"""\nimport logging\nfrom typing import Dict, List, Any, Type, Optional\nfrom concurrent.futures import ThreadPoolExecutor, as_completed\nimport time\nimport signal\nimport sys\n\nfrom .base import BaseCollector\n\nclass CollectorManager:\n    """Manages multiple log collectors and aggregates their output."""\n    \n    def __init__(self, config: Dict[str, Any] = None):\n        """Initialize the collector manager.\n        \n        Args:\n            config: Configuration dictionary\n        """\n        self.config = config or {}\n        self.logger = logging.getLogger("siem.collector.manager")\n        self.collectors: Dict[str, BaseCollector] = {}\n        self.running = False\n        self.executor = ThreadPoolExecutor(\n            max_workers=self.config.get('max_workers', 5),\n            thread_name_prefix='siem_collector_'\n        )\n        \n        # Register signal handlers for graceful shutdown\n        signal.signal(signal.SIGINT, self._signal_handler)\n        signal.signal(signal.SIGTERM, self._signal_handler)\n    \n    def _signal_handler(self, signum, frame):\n        """Handle shutdown signals."""\n        self.logger.info(f"Received signal {signum}, shutting down...")\n        self.stop()\n        sys.exit(0)\n    \n    def add_collector(self, collector_id: str, collector_class: Type[BaseCollector], \n                     collector_config: Dict[str, Any] = None) -> None:\n        """Add a new collector.\n        \n        Args:\n            collector_id: Unique identifier for the collector\n            collector_class: Collector class (subclass of BaseCollector)\n            collector_config: Configuration for the collector\n        """\n        if collector_id in self.collectors:\n            self.logger.warning(f"Collector {collector_id} already exists, replacing")\n        \n        try:\n            collector = collector_class(collector_config or {})\n            self.collectors[collector_id] = collector\n            self.logger.info(f"Added collector: {collector_id} ({collector_class.__name__})")\n        except Exception as e:\n            self.logger.error(f"Failed to initialize collector {collector_id}: {e}")\n            raise\n    \n    def remove_collector(self, collector_id: str) -> bool:\n        """Remove a collector.\n        \n        Args:\n            collector_id: ID of the collector to remove\n            \n        Returns:\n            True if collector was removed, False if not found\n        """\n        if collector_id in self.collectors:\n            collector = self.collectors.pop(collector_id)\n            try:\n                collector.stop()\n            except Exception as e:\n                self.logger.error(f"Error stopping collector {collector_id}: {e}")\n            return True\n        return False\n    \n    def collect_all(self) -> List[Dict[str, Any]]:\n        """Collect logs from all collectors in parallel.\n        \n        Returns:\n            List of collected log entries\n        """\n        all_entries = []\n        futures = {}\n        \n        # Start collection tasks\n        for collector_id, collector in self.collectors.items():\n            future = self.executor.submit(self._collect_safe, collector_id, collector)\n            futures[future] = collector_id\n        \n        # Process results as they complete\n        for future in as_completed(futures):\n            collector_id = futures[future]\n            try:\n                entries = future.result()\n                if entries:\n                    all_entries.extend(entries)\n                    self.logger.debug(\n                        f"Collected {len(entries)} entries from {collector_id}"\n                    )\n            except Exception as e:\n                self.logger.error(\n                    f"Error collecting from {collector_id}: {e}",\n                    exc_info=True\n                )\n        \n        return all_entries\n    \n    def _collect_safe(self, collector_id: str, collector: BaseCollector) -> List[Dict[str, Any]]:\n        """Safely collect logs from a single collector.\n        \n        Args:\n            collector_id: ID of the collector\n            collector: Collector instance\n            \n        Returns:\n            List of collected log entries or empty list on error\n        """\n        try:\n            return collector.collect() or []\n        except Exception as e:\n            self.logger.error(\n                f"Unhandled exception in collector {collector_id}: {e}",\n                exc_info=True\n            )\n            return []\n    \n    def start(self) -> None:\n        """Start all collectors."""\n        if self.running:\n            self.logger.warning("Collector manager is already running")\n            return\n            \n        self.running = True\n        \n        # Start all collectors\n        for collector_id, collector in self.collectors.items():
            try:
                collector.start()
                self.logger.info(f"Started collector: {collector_id}")
            except Exception as e:
                self.logger.error(f"Failed to start collector {collector_id}: {e}")
                
        self.logger.info(f"Collector manager started with {len(self.collectors)} collectors")
    
    def stop(self) -> None:
        """Stop all collectors and clean up resources."""
        if not self.running:
            return
            
        self.logger.info("Stopping collector manager...")
        self.running = False
        
        # Stop all collectors
        for collector_id, collector in self.collectors.items():
            try:
                collector.stop()
                self.logger.info(f"Stopped collector: {collector_id}")
            except Exception as e:
                self.logger.error(f"Error stopping collector {collector_id}: {e}")
        
        # Shutdown the executor
        self.executor.shutdown(wait=True)
        self.logger.info("Collector manager stopped")
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
