"""
Monitoring Service for SIEM

This service integrates metrics collection, alerting, and health checks
into the SIEM system.
"""

import logging
import threading
import time
from typing import Dict, Any, List, Optional
from pathlib import Path

# Import monitoring components
from ..monitoring.metrics import metrics_collector, MetricsExporter, ConsoleExporter, PrometheusExporter, MetricsManager
from ..monitoring.alerts import alert_manager, AlertRule, AlertSeverity, CommonAlertRules
from ..monitoring.health import health_check_runner, setup_default_checks, HealthStatus

logger = logging.getLogger('siem.monitoring')

class MonitoringService:
    """Service for managing monitoring functionality in the SIEM."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the monitoring service.
        
        Args:
            config: Configuration dictionary for monitoring
        """
        self.config = config
        self.metrics_manager: Optional[MetricsManager] = None
        self.exporters: List[MetricsExporter] = []
        self.running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        
        # Initialize components
        self._init_metrics()
        self._init_alerts()
        self._init_health_checks()
    
    def _init_metrics(self) -> None:
        """Initialize metrics collection and exporters."""
        # Create metrics manager
        self.metrics_manager = MetricsManager(metrics_collector)
        
        # Configure exporters from config
        if 'metrics' in self.config and 'exporters' in self.config['metrics']:
            for exporter_config in self.config['metrics']['exporters']:
                if exporter_config['type'] == 'console':
                    self.exporters.append(ConsoleExporter(
                        format=exporter_config.get('format', 'text')
                    ))
                elif exporter_config['type'] == 'prometheus':
                    prom_exporter = PrometheusExporter(
                        port=exporter_config.get('port', 9090)
                    )
                    if prom_exporter.start():
                        self.exporters.append(prom_exporter)
                    else:
                        logger.error("Failed to start Prometheus exporter")
        
        # Add exporters to metrics manager
        for exporter in self.exporters:
            self.metrics_manager.add_exporter(exporter)
        
        logger.info(f"Initialized metrics with {len(self.exporters)} exporters")
    
    def _init_alerts(self) -> None:
        """Initialize alerting rules and configuration."""
        # Add common alert rules
        if 'alerts' in self.config and 'rules' in self.config['alerts']:
            for rule_config in self.config['alerts']['rules']:
                self._add_alert_rule(rule_config)
        
        # Add system alert rules
        self._add_system_alert_rules()
        
        # Start alert processing
        alert_manager.start_processing()
        logger.info("Initialized alerting system")
    
    def _add_alert_rule(self, rule_config: Dict[str, Any]) -> None:
        """Add an alert rule from configuration."""
        try:
            # Handle different rule types
            if rule_config['type'] == 'threshold':
                self._add_threshold_alert_rule(rule_config)
            elif rule_config['type'] == 'rate':
                self._add_rate_alert_rule(rule_config)
            # Add more rule types as needed
            
        except Exception as e:
            logger.error(f"Failed to add alert rule {rule_config.get('name', 'unknown')}: {e}")
    
    def _add_threshold_alert_rule(self, rule_config: Dict[str, Any]) -> None:
        """Add a threshold-based alert rule."""
        def condition(metrics):
            value = metrics.get(rule_config['metric'])
            if value is None:
                return False
            return value > rule_config['threshold']
        
        alert_rule = AlertRule(
            name=rule_config['name'],
            description=rule_config.get('description', ''),
            condition=condition,
            severity=AlertSeverity[rule_config.get('severity', 'MEDIUM').upper()],
            source='siem',
            labels=rule_config.get('labels', {}),
            annotations=rule_config.get('annotations', {}),
            throttle_seconds=rule_config.get('throttle_seconds', 300)
        )
        
        alert_manager.add_rule(alert_rule)
        logger.debug(f"Added threshold alert rule: {rule_config['name']}")
    
    def _add_rate_alert_rule(self, rule_config: Dict[str, Any]) -> None:
        """Add a rate-based alert rule."""
        # This would be more sophisticated in a real implementation
        # Tracking rates would require maintaining state between checks
        def condition(metrics):
            # This is a simplified example
            # In practice, you'd want to track rates over time
            return False
        
        alert_rule = AlertRule(
            name=rule_config['name'],
            description=rule_config.get('description', ''),
            condition=condition,
            severity=AlertSeverity[rule_config.get('severity', 'MEDIUM').upper()],
            source='siem',
            labels=rule_config.get('labels', {}),
            annotations=rule_config.get('annotations', {}),
            throttle_seconds=rule_config.get('throttle_seconds', 300)
        )
        
        alert_manager.add_rule(alert_rule)
        logger.debug(f"Added rate alert rule: {rule_config['name']}")
    
    def _add_system_alert_rules(self) -> None:
        """Add system-level alert rules."""
        # High CPU usage
        alert_manager.add_rule(CommonAlertRules.high_cpu_usage(
            warning_threshold=80.0,
            critical_threshold=90.0
        ))
        
        # High memory usage
        alert_manager.add_rule(CommonAlertRules.high_memory_usage(
            warning_threshold=80.0,
            critical_threshold=90.0
        ))
        
        # High error rate
        alert_manager.add_rule(CommonAlertRules.high_error_rate(
            error_threshold=0.1,  # 10% error rate
            window_minutes=5
        ))
        
        logger.debug("Added system alert rules")
    
    def _init_health_checks(self) -> None:
        """Initialize health checks."""
        # Setup default health checks
        setup_default_checks()
        
        # Add custom health checks from config
        if 'health_checks' in self.config:
            self._add_custom_health_checks(self.config['health_checks'])
        
        logger.info("Initialized health checks")
    
    def _add_custom_health_checks(self, health_checks_config: Dict[str, Any]) -> None:
        """Add custom health checks from configuration."""
        # This would be implemented to add custom health checks
        # based on the configuration
        pass
    
    def start(self) -> None:
        """Start the monitoring service."""
        if self.running:
            logger.warning("Monitoring service is already running")
            return
        
        self.running = True
        self._stop_event.clear()
        
        # Start metrics collection
        if self.metrics_manager:
            self.metrics_manager.start(interval=60.0)
        
        # Start health check runner
        health_check_runner.start(interval=60.0)
        
        # Start monitoring thread
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name='monitoring_service',
            daemon=True
        )
        self._thread.start()
        
        logger.info("Started monitoring service")
    
    def stop(self) -> None:
        """Stop the monitoring service."""
        if not self.running:
            return
        
        self.running = False
        self._stop_event.set()
        
        # Stop metrics collection
        if self.metrics_manager:
            self.metrics_manager.stop()
        
        # Stop health check runner
        health_check_runner.stop()
        
        # Wait for thread to finish
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        
        logger.info("Stopped monitoring service")
    
    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while not self._stop_event.is_set():
            try:
                # Check system health
                self._check_system_health()
                
                # Process any pending monitoring tasks
                self._process_monitoring_tasks()
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
            
            # Sleep for a bit
            self._stop_event.wait(30.0)  # Check every 30 seconds
    
    def _check_system_health(self) -> None:
        """Check system health and update metrics."""
        # This would check various system metrics and update the metrics collector
        pass
    
    def _process_monitoring_tasks(self) -> None:
        """Process any pending monitoring tasks."""
        # This would handle any periodic monitoring tasks
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the monitoring service."""
        return {
            'running': self.running,
            'metrics': {
                'exporters': [str(e) for e in self.exporters]
            },
            'alerts': {
                'active': len(alert_manager.get_active_alerts()),
                'rules': len(alert_manager.rules)
            },
            'health_checks': {
                'total': len(health_check_runner.checks),
                'last_run': health_check_runner._last_run.isoformat() if hasattr(health_check_runner, '_last_run') and health_check_runner._last_run else None
            }
        }


def create_monitoring_service(config: Dict[str, Any]) -> MonitoringService:
    """Create and configure a monitoring service.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Configured MonitoringService instance
    """
    return MonitoringService(config)
