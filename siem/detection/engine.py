"""
Threat Detection Engine for SIEM.
Manages multiple threat detectors and processes events through them.
"""
import logging
from typing import Dict, List, Any, Type, Optional, TypeVar, Set
from datetime import datetime, timedelta
import importlib
import inspect

from .base import ThreatDetector, AlertManager

# Type variable for ThreatDetector subclasses
DetectorClass = TypeVar('DetectorClass', bound=ThreatDetector)

class DetectionEngine:
    """
    Central engine for detecting security threats.
    Manages multiple threat detectors and processes events through them.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the detection engine."""
        self.config = config or {}
        self.logger = logging.getLogger("siem.detection.engine")
        
        # Initialize alert manager
        self.alert_manager = AlertManager(
            self.config.get('alerting', {})
        )
        
        # Dictionary to store detector instances
        self.detectors: Dict[str, ThreatDetector] = {}
        
        # Load built-in detectors
        self._load_builtin_detectors()
        
        # Statistics
        self.stats = {
            'processed_events': 0,
            'alerts_triggered': 0,
            'last_processed': None,
            'detector_stats': {}
        }
    
    def _load_builtin_detectors(self) -> None:
        """Load built-in threat detectors."""
        try:
            # Import the detectors module to get all detector classes
            from . import detectors
            
            # Find all detector classes in the module
            for name, obj in inspect.getmembers(detectors):
                if (
                    inspect.isclass(obj) 
                    and issubclass(obj, ThreatDetector) 
                    and obj != ThreatDetector  # Don't include the base class
                ):
                    # Create an instance with default config
                    self.add_detector(obj, {})
            
            self.logger.info(f"Loaded {len(self.detectors)} built-in threat detectors")
                    
        except Exception as e:
            self.logger.error(f"Failed to load built-in detectors: {e}")
    
    def add_detector(
        self, 
        detector_class: Type[DetectorClass], 
        config: Dict[str, Any]
    ) -> str:
        """
        Add a threat detector to the engine.
        
        Args:
            detector_class: The detector class to add
            config: Configuration for the detector
            
        Returns:
            The ID of the added detector
        """
        try:
            # Create detector instance
            detector = detector_class(config)
            detector_id = detector.detector_id
            
            # Add to detectors dictionary
            self.detectors[detector_id] = detector
            
            # Initialize stats for this detector
            self.stats['detector_stats'][detector_id] = {
                'processed': 0,
                'alerts_triggered': 0,
                'last_alert': None
            }
            
            self.logger.info(f"Added threat detector: {detector_id}")
            return detector_id
            
        except Exception as e:
            self.logger.error(f"Failed to add detector {detector_class.__name__}: {e}")
            raise
    
    def remove_detector(self, detector_id: str) -> bool:
        """
        Remove a detector from the engine.
        
        Args:
            detector_id: ID of the detector to remove
            
        Returns:
            True if detector was removed, False if not found
        """
        if detector_id in self.detectors:
            del self.detectors[detector_id]
            if detector_id in self.stats['detector_stats']:
                del self.stats['detector_stats'][detector_id]
            self.logger.info(f"Removed detector: {detector_id}")
            return True
        return False
    
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process an event through all enabled detectors.
        
        Args:
            event: The event to process
            
        Returns:
            List of generated alerts (may be empty)
        """
        # Skip if event is already an alert
        if event.get('event', {}).get('kind') == 'alert':
            return []
        
        alerts = []
        now = datetime.utcnow()
        
        # Update stats
        self.stats['processed_events'] += 1
        self.stats['last_processed'] = now.isoformat()
        
        # Process through all detectors
        for detector_id, detector in self.detectors.items():
            if not detector.enabled:
                continue
                
            try:
                # Update detector stats
                self.stats['detector_stats'][detector_id]['processed'] += 1
                
                # Process the event
                alert = detector.detect(event)
                
                if alert:
                    # Add to alert manager
                    alert_id = self.alert_manager.add_alert(alert)
                    
                    # Update stats
                    self.stats['alerts_triggered'] += 1
                    self.stats['detector_stats'][detector_id]['alerts_triggered'] += 1
                    self.stats['detector_stats'][detector_id]['last_alert'] = now.isoformat()
                    
                    # Add to return list
                    alerts.append(alert)
                    
                    self.logger.debug(
                        f"Detector {detector_id} triggered alert: {alert_id}"
                    )
                        
            except Exception as e:
                self.logger.error(
                    f"Error in detector {detector_id}: {e}",
                    exc_info=True
                )
        
        return alerts
    
    def batch_process(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Process a batch of events through all enabled detectors.
        
        Args:
            events: List of events to process
            
        Returns:
            List of all generated alerts
        """
        all_alerts = []
        
        for event in events:
            alerts = self.process_event(event)
            all_alerts.extend(alerts)
            
        return all_alerts
    
    def get_detector_status(self) -> Dict[str, Any]:
        """
        Get status information for all detectors.
        
        Returns:
            Dictionary with detector status information
        """
        status = {
            'detectors': {},
            'stats': self.stats.copy()
        }
        
        # Add detector details
        for detector_id, detector in self.detectors.items():
            status['detectors'][detector_id] = {
                'name': detector.name,
                'enabled': detector.enabled,
                'severity': detector.severity,
                'stats': self.stats['detector_stats'].get(detector_id, {})
            }
        
        return status
    
    def cleanup(self) -> None:
        """Clean up resources and perform maintenance."""
        # Clean up old alerts
        removed = self.alert_manager.cleanup_old_alerts()
        if removed > 0:
            self.logger.debug(f"Cleaned up {removed} old alerts")
        
        # Perform any other maintenance tasks
        # (e.g., rotating logs, cleaning up temporary files, etc.)
        
        self.logger.debug("Completed cleanup")
    
    def get_alerts(
        self,
        severity: Optional[str] = None,
        time_range: Optional[timedelta] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get alerts matching the specified criteria.
        
        Args:
            severity: Severity level to filter by
            time_range: Maximum age of alerts to return
            limit: Maximum number of alerts to return
            
        Returns:
            List of matching alerts
        """
        return self.alert_manager.get_alerts(
            severity=severity,
            time_range=time_range,
            limit=limit
        )
    
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an alert by ID.
        
        Args:
            alert_id: ID of the alert to retrieve
            
        Returns:
            The alert, or None if not found
        """
        return self.alert_manager.get_alert(alert_id)
