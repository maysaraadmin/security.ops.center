"""
Threat Detector Module

This module provides the ThreatDetector class for detecting various types of threats.
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from .detection import DetectionEngine, DetectionRule, EDREvent, ThreatInfo

class ThreatDetector:
    """Detects various types of threats using multiple detection methods."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threat detector with configuration.
        
        Args:
            config: Configuration dictionary for the detector
        """
        self.config = config or {}
        self.logger = logging.getLogger("edr.detection.threat_detector")
        self.detection_engine = DetectionEngine(self.config)
        self._setup_detection_rules()
    
    def _setup_detection_rules(self) -> None:
        """Initialize and configure detection rules."""
        # Add default rules if none exist
        if not self.detection_engine.rules:
            self.logger.info("Initializing default detection rules")
            # Add your default rules here
            pass
    
    def detect_threats(self, event: EDREvent) -> List[ThreatInfo]:
        """Analyze an event for potential threats.
        
        Args:
            event: The event to analyze
            
        Returns:
            List of detected threats (empty if none found)
        """
        try:
            return self.detection_engine.analyze(event)
        except Exception as e:
            self.logger.error(f"Error during threat detection: {e}")
            return []
    
    def add_rule(self, rule: DetectionRule) -> bool:
        """Add a new detection rule.
        
        Args:
            rule: The detection rule to add
            
        Returns:
            bool: True if rule was added successfully
        """
        try:
            self.detection_engine.add_rule(rule)
            return True
        except Exception as e:
            self.logger.error(f"Failed to add rule: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a detection rule.
        
        Args:
            rule_id: ID of the rule to remove
            
        Returns:
            bool: True if rule was removed
        """
        return self.detection_engine.remove_rule(rule_id)
    
    def get_rules(self) -> Dict[str, DetectionRule]:
        """Get all detection rules.
        
        Returns:
            Dictionary of rule ID to DetectionRule objects
        """
        return self.detection_engine.get_rules()
    
    def start(self) -> None:
        """Start the threat detector."""
        self.logger.info("Starting threat detector")
        self.detection_engine.start()
    
    def stop(self) -> None:
        """Stop the threat detector."""
        self.logger.info("Stopping threat detector")
        self.detection_engine.stop()
