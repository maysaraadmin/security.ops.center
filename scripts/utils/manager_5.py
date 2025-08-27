"""
HIPS Manager - Coordinates the HIPS detection engine and provides a high-level API.
"""
import os
import json
import logging
import threading
from typing import Dict, List, Optional, Callable, Any
from pathlib import Path
from datetime import datetime

from .detection_engine import HIPSDetectionEngine

class HIPSManager:
    """Manages the HIPS detection engine and provides a high-level API."""
    
    def __init__(self, config_dir: str = None, alert_callback: Callable[[Dict], None] = None):
        """
        Initialize the HIPS manager.
        
        Args:
            config_dir: Directory to store configuration and logs
            alert_callback: Function to call when an alert is generated
        """
        self.logger = logging.getLogger(__name__)
        
        # Set up configuration directory
        if config_dir is None:
            config_dir = os.path.join(os.path.expanduser('~'), '.siem', 'hips')
        
        self.config_dir = os.path.abspath(config_dir)
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Set up file paths
        self.rules_file = os.path.join(self.config_dir, 'rules.json')
        self.whitelist_file = os.path.join(self.config_dir, 'whitelist.json')
        self.alerts_file = os.path.join(self.config_dir, 'alerts.log')
        
        # Initialize detection engine
        self.detection_engine = HIPSDetectionEngine(alert_callback=self._handle_alert)
        
        # Load saved configuration
        self._load_config()
        
        # Initialize state
        self.running = False
        self.start_time = None
        self.alert_callbacks = []
        
        # Add the provided alert callback if any
        if alert_callback:
            self.alert_callbacks.append(alert_callback)
    
    def _load_config(self):
        """Load configuration from disk."""
        try:
            # Load rules
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    saved_rules = json.load(f)
                    self.detection_engine.rules = saved_rules
            
            # Load whitelist
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    saved_whitelist = json.load(f)
                    self.detection_engine.whitelist = saved_whitelist
                    
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}", exc_info=True)
    
    def _save_config(self):
        """Save configuration to disk."""
        try:
            # Save rules
            with open(self.rules_file, 'w') as f:
                json.dump(self.detection_engine.rules, f, indent=2)
            
            # Save whitelist
            with open(self.whitelist_file, 'w') as f:
                json.dump(self.detection_engine.whitelist, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}", exc_info=True)
    
    def _log_alert(self, alert: Dict):
        """Log an alert to the alerts file."""
        try:
            with open(self.alerts_file, 'a') as f:
                timestamp = datetime.fromtimestamp(alert['timestamp']).isoformat()
                log_entry = {
                    'timestamp': timestamp,
                    'rule_id': alert['rule_id'],
                    'rule_name': alert['rule_name'],
                    'severity': alert['severity'],
                    'description': alert['description'],
                    'details': alert['details']
                }
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            self.logger.error(f"Error logging alert: {e}", exc_info=True)
    
    def _handle_alert(self, alert: Dict):
        """Handle an alert from the detection engine."""
        # Log the alert
        self._log_alert(alert)
        
        # Call all registered alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}", exc_info=True)
    
    def start(self):
        """Start the HIPS manager and detection engine."""
        if self.running:
            self.logger.warning("HIPS manager is already running")
            return False
        
        try:
            self.detection_engine.start()
            self.running = True
            self.start_time = datetime.now()
            self.logger.info("HIPS manager started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start HIPS manager: {e}", exc_info=True)
            return False
    
    def stop(self):
        """Stop the HIPS manager and detection engine."""
        if not self.running:
            return
        
        try:
            self.detection_engine.stop()
            self.running = False
            self.logger.info("HIPS manager stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping HIPS manager: {e}", exc_info=True)
    
    def get_status(self) -> Dict:
        """Get the current status of the HIPS manager and detection engine."""
        status = self.detection_engine.get_status()
        status.update({
            'config_dir': self.config_dir,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'uptime': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
            'alerts_file': self.alerts_file,
            'rules_file': self.rules_file,
            'whitelist_file': self.whitelist_file
        })
        return status
    
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent alerts."""
        return self.detection_engine.get_alerts(limit)
    
    def clear_alerts(self):
        """Clear all alerts."""
        self.detection_engine.clear_alerts()
    
    def add_alert_callback(self, callback: Callable[[Dict], None]):
        """Add a callback function to be called when an alert is generated."""
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[Dict], None]):
        """Remove an alert callback function."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    # Rule management
    
    def get_rules(self) -> List[Dict]:
        """Get all rules."""
        return self.detection_engine.rules
    
    def get_rule(self, rule_id: str) -> Optional[Dict]:
        """Get a rule by ID."""
        for rule in self.detection_engine.rules:
            if rule['id'] == rule_id:
                return rule
        return None
    
    def add_rule(self, rule: Dict) -> bool:
        """Add a new rule."""
        # Validate rule
        if not self._validate_rule(rule):
            return False
        
        # Check if rule with same ID already exists
        if any(r['id'] == rule['id'] for r in self.detection_engine.rules):
            self.logger.warning(f"Rule with ID {rule['id']} already exists")
            return False
        
        # Add the rule
        self.detection_engine.rules.append(rule)
        self._save_config()
        return True
    
    def update_rule(self, rule_id: str, rule_updates: Dict) -> bool:
        """Update an existing rule."""
        for i, rule in enumerate(self.detection_engine.rules):
            if rule['id'] == rule_id:
                # Create updated rule
                updated_rule = {**rule, **rule_updates}
                
                # Validate the updated rule
                if not self._validate_rule(updated_rule):
                    return False
                
                # Update the rule
                self.detection_engine.rules[i] = updated_rule
                self._save_config()
                return True
        
        self.logger.warning(f"Rule with ID {rule_id} not found")
        return False
    
    def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule by ID."""
        for i, rule in enumerate(self.detection_engine.rules):
            if rule['id'] == rule_id:
                del self.detection_engine.rules[i]
                self._save_config()
                return True
        
        self.logger.warning(f"Rule with ID {rule_id} not found")
        return False
    
    def enable_rule(self, rule_id: str, enabled: bool = True) -> bool:
        """Enable or disable a rule."""
        return self.update_rule(rule_id, {'enabled': enabled})
    
    def _validate_rule(self, rule: Dict) -> bool:
        """Validate a rule."""
        required_fields = ['id', 'name', 'type', 'severity', 'action', 'enabled']
        
        # Check required fields
        for field in required_fields:
            if field not in rule:
                self.logger.error(f"Rule is missing required field: {field}")
                return False
        
        # Validate rule type
        valid_types = ['file_system', 'registry', 'process', 'network', 'service']
        if rule['type'] not in valid_types:
            self.logger.error(f"Invalid rule type: {rule['type']}")
            return False
        
        # Type-specific validation
        if rule['type'] == 'file_system':
            if 'paths' not in rule or not isinstance(rule['paths'], list):
                self.logger.error("File system rule must have a 'paths' list")
                return False
            if 'patterns' not in rule or not isinstance(rule['patterns'], list):
                self.logger.error("File system rule must have a 'patterns' list")
                return False
        
        elif rule['type'] == 'registry':
            if 'keys' not in rule or not isinstance(rule['keys'], list):
                self.logger.error("Registry rule must have a 'keys' list")
                return False
        
        elif rule['type'] == 'process':
            if 'process_names' not in rule or not isinstance(rule['process_names'], list):
                self.logger.error("Process rule must have a 'process_names' list")
                return False
        
        elif rule['type'] == 'network':
            if 'dest_ips' not in rule and 'dest_ports' not in rule:
                self.logger.error("Network rule must have at least one of 'dest_ips' or 'dest_ports'")
                return False
        
        elif rule['type'] == 'service':
            if 'service_names' not in rule or not isinstance(rule['service_names'], list):
                self.logger.error("Service rule must have a 'service_names' list")
                return False
        
        return True
    
    # Whitelist management
    
    def get_whitelist(self, list_type: str = None) -> Dict:
        """Get the whitelist or a specific whitelist type."""
        if list_type:
            return self.detection_engine.whitelist.get(list_type, [])
        return self.detection_engine.whitelist
    
    def add_to_whitelist(self, list_type: str, item: str) -> bool:
        """Add an item to a whitelist."""
        if list_type not in self.detection_engine.whitelist:
            self.detection_engine.whitelist[list_type] = []
        
        if item not in self.detection_engine.whitelist[list_type]:
            self.detection_engine.whitelist[list_type].append(item)
            self._save_config()
            return True
        
        return False
    
    def remove_from_whitelist(self, list_type: str, item: str) -> bool:
        """Remove an item from a whitelist."""
        if list_type in self.detection_engine.whitelist and item in self.detection_engine.whitelist[list_type]:
            self.detection_engine.whitelist[list_type].remove(item)
            self._save_config()
            return True
        
        return False
    
    # Monitoring control
    
    def set_monitoring(self, monitor_type: str, enabled: bool) -> bool:
        """Enable or disable a monitoring type."""
        valid_types = ['file_system', 'registry', 'processes', 'network', 'services']
        
        if monitor_type not in valid_types:
            self.logger.error(f"Invalid monitoring type: {monitor_type}")
            return False
        
        # Map to the actual attribute name
        attr_name = f'monitor_{monitor_type}'
        
        # Update the setting
        setattr(self.detection_engine, attr_name, enabled)
        self.logger.info(f"{monitor_type.replace('_', ' ').title()} monitoring {'enabled' if enabled else 'disabled'}")
        return True
    
    def get_monitoring_status(self) -> Dict[str, bool]:
        """Get the status of all monitoring types."""
        return {
            'file_system': self.detection_engine.monitor_file_system,
            'registry': self.detection_engine.monitor_registry,
            'processes': self.detection_engine.monitor_processes,
            'network': self.detection_engine.monitor_network,
            'services': self.detection_engine.monitor_services
        }
