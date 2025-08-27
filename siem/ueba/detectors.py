"""
Anomaly detectors for User and Entity Behavior Analytics (UEBA).
"""
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import logging
import re
import hashlib
from collections import defaultdict, deque
import numpy as np

from .base import BaseBehaviorModel, UEBAEngine

class FailedLoginDetector(BaseBehaviorModel):
    """Detects patterns of failed login attempts that may indicate brute force attacks."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the failed login detector."""
        super().__init__(config or {})
        self.window_minutes = int(self.config.get('window_minutes', 15))
        self.failed_attempts_threshold = int(self.config.get('failed_attempts_threshold', 5))
        self.whitelisted_ips = set(self.config.get('whitelisted_ips', []))
        
        # Track failed login attempts
        self.failed_logins = defaultdict(list)  # ip -> [(timestamp, username), ...]
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract features related to failed logins."""
        # Only process authentication events
        if 'event' not in event or 'authentication' not in event['event'].get('category', []):
            return None
        
        # Skip if source IP is missing or whitelisted
        source_ip = event.get('source', {}).get('ip')
        if not source_ip or source_ip in self.whitelisted_ips:
            return None
        
        username = event.get('user', {}).get('name', 'unknown')
        timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
        
        # Track failed logins
        if event.get('event', {}).get('outcome') == 'failure':
            self.failed_logins[source_ip].append((timestamp, username))
            
            # Clean up old entries
            cutoff = timestamp - timedelta(minutes=self.window_minutes)
            self.failed_logins[source_ip] = [
                (ts, user) for ts, user in self.failed_logins[source_ip]
                if ts >= cutoff
            ]
            
            # Calculate features
            recent_attempts = [
                ts for ts, _ in self.failed_logins[source_ip]
                if ts >= timestamp - timedelta(minutes=self.window_minutes)
            ]
            
            unique_users = len({user for _, user in self.failed_logins[source_ip]})
            
            return {
                'failed_attempts': float(len(recent_attempts)),
                'unique_users': float(unique_users),
                'attempt_rate': float(len(recent_attempts)) / self.window_minutes,
                'is_high_risk_ip': 1.0 if self._is_high_risk_ip(source_ip) else 0.0
            }
        
        return None
    
    def _is_high_risk_ip(self, ip: str) -> bool:
        """Check if an IP is considered high risk."""
        # In a real implementation, this would check threat intelligence feeds
        return False


class DataExfiltrationDetector(BaseBehaviorModel):
    """Detects potential data exfiltration attempts."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the data exfiltration detector."""
        super().__init__(config or {})
        self.suspicious_domains = set(self.config.get('suspicious_domains', []))
        self.sensitive_data_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.config.get('sensitive_data_patterns', [
                r'\b(?:ssn|social security|credit.?card|password|api[_-]?key)\b',
                r'\b\d{3}[-\.]?\d{2}[-\.]?\d{4}\b',  # SSN-like patterns
                r'\b\d{4}[-\.]?\d{4}[-\.]?\d{4}[-\.]?\d{4}\b'  # Credit card-like
            ])
        ]
        
        # Track data transfers by user and destination
        self.data_transfers = defaultdict(lambda: defaultdict(int))  # user -> {destination -> bytes}
        self.window_hours = int(self.config.get('window_hours', 24))
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract features related to data exfiltration."""
        # Only process network events with data transfer
        if 'network' not in event or 'bytes' not in event['network']:
            return None
        
        # Skip if no user or destination information
        user = event.get('user', {}).get('name')
        destination = event.get('destination', {})
        dest_ip = destination.get('ip')
        dest_domain = destination.get('domain')
        
        if not user or (not dest_ip and not dest_domain):
            return None
        
        # Get data size in MB
        bytes_transferred = int(event['network']['bytes'])
        mb_transferred = bytes_transferred / (1024 * 1024)
        
        # Update data transfer tracking
        dest_key = dest_domain or dest_ip
        self.data_transfers[user][dest_key] += mb_transferred
        
        # Clean up old data (simplified for example)
        # In a real implementation, you'd track timestamps and clean up old entries
        
        # Check for suspicious patterns in the data
        suspicious_content = False
        if 'message' in event:
            content = str(event['message']).lower()
            suspicious_content = any(
                pattern.search(content) 
                for pattern in self.sensitive_data_patterns
            )
        
        # Calculate features
        is_suspicious_domain = 1.0 if dest_domain in self.suspicious_domains else 0.0
        
        return {
            'data_volume_mb': mb_transferred,
            'is_suspicious_domain': is_suspicious_domain,
            'suspicious_content': 1.0 if suspicious_content else 0.0,
            'unusual_destination': self._is_unusual_destination(user, dest_key),
            'data_velocity': self._calculate_data_velocity(user, mb_transferred)
        }
    
    def _is_unusual_destination(self, user: str, destination: str) -> float:
        """Check if the destination is unusual for this user."""
        # In a real implementation, this would use historical data
        # to determine if the destination is unusual for this user
        return 0.0
    
    def _calculate_data_velocity(self, user: str, current_transfer: float) -> float:
        """Calculate how unusual this data transfer is compared to the user's baseline."""
        # In a real implementation, this would compare to historical baselines
        return current_transfer / 100.0  # Simplified for example


class PrivilegeEscalationDetector(BaseBehaviorModel):
    """Detects potential privilege escalation attempts."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the privilege escalation detector."""
        super().__init__(config or {})
        self.privileged_commands = set(self.config.get('privileged_commands', [
            'sudo', 'su', 'runas', 'psexec', 'schtasks', 'at', 'crontab'
        ]))
        
        # Track user privilege changes
        self.user_privileges = {}  # user -> current_privilege_level
        self.privilege_changes = defaultdict(list)  # user -> [(timestamp, from_priv, to_priv)]
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract features related to privilege escalation."""
        # Only process process or authentication events
        if 'event' not in event:
            return None
        
        event_type = event.get('event', {}).get('type', [])
        if not isinstance(event_type, list):
            event_type = [event_type]
        
        user = event.get('user', {}).get('name')
        if not user:
            return None
        
        features = {}
        
        # Check for privilege changes
        if 'authentication' in event_type:
            # This is a simplified example - in reality, you'd parse the actual privilege level
            new_privilege = event.get('event', {}).get('outcome') == 'success'
            
            if user in self.user_privileges and self.user_privileges[user] != new_privilege:
                # Privilege change detected
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                self.privilege_changes[user].append(
                    (timestamp, self.user_privileges[user], new_privilege)
                )
                
                features['privilege_change'] = 1.0
                features['new_privilege_level'] = 1.0 if new_privilege else 0.0
            
            self.user_privileges[user] = new_privilege
        
        # Check for privileged commands
        if 'process' in event_type and 'command_line' in event.get('process', {}):
            cmd = event['process']['command_line'].lower()
            if any(priv_cmd in cmd for priv_cmd in self.privileged_commands):
                features['privileged_command'] = 1.0
                
                # Check if this is unusual for the user
                if not self.user_privileges.get(user, False):
                    features['unprivileged_privileged_command'] = 1.0
        
        return features if features else None


class InsiderThreatDetector(BaseBehaviorModel):
    """Detects potential insider threats by analyzing user behavior patterns."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the insider threat detector."""
        super().__init__(config or {})
        
        # User behavior profiles (simplified for example)
        self.user_profiles = defaultdict(dict)
        
        # Track user activities
        self.user_activities = defaultdict(list)  # user -> [(timestamp, activity_type, risk_score)]
        self.activity_window = int(self.config.get('activity_window_days', 30))
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract features related to insider threats."""
        user = event.get('user', {}).get('name')
        if not user:
            return None
        
        timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
        
        # Classify the activity
        activity_type, risk_score = self._classify_activity(event)
        
        # Update user activity log
        self.user_activities[user].append((timestamp, activity_type, risk_score))
        
        # Clean up old activities
        cutoff = timestamp - timedelta(days=self.activity_window)
        self.user_activities[user] = [
            (ts, act, score) for ts, act, score in self.user_activities[user]
            if ts >= cutoff
        ]
        
        # Calculate behavior metrics
        recent_activities = [
            (act, score) for ts, act, score in self.user_activities[user]
            if ts >= timestamp - timedelta(days=7)
        ]
        
        if not recent_activities:
            return None
        
        activities, scores = zip(*recent_activities)
        
        return {
            'activity_risk': float(np.mean(scores)),
            'unusual_activity_time': self._check_unusual_time(user, timestamp),
            'access_pattern_change': self._check_access_pattern_change(user, activity_type),
            'data_access_velocity': self._calculate_data_access_velocity(user, event),
            'off_hours_activity': self._check_off_hours_activity(user, timestamp)
        }
    
    def _classify_activity(self, event: Dict[str, Any]) -> Tuple[str, float]:
        """Classify the activity type and assign a risk score."""
        # This is a simplified example - in reality, you'd have more sophisticated classification
        event_type = event.get('event', {}).get('type', 'unknown')
        
        if isinstance(event_type, list):
            event_type = event_type[0] if event_type else 'unknown'
        
        # Map event types to risk scores (0-1)
        risk_scores = {
            'authentication': 0.1,
            'file_access': 0.3,
            'process': 0.5,
            'network': 0.7,
            'admin': 0.9
        }
        
        return event_type, risk_scores.get(event_type, 0.5)
    
    def _check_unusual_time(self, user: str, timestamp: datetime) -> float:
        """Check if the activity is happening at an unusual time for the user."""
        # In a real implementation, this would compare to the user's historical patterns
        hour = timestamp.hour
        is_work_hours = 9 <= hour < 17
        return 0.0 if is_work_hours else 0.7
    
    def _check_access_pattern_change(self, user: str, activity_type: str) -> float:
        """Check if the user's access pattern has changed."""
        # In a real implementation, this would compare to historical patterns
        return 0.0
    
    def _calculate_data_access_velocity(self, user: str, event: Dict[str, Any]) -> float:
        """Calculate how much data the user is accessing compared to their baseline."""
        # In a real implementation, this would compare to historical baselines
        return 0.0
    
    def _check_off_hours_activity(self, user: str, timestamp: datetime) -> float:
        """Check if the activity is happening outside normal working hours."""
        # Simple check for off-hours (8 PM to 6 AM)
        hour = timestamp.hour
        is_off_hours = hour < 6 or hour >= 20
        return 1.0 if is_off_hours else 0.0


class UEBAWithDetectors(UEBAEngine):
    """Extended UEBA engine with pre-configured detectors."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize with default detectors."""
        super().__init__(config)
        
        # Add specialized detectors
        self.detectors = [
            FailedLoginDetector(self.config.get('failed_login_config', {})),
            DataExfiltrationDetector(self.config.get('exfiltration_config', {})),
            PrivilegeEscalationDetector(self.config.get('privilege_config', {})),
            InsiderThreatDetector(self.config.get('insider_threat_config', {}))
        ]
        
        self.logger.info(f"Initialized UEBA with {len(self.detectors)} specialized detectors")
    
    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process events through all models and detectors."""
        if not events:
            return []
        
        all_results = []
        
        # Process with base models
        base_results = super().process_events(events)
        all_results.extend(base_results)
        
        # Process with specialized detectors
        for detector in self.detectors:
            try:
                results = detector.predict(events)
                all_results.extend(results)
                
                self.logger.debug(
                    f"Processed {len(events)} events with {detector.model_id}, "
                    f"found {sum(1 for r in results if r['is_anomaly'])} anomalies"
                )
                
            except Exception as e:
                self.logger.error(f"Error processing events with {detector.model_id}: {e}", exc_info=True)
        
        return all_results
    
    def train_models(self, events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Train all models and detectors."""
        if not events:
            return {}
        
        results = {}
        
        # Train base models
        base_results = super().train_models(events)
        results.update(base_results)
        
        # Train detectors
        for detector in self.detectors:
            try:
                self.logger.info(f"Training {detector.model_id} on {len(events)} events")
                result = detector.train(events)
                results[detector.model_id] = result
                
                if result.get('success'):
                    self.logger.info(
                        f"Successfully trained {detector.model_id} on {result['samples_used']} samples"
                    )
                else:
                    self.logger.warning(
                        f"Training failed for {detector.model_id}: {result.get('message', 'Unknown error')}"
                    )
                
            except Exception as e:
                error_msg = f"Error training {detector.model_id}: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                results[detector.model_id] = {
                    'success': False,
                    'message': error_msg
                }
        
        return results
    
    def save_models(self, base_dir: str = "models/ueba") -> Dict[str, str]:
        """Save all models and detectors to disk."""
        saved_paths = super().save_models(base_dir)
        
        for detector in self.detectors:
            try:
                model_dir = f"{base_dir}/{detector.model_id}"
                save_path = detector.save(model_dir)
                saved_paths[detector.model_id] = save_path
                self.logger.info(f"Saved {detector.model_id} to {save_path}")
            except Exception as e:
                self.logger.error(f"Error saving {detector.model_id}: {e}", exc_info=True)
                saved_paths[detector.model_id] = f"error: {str(e)}"
        
        return saved_paths
