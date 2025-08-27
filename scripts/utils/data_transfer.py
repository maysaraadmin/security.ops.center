"""
Data transfer behavior analyzer for UEBA.

This module provides analysis of data transfer patterns to detect anomalies
such as data exfiltration or unusual data movement.
"""
import logging
from datetime import datetime
from typing import Dict, Any
import hashlib

from .base import BaseAnalyzer

logger = logging.getLogger('siem.ueba.analyzers.data_transfer')

class DataTransferAnalyzer(BaseAnalyzer):
    """Analyzes data transfer patterns to detect anomalies."""
    
    def __init__(self, model_type: str = 'statistical'):
        super().__init__(model_type)
        self.sensitive_destinations = {
            'external_cloud',
            'usb_device',
            'external_email'
        }
    
    def _is_data_transfer_event(self, event_data: Dict[str, Any]) -> bool:
        """Check if the event is a data transfer event."""
        event_type = event_data.get('event_type', '').lower()
        return any(term in event_type for term in ['transfer', 'upload', 'download', 'copy', 'export'])
    
    def _hash_sensitive_value(self, value: str) -> str:
        """Hash sensitive values for privacy."""
        if not value:
            return ''
        return hashlib.sha256(value.encode()).hexdigest()
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address by hashing it."""
        if not ip_address:
            return '0.0.0.0'
        return hashlib.md5(ip_address.encode()).hexdigest()
    
    def extract_features(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data transfer features from an event."""
        if not self._is_data_transfer_event(event_data):
            return {}
        
        features = {}
        
        # Extract basic info
        timestamp = event_data.get('timestamp')
        user = event_data.get('user', {})
        
        # Time-based features
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
                features['hour_of_day'] = dt.hour
                features['day_of_week'] = dt.weekday()
            except (ValueError, AttributeError):
                pass
        
        # User features
        if user:
            features['user_id'] = self._hash_sensitive_value(user.get('id', ''))
        
        # Transfer details
        transfer = event_data.get('transfer', {})
        if transfer:
            # Size in MB
            size_mb = transfer.get('size_bytes', 0) / (1024 * 1024)
            features['transfer_size_mb'] = size_mb
            
            # Source and destination
            source = transfer.get('source', '').lower()
            destination = transfer.get('destination', '').lower()
            
            features['source_type'] = source
            features['destination_type'] = destination
            
            # Check if destination is potentially sensitive
            features['sensitive_destination'] = 1 if any(
                dest in destination for dest in self.sensitive_destinations
            ) else 0
            
            # Protocol/application used
            features['protocol'] = transfer.get('protocol', 'unknown').lower()
        
        return features
    
    def describe_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """Generate a human-readable description of a data transfer anomaly."""
        if not features:
            return "Suspicious data transfer detected"
            
        parts = []
        
        size_mb = features.get('transfer_size_mb', 0)
        if size_mb > 100:  # Large transfer
            parts.append(f"large data transfer ({size_mb:.2f}MB)")
        
        if features.get('sensitive_destination') == 1:
            parts.append(f"to sensitive destination: {features.get('destination_type', 'unknown')}")
        
        protocol = features.get('protocol')
        if protocol and protocol not in ['https', 'sftp', 's3']:
            parts.append(f"unusual transfer protocol: {protocol}")
        
        hour = features.get('hour_of_day')
        if hour is not None and (hour < 6 or hour > 20):
            parts.append(f"unusual transfer time ({hour}:00)")
        
        if not parts:
            return f"Unusual data transfer pattern (confidence: {score:.2f})"
            
        return f"Anomalous data transfer: {', '.join(parts)} (confidence: {score:.2f})"
