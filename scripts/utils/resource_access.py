"""
Resource access behavior analyzer for UEBA.

This module provides analysis of how users access resources to detect anomalies.
"""
import logging
from datetime import datetime
from typing import Dict, Any, Set
import hashlib

from .base import BaseAnalyzer

logger = logging.getLogger('siem.ueba.analyzers.resource_access')

class ResourceAccessAnalyzer(BaseAnalyzer):
    """Analyzes user resource access patterns to detect anomalies."""
    
    def __init__(self, model_type: str = 'statistical'):
        super().__init__(model_type)
        self.sensitive_resources: Set[str] = set()
        self._load_sensitive_resources()
    
    def _load_sensitive_resources(self) -> None:
        """Load sensitive resources from configuration or database."""
        # In a real system, this would load from a database or config file
        self.sensitive_resources = {
            'sensitive_db',
            'hr_records',
            'financial_data',
            'customer_pii'
        }
    
    def _is_resource_access_event(self, event_data: Dict[str, Any]) -> bool:
        """Check if the event is a resource access event."""
        event_type = event_data.get('event_type', '').lower()
        return any(term in event_type for term in ['access', 'read', 'write', 'modify'])
    
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
        """Extract resource access features from an event."""
        if not self._is_resource_access_event(event_data):
            return {}
        
        features = {}
        
        # Extract basic info
        timestamp = event_data.get('timestamp')
        user = event_data.get('user', {})
        resource = event_data.get('resource', {})
        
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
        
        # Resource features
        if resource:
            resource_id = resource.get('id', '')
            features['resource_id'] = self._hash_sensitive_value(resource_id)
            features['is_sensitive'] = 1 if resource_id in self.sensitive_resources else 0
            features['access_level'] = resource.get('access_level', 'read').lower()
        
        return features
    
    def describe_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """Generate a human-readable description of a resource access anomaly."""
        if not features:
            return "Suspicious resource access detected"
            
        parts = []
        
        if features.get('is_sensitive') == 1:
            parts.append("access to sensitive resource")
        
        hour = features.get('hour_of_day')
        if hour is not None and (hour < 6 or hour > 20):
            parts.append(f"unusual access time ({hour}:00)")
        
        access_level = features.get('access_level')
        if access_level in ['admin', 'write', 'delete']:
            parts.append(f"elevated access level: {access_level}")
        
        if not parts:
            return f"Unusual resource access pattern (confidence: {score:.2f})"
            
        return f"Anomalous resource access: {', '.join(parts)} (confidence: {score:.2f})"
