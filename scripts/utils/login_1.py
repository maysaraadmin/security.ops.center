"""
Login behavior analyzer for UEBA.

This module provides analysis of user login patterns to detect anomalies
such as unusual login times, locations, or failed login attempts.
"""
import logging
from datetime import datetime, time
from typing import Dict, Any, List, Optional, Tuple
import ipaddress
import hashlib

from .base import BaseAnalyzer

logger = logging.getLogger('siem.ueba.analyzers.login')

class LoginAnalyzer(BaseAnalyzer):
    """
    Analyzes user login behavior to detect anomalies.
    
    This analyzer focuses on:
    - Login times (time of day, day of week)
    - Geographic locations (based on IP)
    - Failed login attempts
    - Login source (IP, device, browser)
    """
    
    def __init__(self, model_type: str = 'statistical'):
        """
        Initialize the login analyzer.
        
        Args:
            model_type: Type of model to use ('statistical', 'isolation_forest', 'one_class_svm')
        """
        super().__init__(model_type)
        # Cache for IP to location mapping (in a real system, this would use a geo-IP service)
        self.ip_location_cache: Dict[str, Dict[str, str]] = {}
    
    def extract_features(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract login-related features from an event.
        
        Args:
            event_data: Raw event data containing login information
            
        Returns:
            Dictionary of login features
        """
        if not self._is_login_event(event_data):
            return {}
            
        features = {}
        
        # Extract basic login info
        timestamp = event_data.get('timestamp')
        user = event_data.get('user', {})
        
        # Time-based features
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
                features['hour_of_day'] = dt.hour
                features['day_of_week'] = dt.weekday()  # 0=Monday, 6=Sunday
                features['is_weekend'] = 1 if dt.weekday() >= 5 else 0
            except (ValueError, AttributeError) as e:
                logger.warning(f"Error parsing timestamp {timestamp}: {e}")
        
        # User features
        if user:
            features['user_id'] = self._hash_sensitive_value(user.get('id', ''))
            features['username'] = self._hash_sensitive_value(user.get('name', ''))
        
        # Source IP features
        source_ip = event_data.get('source_ip')
        if source_ip:
            features['source_ip'] = self._anonymize_ip(source_ip)
            
            # Get location features (in a real system, this would use a geo-IP service)
            location = self._get_ip_location(source_ip)
            if location:
                features['country'] = location.get('country', 'unknown')
                features['city'] = location.get('city', 'unknown')
        
        # Authentication method
        auth_method = event_data.get('auth_method', 'unknown').lower()
        features['auth_method'] = auth_method
        
        # Authentication outcome
        outcome = event_data.get('outcome', 'unknown').lower()
        features['success'] = 1 if outcome == 'success' else 0
        
        # Additional context
        features['failed_attempts'] = event_data.get('failed_attempts', 0)
        
        # Device and browser info (if available)
        device = event_data.get('device', {})
        if device:
            features['device_type'] = device.get('type', 'unknown')
            features['os'] = device.get('os', 'unknown')
            
            browser = device.get('browser', {})
            if browser:
                features['browser'] = browser.get('name', 'unknown')
                features['browser_version'] = browser.get('version', 'unknown')
        
        return features
    
    def describe_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """
        Generate a human-readable description of a login anomaly.
        
        Args:
            features: The features that triggered the anomaly
            score: The anomaly score
            
        Returns:
            Human-readable description of the anomaly
        """
        if not features:
            return "Suspicious login activity detected"
            
        parts = []
        
        # Check for unusual time
        hour = features.get('hour_of_day')
        if hour is not None:
            if hour < 6 or hour > 20:  # Late night or early morning
                parts.append(f"unusual login time ({hour}:00)")
        
        # Check for weekend login if not common for this user
        if features.get('is_weekend') == 1:
            parts.append("weekend login")
        
        # Check for failed attempts
        failed_attempts = features.get('failed_attempts', 0)
        if failed_attempts > 3:
            parts.append(f"multiple failed login attempts ({failed_attempts})")
        
        # Check for unusual location
        if 'country' in features and features['country'] != 'US':  # Assuming normal location is US
            parts.append(f"login from {features['country']}")
        
        # Check for unusual auth method
        auth_method = features.get('auth_method')
        if auth_method and auth_method not in ['password', 'sso']:  # Assuming these are the common methods
            parts.append(f"unusual authentication method: {auth_method}")
        
        if not parts:
            return "Suspicious login pattern detected"
            
        return f"Anomalous login: {', '.join(parts)} (confidence: {score:.2f})"
    
    def _is_login_event(self, event_data: Dict[str, Any]) -> bool:
        """Check if the event is a login-related event."""
        event_type = event_data.get('event_type', '').lower()
        return 'login' in event_type or 'authentication' in event_type or 'auth' in event_type
    
    def _anonymize_ip(self, ip_address: str) -> str:
        """Anonymize IP address by hashing it."""
        if not ip_address:
            return '0.0.0.0'
        
        try:
            # For IPv4, hash the last octet; for IPv6, hash the last 64 bits
            ip = ipaddress.ip_address(ip_address)
            if ip.version == 4:
                # For IPv4, just hash the last octet
                parts = str(ip).split('.')
                if len(parts) == 4:
                    parts[-1] = str(hash(parts[-1]) % 254 + 1)  # Ensure it's a valid IP octet
                    return '.'.join(parts)
            else:
                # For IPv6, hash the last 64 bits
                parts = str(ip).split(':')
                if len(parts) >= 4:
                    # Keep the first 4 segments, hash the rest
                    prefix = ':'.join(parts[:4])
                    suffix = ':'.join(parts[4:])
                    hashed_suffix = hashlib.md5(suffix.encode()).hexdigest()[:8]  # Use first 8 chars of hash
                    return f"{prefix}:{hashed_suffix}"
        except ValueError:
            pass
            
        # Fallback: hash the entire IP
        return hashlib.md5(ip_address.encode()).hexdigest()
    
    def _hash_sensitive_value(self, value: str) -> str:
        """Hash sensitive values like usernames and user IDs."""
        if not value:
            return ''
        return hashlib.sha256(value.encode()).hexdigest()
    
    def _get_ip_location(self, ip_address: str) -> Dict[str, str]:
        """
        Get location information for an IP address.
        
        In a real system, this would use a geo-IP service like MaxMind GeoIP2.
        This is a simplified version that just returns a fixed location for demonstration.
        
        Args:
            ip_address: The IP address to look up
            
        Returns:
            Dictionary with location information
        """
        if not ip_address:
            return {}
            
        # Check cache first
        if ip_address in self.ip_location_cache:
            return self.ip_location_cache[ip_address]
        
        # In a real system, this would call a geo-IP service
        # For now, just return a fixed location based on the IP's hash
        ip_hash = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
        
        # Use the hash to select a location from a fixed set
        locations = [
            {'country': 'US', 'city': 'New York'},
            {'country': 'US', 'city': 'San Francisco'},
            {'country': 'UK', 'city': 'London'},
            {'country': 'DE', 'city': 'Berlin'},
            {'country': 'JP', 'city': 'Tokyo'},
            {'country': 'AU', 'city': 'Sydney'},
            {'country': 'CA', 'city': 'Toronto'},
            {'country': 'FR', 'city': 'Paris'},
            {'country': 'SG', 'city': 'Singapore'},
            {'country': 'BR', 'city': 'Sao Paulo'}
        ]
        
        location = locations[ip_hash % len(locations)]
        
        # Cache the result
        self.ip_location_cache[ip_address] = location
        
        return location
