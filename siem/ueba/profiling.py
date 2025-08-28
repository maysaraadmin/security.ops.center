"""
User & Entity Behavior Analytics (UEBA) - Behavior Profiling Module

This module handles the creation and management of behavior profiles for users and entities.
"""
import json
import logging
import hashlib
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple, Set
from dataclasses import dataclass, field, asdict, fields
from enum import Enum, auto
from collections import defaultdict, deque
import time
from pathlib import Path
import pickle
import gzip
import os

# Third-party imports
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.mixture import GaussianMixture
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

class EntityType(Enum):
    """Types of entities that can be profiled."""
    USER = "user"
    HOST = "host"
    APPLICATION = "application"
    SERVICE_ACCOUNT = "service_account"
    PRIVILEGED_ACCOUNT = "privileged_account"
    DEVICE = "device"
    NETWORK = "network"
    OTHER = "other"

class TimeWindow(Enum):
    """Time windows for behavior analysis."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

class ProfileState(Enum):
    """State of a behavior profile."""
    LEARNING = "learning"  # Profile is in learning mode, building baseline
    ACTIVE = "active"      # Profile is active and being used for detection
    STALE = "stale"        # Profile hasn't been updated in a while
    INACTIVE = "inactive"  # Profile is no longer active

@dataclass
class BehaviorMetric:
    """Represents a behavior metric with statistical properties."""
    name: str
    count: int = 0
    sum: float = 0.0
    min: float = float('inf')
    max: float = float('-inf')
    mean: float = 0.0
    m2: float = 0.0  # For Welford's online variance calculation
    std_dev: float = 0.0
    percentiles: Dict[float, float] = field(default_factory=dict)  # e.g., {50: median, 95: p95}
    last_updated: datetime = field(default_factory=datetime.utcnow)
    
    def update(self, value: float, timestamp: Optional[datetime] = None) -> None:
        """Update the metric with a new value using Welford's online algorithm."""
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        
        # Update min/max
        self.min = min(self.min, value)
        self.max = max(self.max, value)
        
        # Update standard deviation
        if self.count > 1:
            self.std_dev = (self.m2 / (self.count - 1)) ** 0.5
        
        # Update last updated timestamp
        self.last_updated = timestamp or datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the metric to a dictionary."""
        return {
            'name': self.name,
            'count': self.count,
            'sum': self.sum,
            'min': self.min,
            'max': self.max,
            'mean': self.mean,
            'std_dev': self.std_dev,
            'percentiles': self.percentiles,
            'last_updated': self.last_updated.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorMetric':
        """Create a BehaviorMetric from a dictionary."""
        metric = cls(
            name=data['name'],
            count=data.get('count', 0),
            sum=data.get('sum', 0.0),
            min=data.get('min', float('inf')),
            max=data.get('max', float('-inf')),
            mean=data.get('mean', 0.0),
            m2=data.get('m2', 0.0),
            std_dev=data.get('std_dev', 0.0),
            percentiles=data.get('percentiles', {})
        )
        
        # Handle last_updated
        if 'last_updated' in data:
            if isinstance(data['last_updated'], str):
                metric.last_updated = datetime.fromisoformat(data['last_updated'])
            else:
                metric.last_updated = data['last_updated']
        
        return metric

@dataclass
class BehaviorPattern:
    """Represents a behavior pattern for a specific context."""
    context: str  # e.g., 'logon_attempts', 'data_access', 'command_execution'
    metrics: Dict[str, BehaviorMetric] = field(default_factory=dict)
    clusters: Optional[Dict[str, Any]] = None  # For clustering analysis
    patterns: Dict[str, Any] = field(default_factory=dict)  # For pattern recognition
    last_analyzed: Optional[datetime] = None
    
    def add_metric_value(self, metric_name: str, value: float, timestamp: Optional[datetime] = None) -> None:
        """Add a value to a metric, creating it if it doesn't exist."""
        if metric_name not in self.metrics:
            self.metrics[metric_name] = BehaviorMetric(name=metric_name)
        
        self.metrics[metric_name].update(value, timestamp)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the pattern to a dictionary."""
        return {
            'context': self.context,
            'metrics': {name: metric.to_dict() for name, metric in self.metrics.items()},
            'clusters': self.clusters,
            'patterns': self.patterns,
            'last_analyzed': self.last_analyzed.isoformat() if self.last_analyzed else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorPattern':
        """Create a BehaviorPattern from a dictionary."""
        pattern = cls(
            context=data['context'],
            metrics={},
            clusters=data.get('clusters'),
            patterns=data.get('patterns', {})
        )
        
        # Convert metrics
        for metric_name, metric_data in data.get('metrics', {}).items():
            pattern.metrics[metric_name] = BehaviorMetric.from_dict(metric_data)
        
        # Handle last_analyzed
        if 'last_analyzed' in data and data['last_analyzed']:
            if isinstance(data['last_analyzed'], str):
                pattern.last_analyzed = datetime.fromisoformat(data['last_analyzed'])
            else:
                pattern.last_analyzed = data['last_analyzed']
        
        return pattern

@dataclass
class BehaviorProfile:
    """Represents a behavior profile for a user or entity."""
    entity_id: str
    entity_type: Union[str, EntityType]
    patterns: Dict[str, BehaviorPattern] = field(default_factory=dict)
    risk_score: float = 0.0
    confidence: float = 0.0  # Confidence in the profile (0-1)
    state: Union[str, ProfileState] = ProfileState.LEARNING
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Ensure enums are properly initialized."""
        if isinstance(self.entity_type, str):
            self.entity_type = EntityType(self.entity_type.lower())
        if isinstance(self.state, str):
            self.state = ProfileState(self.state.lower())
    
    def add_observation(
        self, 
        context: str, 
        metric_name: str, 
        value: float, 
        timestamp: Optional[datetime] = None
    ) -> None:
        """Add an observation to the profile."""
        if context not in self.patterns:
            self.patterns[context] = BehaviorPattern(context=context)
        
        self.patterns[context].add_metric_value(metric_name, value, timestamp)
        self.updated_at = datetime.utcnow()
    
    def get_metric(self, context: str, metric_name: str) -> Optional[BehaviorMetric]:
        """Get a metric by context and name."""
        if context in self.patterns and metric_name in self.patterns[context].metrics:
            return self.patterns[context].metrics[metric_name]
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the profile to a dictionary."""
        return {
            'entity_id': self.entity_id,
            'entity_type': self.entity_type.value,
            'patterns': {ctx: pattern.to_dict() for ctx, pattern in self.patterns.items()},
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'state': self.state.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorProfile':
        """Create a BehaviorProfile from a dictionary."""
        profile = cls(
            entity_id=data['entity_id'],
            entity_type=data['entity_type'],
            risk_score=data.get('risk_score', 0.0),
            confidence=data.get('confidence', 0.0),
            state=data.get('state', ProfileState.LEARNING.value),
            metadata=data.get('metadata', {})
        )
        
        # Convert patterns
        for ctx, pattern_data in data.get('patterns', {}).items():
            profile.patterns[ctx] = BehaviorPattern.from_dict(pattern_data)
        
        # Handle timestamps
        if 'created_at' in data:
            if isinstance(data['created_at'], str):
                profile.created_at = datetime.fromisoformat(data['created_at'])
            else:
                profile.created_at = data['created_at']
        
        if 'updated_at' in data:
            if isinstance(data['updated_at'], str):
                profile.updated_at = datetime.fromisoformat(data['updated_at'])
            else:
                profile.updated_at = data['updated_at']
        
        return profile

class ProfileManager:
    """Manages behavior profiles for users and entities."""
    
    def __init__(
        self, 
        storage_dir: str = "./ueba_profiles",
        min_observations: int = 100,  # Minimum observations before profile is considered stable
        learning_period: int = 30,    # Days of learning before profile becomes active
        max_profile_age: int = 90     # Days before a profile is considered stale
    ):
        """Initialize the profile manager.
        
        Args:
            storage_dir: Directory to store profile data
            min_observations: Minimum observations before profile is considered stable
            learning_period: Days of learning before profile becomes active
            max_profile_age: Days before a profile is considered stale
        """
        self.storage_dir = Path(storage_dir)
        self.min_observations = min_observations
        self.learning_period = learning_period
        self.max_profile_age = max_profile_age
        
        # Create storage directory if it doesn't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache of profiles
        self._profiles: Dict[str, Dict[str, BehaviorProfile]] = {
            entity_type.value: {}
            for entity_type in EntityType
        }
        
        # Load existing profiles
        self._load_profiles()
    
    def _get_profile_path(self, entity_type: Union[str, EntityType], entity_id: str) -> Path:
        """Get the path to a profile file."""
        if isinstance(entity_type, EntityType):
            entity_type = entity_type.value
        
        # Create a safe filename from entity_id
        safe_id = hashlib.md5(entity_id.encode('utf-8')).hexdigest()
        return self.storage_dir / f"{entity_type}_{safe_id}.json"
    
    def _load_profiles(self) -> None:
        """Load all profiles from disk."""
        for entity_type in EntityType:
            entity_dir = self.storage_dir / entity_type.value
            if not entity_dir.exists():
                continue
            
            for profile_file in entity_dir.glob("*.json"):
                try:
                    with open(profile_file, 'r') as f:
                        profile_data = json.load(f)
                    
                    profile = BehaviorProfile.from_dict(profile_data)
                    self._profiles[entity_type.value][profile.entity_id] = profile
                    
                    # Check if profile is stale
                    if (datetime.utcnow() - profile.updated_at).days > self.max_profile_age:
                        profile.state = ProfileState.STALE
                        self.save_profile(profile)
                
                except Exception as e:
                    logger.error(f"Error loading profile {profile_file}: {e}")
    
    def get_profile(
        self, 
        entity_id: str, 
        entity_type: Union[str, EntityType] = EntityType.USER,
        create_if_missing: bool = True
    ) -> Optional[BehaviorProfile]:
        """Get a behavior profile, optionally creating it if it doesn't exist."""
        if isinstance(entity_type, EntityType):
            entity_type = entity_type.value
        
        # Check in-memory cache
        if entity_id in self._profiles[entity_type]:
            return self._profiles[entity_type][entity_id]
        
        # Try to load from disk
        profile_path = self._get_profile_path(entity_type, entity_id)
        if profile_path.exists():
            try:
                with open(profile_path, 'r') as f:
                    profile_data = json.load(f)
                
                profile = BehaviorProfile.from_dict(profile_data)
                self._profiles[entity_type][entity_id] = profile
                return profile
            
            except Exception as e:
                logger.error(f"Error loading profile {entity_id}: {e}")
                return None
        
        # Create a new profile if requested
        if create_if_missing:
            profile = BehaviorProfile(
                entity_id=entity_id,
                entity_type=entity_type,
                state=ProfileState.LEARNING
            )
            self._profiles[entity_type][entity_id] = profile
            self.save_profile(profile)
            return profile
        
        return None
    
    def save_profile(self, profile: BehaviorProfile) -> bool:
        """Save a behavior profile to disk."""
        try:
            # Update the profile's updated_at timestamp
            profile.updated_at = datetime.utcnow()
            
            # Ensure the entity type directory exists
            entity_dir = self.storage_dir / profile.entity_type.value
            entity_dir.mkdir(parents=True, exist_ok=True)
            
            # Save the profile
            profile_path = self._get_profile_path(profile.entity_type, profile.entity_id)
            with open(profile_path, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2, default=str)
            
            return True
        
        except Exception as e:
            logger.error(f"Error saving profile {profile.entity_id}: {e}")
            return False
    
    def update_profile(
        self,
        entity_id: str,
        entity_type: Union[str, EntityType],
        context: str,
        metric_name: str,
        value: float,
        timestamp: Optional[datetime] = None
    ) -> Optional[BehaviorProfile]:
        """Update a behavior profile with a new observation."""
        profile = self.get_profile(entity_id, entity_type)
        if not profile:
            return None
        
        # Add the observation
        profile.add_observation(context, metric_name, value, timestamp)
        
        # Update profile state if needed
        if profile.state == ProfileState.LEARNING:
            # Check if we have enough observations to consider the profile stable
            total_observations = sum(
                metric.count 
                for pattern in profile.patterns.values() 
                for metric in pattern.metrics.values()
            )
            
            if total_observations >= self.min_observations and \
               (datetime.utcnow() - profile.created_at).days >= self.learning_period:
                profile.state = ProfileState.ACTIVE
                logger.info(f"Profile for {entity_type} {entity_id} is now active")
        
        # Save the updated profile
        self.save_profile(profile)
        return profile
    
    def get_entity_risk_score(
        self,
        entity_id: str,
        entity_type: Union[str, EntityType],
        time_window: TimeWindow = TimeWindow.DAILY
    ) -> float:
        """Calculate a risk score for an entity based on behavior patterns."""
        profile = self.get_profile(entity_id, entity_type, create_if_missing=False)
        if not profile:
            return 0.0  # No profile means no risk (or very low risk)
        
        # Simple implementation - in a real system, this would be more sophisticated
        risk_score = 0.0
        
        # Check for anomalies in each pattern
        for context, pattern in profile.patterns.items():
            for metric_name, metric in pattern.metrics.items():
                # Skip if we don't have enough data
                if metric.count < 10:  # Minimum observations for meaningful stats
                    continue
                
                # Example: Calculate deviation from mean in terms of standard deviations
                if metric.std_dev > 0:
                    # This is a simplified example - real implementation would be more sophisticated
                    deviation = abs(metric.mean - metric.last_value) / metric.std_dev
                    risk_score += min(deviation, 10.0)  # Cap the contribution of any single metric
        
        # Normalize the score to 0-100
        risk_score = min(max(risk_score, 0.0), 100.0)
        
        # Update the profile's risk score
        profile.risk_score = risk_score
        self.save_profile(profile)
        
        return risk_score
    
    def find_anomalies(
        self,
        entity_type: Optional[Union[str, EntityType]] = None,
        min_risk_score: float = 70.0,
        time_window: TimeWindow = TimeWindow.DAILY
    ) -> List[Dict[str, Any]]:
        """Find entities with anomalous behavior."""
        anomalies = []
        
        # Determine which entity types to check
        entity_types = [entity_type] if entity_type else [e.value for e in EntityType]
        
        for et in entity_types:
            for entity_id, profile in self._profiles[et].items():
                # Skip profiles that are still learning
                if profile.state != ProfileState.ACTIVE:
                    continue
                
                # Calculate risk score if not already done
                if profile.risk_score == 0.0:
                    self.get_entity_risk_score(entity_id, et, time_window)
                
                # Check if the risk score is above the threshold
                if profile.risk_score >= min_risk_score:
                    anomalies.append({
                        'entity_id': entity_id,
                        'entity_type': et,
                        'risk_score': profile.risk_score,
                        'last_updated': profile.updated_at.isoformat()
                    })
        
        # Sort by risk score (highest first)
        return sorted(anomalies, key=lambda x: x['risk_score'], reverse=True)

# Example usage
if __name__ == "__main__":
    import logging
    import random
    from datetime import datetime, timedelta
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create a profile manager
    profile_manager = ProfileManager(
        storage_dir="./ueba_profiles",
        min_observations=50,
        learning_period=1,  # 1 day for testing
        max_profile_age=30
    )
    
    # Simulate some user behavior
    user_id = "user123"
    now = datetime.utcnow()
    
    print(f"Simulating behavior for user {user_id}...")
    
    # Simulate normal behavior (logins during business hours)
    for day in range(30):  # Last 30 days
        date = now - timedelta(days=day)
        
        # 0-2 logins per day
        num_logins = random.randint(0, 2)
        
        for _ in range(num_logins):
            # Business hours (9 AM to 5 PM)
            login_hour = random.randint(9, 16)
            login_time = date.replace(hour=login_hour, minute=random.randint(0, 59))
            
            # Update profile with login
            profile_manager.update_profile(
                entity_id=user_id,
                entity_type=EntityType.USER,
                context="logins",
                metric_name="login_count",
                value=1,
                timestamp=login_time
            )
    
    # Simulate some anomalous behavior (login at unusual time)
    print("Adding anomalous login...")
    profile_manager.update_profile(
        entity_id=user_id,
        entity_type=EntityType.USER,
        context="logins",
        metric_name="login_count",
        value=1,
        timestamp=now.replace(hour=3, minute=30)  # 3:30 AM
    )
    
    # Check for anomalies
    print("\nChecking for anomalies...")
    anomalies = profile_manager.find_anomalies(min_risk_score=50.0)
    
    if anomalies:
        print("\nFound anomalies:")
        for anomaly in anomalies:
            print(f"- {anomaly['entity_type']} {anomaly['entity_id']}: "
                  f"risk_score={anomaly['risk_score']:.1f}")
    else:
        print("No anomalies found.")
    
    # Get the user's profile
    profile = profile_manager.get_profile(user_id, EntityType.USER)
    if profile:
        print(f"\nProfile state: {profile.state.value}")
        print(f"Total observations: {sum(m.count for p in profile.patterns.values() for m in p.metrics.values())}")
        print(f"Current risk score: {profile.risk_score:.1f}")
