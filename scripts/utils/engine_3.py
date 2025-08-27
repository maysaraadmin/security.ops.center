"""
UEBA Engine - Core engine for User and Entity Behavior Analytics.

This module implements the main UEBA engine that coordinates behavior analysis,
model training, and anomaly detection.
"""
import logging
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import json
import numpy as np
from pathlib import Path

from ..models.database import Database
from .models.base import BehaviorModel
from .analyzers import (
    LoginAnalyzer,
    ResourceAccessAnalyzer,
    DataTransferAnalyzer,
    ProcessExecutionAnalyzer
)
from .utils import TimeWindow, BehaviorProfile

logger = logging.getLogger('siem.ueba.engine')

class UebaEngine:
    """
    Main UEBA engine that coordinates behavior analysis and anomaly detection.
    
    The engine maintains behavior profiles for users and entities, trains models,
    and detects anomalies based on behavioral deviations.
    """
    
    def __init__(self, db: Database, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the UEBA engine.
        
        Args:
            db: Database connection
            config: Configuration dictionary
        """
        self.db = db
        self.config = config or self._load_default_config()
        self.models: Dict[str, Dict[str, BehaviorModel]] = {}
        self.behavior_profiles: Dict[str, Dict[str, BehaviorProfile]] = {}
        self.analyzers = self._initialize_analyzers()
        self._load_models()
        
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            'training_interval': 24,  # hours
            'anomaly_threshold': 0.95,  # 95th percentile
            'baseline_period': 30,  # days
            'model_storage': 'models/ueba',
            'enabled_analyzers': ['login', 'resource_access', 'data_transfer', 'process_execution']
        }
    
    def _initialize_analyzers(self) -> Dict[str, Any]:
        """Initialize behavior analyzers."""
        analyzers = {}
        
        if 'login' in self.config['enabled_analyzers']:
            analyzers['login'] = LoginAnalyzer()
        if 'resource_access' in self.config['enabled_analyzers']:
            analyzers['resource_access'] = ResourceAccessAnalyzer()
        if 'data_transfer' in self.config['enabled_analyzers']:
            analyzers['data_transfer'] = DataTransferAnalyzer()
        if 'process_execution' in self.config['enabled_analyzers']:
            analyzers['process_execution'] = ProcessExecutionAnalyzer()
            
        return analyzers
    
    def _load_models(self) -> None:
        """Load trained models from storage."""
        model_dir = Path(self.config.get('model_storage', 'models/ueba'))
        model_dir.mkdir(parents=True, exist_ok=True)
        
        for analyzer_name, analyzer in self.analyzers.items():
            model_path = model_dir / f"{analyzer_name}_model.pkl"
            if model_path.exists():
                try:
                    self.models[analyzer_name] = analyzer.load_model(str(model_path))
                    logger.info(f"Loaded model for {analyzer_name}")
                except Exception as e:
                    logger.error(f"Failed to load model for {analyzer_name}: {e}")
    
    def train_models(self, force_retrain: bool = False) -> None:
        """
        Train behavior models using historical data.
        
        Args:
            force_retrain: If True, retrain models even if they exist
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=self.config['baseline_period'])
        
        for analyzer_name, analyzer in self.analyzers.items():
            # Skip if model exists and we're not forcing retrain
            if not force_retrain and analyzer_name in self.models:
                continue
                
            try:
                logger.info(f"Training {analyzer_name} model...")
                
                # Get training data
                training_data = self._get_training_data(analyzer_name, start_time, end_time)
                
                # Train model
                model = analyzer.train(training_data)
                self.models[analyzer_name] = model
                
                # Save model
                model_dir = Path(self.config.get('model_storage', 'models/ueba'))
                model_dir.mkdir(parents=True, exist_ok=True)
                model_path = model_dir / f"{analyzer_name}_model.pkl"
                analyzer.save_model(model, str(model_path))
                
                logger.info(f"Trained and saved {analyzer_name} model")
                
            except Exception as e:
                logger.error(f"Error training {analyzer_name} model: {e}")
    
    def _get_training_data(self, analyzer_name: str, 
                          start_time: datetime, 
                          end_time: datetime) -> List[Dict[str, Any]]:
        """
        Retrieve training data for a specific analyzer.
        
        Args:
            analyzer_name: Name of the analyzer
            start_time: Start of time range
            end_time: End of time range
            
        Returns:
            List of training data records
        """
        # This would query the database for relevant events
        # For now, return an empty list as a placeholder
        return []
    
    def analyze_behavior(self, user_id: str, entity_type: str, 
                        entity_id: str, timestamp: datetime, 
                        event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze user/entity behavior for potential anomalies.
        
        Args:
            user_id: ID of the user
            entity_type: Type of entity (e.g., 'host', 'application')
            entity_id: ID of the entity
            timestamp: When the event occurred
            event_data: Event data to analyze
            
        Returns:
            Dictionary with analysis results including anomaly scores and alerts
        """
        results = {
            'user_id': user_id,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'timestamp': timestamp.isoformat(),
            'anomaly_scores': {},
            'alerts': []
        }
        
        # Update behavior profile
        profile_key = f"{user_id}:{entity_type}:{entity_id}"
        if profile_key not in self.behavior_profiles:
            self.behavior_profiles[profile_key] = {
                'login': BehaviorProfile(),
                'resource_access': BehaviorProfile(),
                'data_transfer': BehaviorProfile(),
                'process_execution': BehaviorProfile()
            }
        
        profile = self.behavior_profiles[profile_key]
        
        # Run through all analyzers
        for analyzer_name, analyzer in self.analyzers.items():
            if analyzer_name not in self.models:
                continue
                
            try:
                # Get features for this analyzer
                features = analyzer.extract_features(event_data)
                if not features:
                    continue
                
                # Update behavior profile
                profile[analyzer_name].update(features, timestamp)
                
                # Score behavior
                score = self.models[analyzer_name].score(features)
                results['anomaly_scores'][analyzer_name] = score
                
                # Check for anomalies
                if score > self.config['anomaly_threshold']:
                    alert = {
                        'analyzer': analyzer_name,
                        'score': score,
                        'features': features,
                        'description': analyzer.describe_anomaly(features, score)
                    }
                    results['alerts'].append(alert)
                    
            except Exception as e:
                logger.error(f"Error in {analyzer_name} analyzer: {e}")
        
        return results
    
    def get_behavior_profile(self, user_id: str, entity_type: str, 
                           entity_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the behavior profile for a user/entity.
        
        Args:
            user_id: ID of the user
            entity_type: Type of entity
            entity_id: ID of the entity
            
        Returns:
            Behavior profile or None if not found
        """
        profile_key = f"{user_id}:{entity_type}:{entity_id}"
        profile = self.behavior_profiles.get(profile_key)
        
        if profile:
            return {
                analyzer_name: analyzer_profile.to_dict() 
                for analyzer_name, analyzer_profile in profile.items()
            }
        return None
