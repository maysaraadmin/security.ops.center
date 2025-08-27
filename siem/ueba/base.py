"""
Base classes for User and Entity Behavior Analytics (UEBA) in SIEM.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timedelta
import logging
import json
from pathlib import Path
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import hashlib

class BaseBehaviorModel(ABC):
    """Abstract base class for behavior models."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the behavior model."""
        self.config = config or {}
        self.model_id = self.config.get('id', self.__class__.__name__)
        self.name = self.config.get('name', self.model_id)
        self.version = '1.0'
        self.logger = logging.getLogger(f"siem.ueba.{self.model_id}")
        
        # Model state
        self.model = None
        self.scaler = StandardScaler()
        self.features: List[str] = []
        self.last_trained: Optional[datetime] = None
        self.training_samples: int = 0
        
        # Model parameters
        self.contamination = float(self.config.get('contamination', 0.01))
        self.training_interval = timedelta(
            hours=int(self.config.get('training_interval_hours', 24))
        )
        self.min_training_samples = int(self.config.get('min_training_samples', 1000))
        
        # Initialize the model
        self._initialize_model()
    
    def _initialize_model(self) -> None:
        """Initialize the machine learning model."""
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1
        )
    
    @abstractmethod
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract features from an event for behavior analysis.
        
        Args:
            event: The event to extract features from
            
        Returns:
            Dictionary of feature names and values, or None if the event should be skipped
        """
        pass
    
    def preprocess(self, events: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
        """Preprocess events into a feature matrix.
        
        Args:
            events: List of events to preprocess
            
        Returns:
            Tuple of (feature_matrix, valid_events) where valid_events are the events
            that were successfully processed
        """
        features_list = []
        valid_events = []
        
        for event in events:
            try:
                features = self.extract_features(event)
                if features:
                    features_list.append(features)
                    valid_events.append(event)
            except Exception as e:
                self.logger.warning(f"Error extracting features from event: {e}")
                continue
        
        if not features_list:
            return np.array([]), []
        
        # Update feature names if needed
        if not self.features:
            self.features = list(features_list[0].keys())
        
        # Create feature matrix
        X = np.array([[f.get(feature, 0) for feature in self.features] 
                      for f in features_list])
        
        return X, valid_events
    
    def train(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the behavior model on a set of events.
        
        Args:
            events: List of events to train on
            
        Returns:
            Dictionary with training results
        """
        self.logger.info(f"Training {self.model_id} on {len(events)} events")
        
        # Preprocess events
        X, valid_events = self.preprocess(events)
        
        if len(valid_events) < self.min_training_samples:
            self.logger.warning(
                f"Insufficient training samples: {len(valid_events)} < {self.min_training_samples}"
            )
            return {
                'success': False,
                'message': f'Insufficient training samples: {len(valid_events)} < {self.min_training_samples}',
                'samples_used': len(valid_events)
            }
        
        try:
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.model.fit(X_scaled)
            
            # Update model state
            self.last_trained = datetime.utcnow()
            self.training_samples = len(valid_events)
            
            self.logger.info(f"Training complete. Samples used: {len(valid_events)}")
            
            return {
                'success': True,
                'samples_used': len(valid_events),
                'features': self.features,
                'last_trained': self.last_trained.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}", exc_info=True)
            return {
                'success': False,
                'message': str(e),
                'samples_used': len(valid_events)
            }
    
    def predict(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score events for anomalies.
        
        Args:
            events: List of events to score
            
        Returns:
            List of results with anomaly scores and predictions
        """
        if not self.model:
            raise RuntimeError("Model has not been trained")
        
        if not events:
            return []
        
        # Preprocess events
        X, valid_events = self.preprocess(events)
        
        if not valid_events:
            return []
        
        try:
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly scores (lower is more anomalous)
            scores = -self.model.score_samples(X_scaled)  # Convert to positive where higher is more anomalous
            predictions = self.model.predict(X_scaled)
            
            # Convert to list of results
            results = []
            for i, event in enumerate(valid_events):
                results.append({
                    'event': event,
                    'score': float(scores[i]),
                    'is_anomaly': bool(predictions[i] == -1),  # -1 is outlier, 1 is inlier
                    'features': dict(zip(self.features, X[i].tolist())),
                    'model': self.model_id,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error predicting with model: {e}", exc_info=True)
            raise
    
    def save(self, directory: Union[str, Path] = None) -> str:
        """Save the model to disk.
        
        Args:
            directory: Directory to save the model to
            
        Returns:
            Path to the saved model
        """
        if not directory:
            directory = Path("models") / "ueba" / self.model_id
        else:
            directory = Path(directory) / self.model_id
        
        directory.mkdir(parents=True, exist_ok=True)
        
        # Save model and metadata
        model_path = directory / "model.joblib"
        metadata = {
            'model_id': self.model_id,
            'name': self.name,
            'version': self.version,
            'features': self.features,
            'last_trained': self.last_trained.isoformat() if self.last_trained else None,
            'training_samples': self.training_samples,
            'config': self.config
        }
        
        joblib.dump({
            'model': self.model,
            'scaler': self.scaler,
            'metadata': metadata
        }, model_path)
        
        # Save metadata separately for easy inspection
        with open(directory / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Saved model to {model_path}")
        return str(model_path)
    
    @classmethod
    def load(cls, directory: Union[str, Path]) -> 'BaseBehaviorModel':
        """Load a model from disk.
        
        Args:
            directory: Directory containing the saved model
            
        Returns:
            Loaded model instance
        """
        directory = Path(directory)
        model_path = directory / "model.joblib"
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found at {model_path}")
        
        # Load the model and metadata
        data = joblib.load(model_path)
        model = data['model']
        scaler = data['scaler']
        metadata = data['metadata']
        
        # Create a new instance with the saved config
        instance = cls(metadata.get('config', {}))
        
        # Restore the model state
        instance.model = model
        instance.scaler = scaler
        instance.features = metadata.get('features', [])
        instance.last_trained = (
            datetime.fromisoformat(metadata['last_timedata']) 
            if metadata.get('last_trained') else None
        )
        instance.training_samples = metadata.get('training_samples', 0)
        
        instance.logger.info(
            f"Loaded model {metadata['model_id']} (trained on {instance.training_samples} samples)"
        )
        
        return instance


class UserBehaviorModel(BaseBehaviorModel):
    """Model for detecting anomalous user behavior."""
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract user behavior features from an event."""
        # Skip non-user events
        if 'user' not in event or not event.get('user', {}).get('name'):
            return None
        
        features = {}
        
        # Time-based features
        event_time = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
        features['hour_of_day'] = event_time.hour + event_time.minute / 60.0
        features['day_of_week'] = event_time.weekday()
        features['is_weekend'] = 1.0 if event_time.weekday() >= 5 else 0.0
        
        # User activity features
        features['event_type_count'] = 1.0  # Will be aggregated per time window
        
        # Resource access patterns
        if 'file' in event and 'path' in event['file']:
            features['file_access'] = 1.0
            features['file_path_depth'] = len(event['file']['path'].split('/'))
        
        if 'network' in event:
            features['network_activity'] = 1.0
            if 'bytes' in event['network']:
                features['bytes_transferred'] = float(event['network']['bytes'])
        
        # Authentication patterns
        if 'event' in event and 'type' in event['event']:
            if 'authentication' in event['event']['type']:
                features['auth_attempt'] = 1.0
                if 'outcome' in event['event']:
                    features['auth_success'] = 1.0 if event['event']['outcome'] == 'success' else 0.0
        
        return features


class EntityBehaviorModel(BaseBehaviorModel):
    """Model for detecting anomalous entity (host, IP, etc.) behavior."""
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """Extract entity behavior features from an event."""
        # Skip events without a source or destination
        if 'source' not in event and 'destination' not in event:
            return None
        
        features = {}
        
        # Source features
        if 'source' in event:
            if 'ip' in event['source']:
                features['src_ip_prefix'] = float(
                    int(event['source']['ip'].split('.')[0])
                )
            if 'port' in event['source']:
                features['src_port'] = float(event['source']['port'])
        
        # Destination features
        if 'destination' in event:
            if 'ip' in event['destination']:
                features['dst_ip_prefix'] = float(
                    int(event['destination']['ip'].split('.')[0])
                )
            if 'port' in event['destination']:
                features['dst_port'] = float(event['destination']['port'])
        
        # Network activity features
        if 'network' in event:
            if 'bytes' in event['network']:
                features['bytes'] = float(event['network']['bytes'])
            if 'protocol' in event['network']:
                # Convert protocol to a numerical value
                protocol = event['network']['protocol'].lower()
                protocol_hash = int(hashlib.md5(protocol.encode()).hexdigest(), 16) % 1000
                features['protocol'] = float(protocol_hash)
        
        # Event type features
        if 'event' in event and 'category' in event['event']:
            for category in event['event']['category']:
                features[f'category_{category}'] = 1.0
        
        return features if features else None


class UEBAEngine:
    """Orchestrates multiple behavior models for UEBA."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the UEBA engine."""
        self.config = config or {}
        self.logger = logging.getLogger("siem.ueba.engine")
        
        # Models for different entity types
        self.models: Dict[str, BaseBehaviorModel] = {}
        
        # Alert thresholds
        self.alert_threshold = float(self.config.get('alert_threshold', 0.9))
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self) -> None:
        """Initialize behavior models from configuration."""
        models_config = self.config.get('models', [
            {
                'id': 'user_behavior',
                'type': 'user',
                'name': 'User Behavior Model',
                'contamination': 0.01,
                'training_interval_hours': 24,
                'min_training_samples': 1000
            },
            {
                'id': 'entity_behavior',
                'type': 'entity',
                'name': 'Entity Behavior Model',
                'contamination': 0.005,
                'training_interval_hours': 24,
                'min_training_samples': 5000
            }
        ])
        
        model_types = {
            'user': UserBehaviorModel,
            'entity': EntityBehaviorModel
        }
        
        for model_config in models_config:
            try:
                model_type = model_config.get('type')
                if model_type not in model_types:
                    self.logger.warning(f"Unknown model type: {model_type}")
                    continue
                
                model_class = model_types[model_type]
                model = model_class(model_config)
                self.models[model.model_id] = model
                
                self.logger.info(f"Initialized {model_type} model: {model.model_id}")
                
            except Exception as e:
                self.logger.error(f"Error initializing model {model_config.get('id')}: {e}")
    
    def process_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process events through all behavior models.
        
        Args:
            events: List of events to analyze
            
        Returns:
            List of detection results with anomaly scores
        """
        if not events:
            return []
        
        all_results = []
        
        for model_id, model in self.models.items():
            try:
                results = model.predict(events)
                all_results.extend(results)
                
                self.logger.debug(
                    f"Processed {len(events)} events with {model_id}, "
                    f"found {sum(1 for r in results if r['is_anomaly'])} anomalies"
                )
                
            except Exception as e:
                self.logger.error(f"Error processing events with {model_id}: {e}", exc_info=True)
        
        return all_results
    
    def train_models(self, events: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Train all behavior models on the provided events.
        
        Args:
            events: List of events to train on
            
        Returns:
            Dictionary of training results by model ID
        """
        if not events:
            return {}
        
        results = {}
        
        for model_id, model in self.models.items():
            try:
                self.logger.info(f"Training {model_id} on {len(events)} events")
                result = model.train(events)
                results[model_id] = result
                
                if result.get('success'):
                    self.logger.info(
                        f"Successfully trained {model_id} on {result['samples_used']} samples"
                    )
                else:
                    self.logger.warning(
                        f"Training failed for {model_id}: {result.get('message', 'Unknown error')}"
                    )
                
            except Exception as e:
                error_msg = f"Error training {model_id}: {str(e)}"
                self.logger.error(error_msg, exc_info=True)
                results[model_id] = {
                    'success': False,
                    'message': error_msg
                }
        
        return results
    
    def save_models(self, base_dir: Union[str, Path] = "models/ueba") -> Dict[str, str]:
        """Save all models to disk.
        
        Args:
            base_dir: Base directory to save models to
            
        Returns:
            Dictionary mapping model IDs to their save paths
        """
        base_dir = Path(base_dir)
        saved_paths = {}
        
        for model_id, model in self.models.items():
            try:
                model_dir = base_dir / model_id
                save_path = model.save(model_dir)
                saved_paths[model_id] = save_path
                self.logger.info(f"Saved {model_id} to {save_path}")
            except Exception as e:
                self.logger.error(f"Error saving {model_id}: {e}", exc_info=True)
                saved_paths[model_id] = f"error: {str(e)}"
        
        return saved_paths
    
    @classmethod
    def load_models(cls, base_dir: Union[str, Path] = "models/ueba") -> 'UEBAEngine':
        """Load models from disk.
        
        Args:
            base_dir: Base directory containing model subdirectories
            
        Returns:
            UEBAEngine instance with loaded models
        """
        base_dir = Path(base_dir)
        engine = cls()
        
        for model_dir in base_dir.iterdir():
            if not model_dir.is_dir():
                continue
                
            try:
                # Try to load metadata to determine model type
                metadata_path = model_dir / "metadata.json"
                if not metadata_path.exists():
                    continue
                
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                model_type = metadata.get('config', {}).get('type')
                if not model_type:
                    continue
                
                # Load the appropriate model type
                if model_type == 'user':
                    model = UserBehaviorModel.load(model_dir)
                elif model_type == 'entity':
                    model = EntityBehaviorModel.load(model_dir)
                else:
                    continue
                
                engine.models[model.model_id] = model
                engine.logger.info(
                    f"Loaded {model_type} model: {model.model_id} "
                    f"(trained on {model.training_samples} samples)"
                )
                
            except Exception as e:
                engine.logger.error(f"Error loading model from {model_dir}: {e}", exc_info=True)
        
        return engine
