"""
Behavioral Anomaly Detection Module

Identifies zero-day attacks by baselining normal network behavior
and detecting deviations from established patterns.
"""
import asyncio
import logging
import json
import numpy as np
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Deque, DefaultDict
from collections import defaultdict, deque
from pathlib import Path
import pickle
import hashlib
import os

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from statsmodels.tsa.seasonal import STL
import pandas as pd

from .models.flow import NetworkFlow, FlowDirection
from .models.alert import NetworkAlert, AlertSeverity
from .utils.net_utils import is_private_ip, get_service_name

logger = logging.getLogger('ndr.behavioral_analyzer')

@dataclass
class BehavioralConfig:
    """Configuration for behavioral anomaly detection."""
    # Learning phase duration (in hours)
    learning_phase_hours: int = 168  # 1 week
    
    # Model update interval (in hours)
    model_update_interval: int = 24  # Daily
    
    # Anomaly detection sensitivity (0.0 to 1.0, higher = more sensitive)
    sensitivity: float = 0.95
    
    # Minimum data points required for training
    min_training_samples: int = 1000
    
    # Feature configuration
    features: List[str] = field(default_factory=lambda: [
        'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
        'duration', 'packet_size_avg', 'bytes_per_second', 'packets_per_second'
    ])
    
    # Time windows for analysis (in minutes)
    time_windows: List[int] = field(default_factory=lambda: [1, 5, 15, 60])
    
    # Data storage
    data_dir: str = "data/ndr/behavioral"
    model_dir: str = "models/ndr/behavioral"
    
    # Alert thresholds
    anomaly_score_threshold: float = 0.8
    
    # Whitelist of known good IPs/CIDRs that won't trigger alerts
    whitelist: List[str] = field(default_factory=list)

class BehavioralAnalyzer:
    """
    Detects zero-day attacks by learning normal network behavior
    and identifying anomalous patterns.
    """
    
    def __init__(self, config: Optional[BehavioralConfig] = None):
        """Initialize the behavioral analyzer."""
        self.config = config or BehavioralConfig()
        self.active = False
        
        # Behavioral models
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        self.baselines: Dict[str, Any] = {}
        
        # Feature storage
        self.feature_store: DefaultDict[str, Deque] = defaultdict(lambda: deque(maxlen=10000))
        self.learning_phase: bool = True
        self.learning_start: Optional[datetime] = None
        
        # Alert tracking
        self.alert_callbacks: List[Callable[[NetworkAlert], None]] = []
        
        # Initialize directories
        self.data_dir = Path(self.config.data_dir)
        self.model_dir = Path(self.config.model_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing models if available
        self._load_models()
        
        # Initialize models if none loaded
        if not self.models:
            self._init_models()
            self.learning_phase = True
            self.learning_start = datetime.utcnow()
        else:
            self.learning_phase = False
    
    async def start(self):
        """Start the behavioral analyzer."""
        if self.active:
            return
            
        self.active = True
        logger.info("Behavioral analyzer started")
        
        # Start background tasks
        asyncio.create_task(self._model_updater())
        asyncio.create_task(self._data_persister())
    
    async def stop(self):
        """Stop the behavioral analyzer."""
        self.active = False
        self._save_models()
        self._save_feature_store()
        logger.info("Behavioral analyzer stopped")
    
    def register_alert_callback(self, callback: Callable[[NetworkAlert], None]):
        """Register a callback for anomaly alerts."""
        self.alert_callbacks.append(callback)
    
    async def analyze_flow(self, flow: NetworkFlow):
        """
        Analyze a network flow for behavioral anomalies.
        
        Args:
            flow: The network flow to analyze
        """
        if not self.active:
            return
            
        try:
            # Skip whitelisted IPs
            if self._is_whitelisted(flow.src_ip) or self._is_whitelisted(flow.dst_ip):
                return
            
            # Extract features from the flow
            features = self._extract_features(flow)
            
            # Store features for model training
            self._store_features(features)
            
            # Skip detection during learning phase
            if self.learning_phase:
                return
                
            # Detect anomalies
            anomalies = self._detect_anomalies(features)
            
            # Generate alerts for detected anomalies
            for entity, score in anomalies.items():
                if score >= self.config.anomaly_score_threshold:
                    self._generate_alert(flow, entity, score)
                    
        except Exception as e:
            logger.error(f"Error analyzing flow: {e}")
    
    def _init_models(self):
        """Initialize machine learning models for anomaly detection."""
        logger.info("Initializing behavioral models")
        
        # Initialize models for each time window
        for window in self.config.time_windows:
            # Isolation Forest for anomaly detection
            self.models[str(window)] = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )
            
            # Feature scaler
            self.scalers[str(window)] = StandardScaler()
            
            # Baseline statistics
            self.baselines[str(window)] = {}
    
    def _extract_features(self, flow: NetworkFlow) -> Dict[str, Any]:
        """Extract features from a network flow for behavioral analysis."""
        # Basic flow features
        features = {
            'timestamp': datetime.utcnow().isoformat(),
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol,
            'direction': flow.direction.name.lower(),
            'bytes_sent': flow.bytes_sent,
            'bytes_received': flow.bytes_received,
            'packets_sent': flow.packets_sent,
            'packets_received': flow.packets_received,
            'duration': flow.duration,
            'packet_size_avg': (flow.bytes_sent + flow.bytes_received) / max(1, flow.packets_sent + flow.packets_received),
            'bytes_per_second': (flow.bytes_sent + flow.bytes_received) / max(1, flow.duration) if flow.duration > 0 else 0,
            'packets_per_second': (flow.packets_sent + flow.packets_received) / max(1, flow.duration) if flow.duration > 0 else 0,
            'is_internal': flow.direction == FlowDirection.INTERNAL,
            'is_external': flow.direction in [FlowDirection.INBOUND, FlowDirection.OUTBOUND]
        }
        
        return features
    
    def _store_features(self, features: Dict[str, Any]):
        """Store features for model training and analysis."""
        # Store features for each time window
        for window in self.config.time_windows:
            # Create a windowed feature set
            window_key = f"{window}m"
            windowed_features = features.copy()
            windowed_features['time_window'] = window_key
            
            # Add to feature store
            self.feature_store[window_key].append(windowed_features)
    
    def _detect_anomalies(self, features: Dict[str, Any]) -> Dict[str, float]:
        """
        Detect anomalies in the given features using trained models.
        
        Returns:
            Dictionary mapping entity names to anomaly scores (0.0 to 1.0)
        """
        anomalies = {}
        
        # Check each time window
        for window in self.config.time_windows:
            window_key = str(window)
            
            # Skip if no model for this window
            if window_key not in self.models:
                continue
                
            try:
                # Prepare features for the model
                X = self._prepare_features_for_model(features, window_key)
                
                if X is None or len(X) == 0:
                    continue
                
                # Get anomaly score (higher = more anomalous)
                score = self.models[window_key].score_samples(X)[0]
                anomaly_score = 1.0 - (1.0 / (1.0 + np.exp(-10 * (score + 0.5))))  # Sigmoid scaling
                
                # Check against baseline
                baseline = self.baselines[window_key].get('anomaly_score_mean', 0.5)
                std = self.baselines[window_key].get('anomaly_score_std', 0.1)
                
                # Calculate deviation from baseline in standard deviations
                deviation = (anomaly_score - baseline) / (std + 1e-6)
                
                # Store results for each entity
                entities = [
                    (f"ip:{features['src_ip']}", 0.4),  # Source IP is less important
                    (f"ip:{features['dst_ip']}", 0.4),  # Destination IP is less important
                    (f"hostpair:{features['src_ip']}-{features['dst_ip']}", 0.6),
                    (f"service:{features.get('dst_port', 0)}:{features.get('protocol', 'unknown')}", 0.8)
                ]
                
                for entity, weight in entities:
                    if entity not in anomalies or deviation > anomalies[entity]:
                        anomalies[entity] = deviation * weight
                
            except Exception as e:
                logger.error(f"Error detecting anomalies: {e}")
        
        return anomalies
    
    def _prepare_features_for_model(self, features: Dict[str, Any], window_key: str) -> Optional[np.ndarray]:
        """Prepare features for model input."""
        try:
            # Select and scale features
            X = np.array([
                features.get(f, 0) for f in self.config.features
                if f in features and isinstance(features[f], (int, float))
            ]).reshape(1, -1)
            
            # Scale features
            if window_key in self.scalers and hasattr(self.scalers[window_key], 'scale_'):
                X = self.scalers[window_key].transform(X)
            
            return X
            
        except Exception as e:
            logger.error(f"Error preparing features: {e}")
            return None
    
    async def _model_updater(self):
        """Periodically update the behavioral models."""
        while self.active:
            try:
                # Check if we're still in the learning phase
                if self.learning_phase:
                    learning_hours = (datetime.utcnow() - self.learning_start).total_seconds() / 3600
                    
                    if learning_hours >= self.config.learning_phase_hours:
                        await self._train_models()
                        self.learning_phase = False
                        logger.info("Learning phase completed. Behavioral models are now active.")
                else:
                    # Update models periodically
                    await self._update_models()
                
                # Wait before next update
                await asyncio.sleep(self.config.model_update_interval * 3600)
                
            except Exception as e:
                logger.error(f"Error in model updater: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _train_models(self):
        """Train the behavioral models using collected data."""
        logger.info("Training behavioral models...")
        
        try:
            # Prepare training data for each time window
            for window in self.config.time_windows:
                window_key = str(window)
                
                # Get features for this window
                features = list(self.feature_store.get(window_key, []))
                
                if len(features) < self.config.min_training_samples:
                    logger.warning(f"Insufficient training samples for {window}m window: {len(features)} < {self.config.min_training_samples}")
                    continue
                
                # Convert to DataFrame
                df = pd.DataFrame(features)
                
                # Select and scale features
                X = df[self.config.features].values
                
                # Train the scaler
                self.scalers[window_key] = StandardScaler()
                X_scaled = self.scalers[window_key].fit_transform(X)
                
                # Train the model
                self.models[window_key].fit(X_scaled)
                
                # Calculate baseline anomaly scores
                scores = self.models[window_key].score_samples(X_scaled)
                self.baselines[window_key] = {
                    'anomaly_score_mean': float(np.mean(scores)),
                    'anomaly_score_std': float(np.std(scores)),
                    'trained_at': datetime.utcnow().isoformat(),
                    'training_samples': len(X_scaled)
                }
                
                logger.info(f"Trained model for {window}m window with {len(X_scaled)} samples")
            
            # Save the trained models
            self._save_models()
            logger.info("Behavioral models trained and saved successfully")
            
        except Exception as e:
            logger.error(f"Error training models: {e}")
    
    async def _update_models(self):
        """Update the behavioral models with new data."""
        logger.info("Updating behavioral models...")
        
        try:
            # For now, we'll just retrain the models
            # In a production system, you might implement incremental learning
            await self._train_models()
            
        except Exception as e:
            logger.error(f"Error updating models: {e}")
    
    async def _data_persister(self):
        """Periodically persist feature data to disk."""
        while self.active:
            try:
                # Save feature store every hour
                self._save_feature_store()
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error persisting feature data: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    def _save_models(self):
        """Save the trained models to disk."""
        try:
            # Save each model
            for window, model in self.models.items():
                model_file = self.model_dir / f"behavior_model_{window}m.pkl"
                with open(model_file, 'wb') as f:
                    pickle.dump({
                        'model': model,
                        'scaler': self.scalers[window],
                        'baseline': self.baselines.get(window, {}),
                        'trained_at': datetime.utcnow().isoformat()
                    }, f)
            
            logger.info("Behavioral models saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    def _load_models(self):
        """Load trained models from disk."""
        try:
            model_files = list(self.model_dir.glob("behavior_model_*.pkl"))
            
            for model_file in model_files:
                try:
                    with open(model_file, 'rb') as f:
                        data = pickle.load(f)
                        
                    window = model_file.stem.split('_')[-1][:-1]  # Extract window size
                    self.models[window] = data['model']
                    self.scalers[window] = data['scaler']
                    self.baselines[window] = data.get('baseline', {})
                    
                    logger.info(f"Loaded model for {window}m window (trained at {data.get('trained_at', 'unknown')})")
                    
                except Exception as e:
                    logger.error(f"Error loading model {model_file}: {e}")
            
            if self.models:
                logger.info(f"Loaded {len(self.models)} behavioral models")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
    
    def _save_feature_store(self):
        """Save the feature store to disk."""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            
            for window, features in self.feature_store.items():
                if not features:
                    continue
                    
                # Create a filename with timestamp and window
                filename = self.data_dir / f"features_{window}_{timestamp}.json"
                
                # Convert deque to list for JSON serialization
                features_list = list(features)
                
                # Save to file
                with open(filename, 'w') as f:
                    json.dump(features_list, f, indent=2)
            
            logger.debug(f"Saved feature store with {sum(len(f) for f in self.feature_store.values())} entries")
            
        except Exception as e:
            logger.error(f"Error saving feature store: {e}")
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist."""
        if not ip or not self.config.whitelist:
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            for cidr in self.config.whitelist:
                if ip_obj in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            pass
            
        return False
    
    def _generate_alert(self, flow: NetworkFlow, entity: str, score: float):
        """Generate an alert for a detected anomaly."""
        try:
            # Create alert
            alert = NetworkAlert(
                title=f"Behavioral Anomaly Detected",
                description=f"Unusual network behavior detected for {entity} (score: {score:.2f})",
                severity=self._get_alert_severity(score),
                source_ip=flow.src_ip,
                destination_ip=flow.dst_ip,
                source_port=flow.src_port,
                destination_port=flow.dst_port,
                protocol=flow.protocol,
                metadata={
                    'entity': entity,
                    'anomaly_score': float(score),
                    'flow_bytes': flow.bytes_sent + flow.bytes_received,
                    'flow_packets': flow.packets_sent + flow.packets_received,
                    'threat_type': 'behavioral_anomaly',
                    'direction': flow.direction.name.lower(),
                    'is_zero_day': True
                }
            )
            
            # Notify callbacks
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error generating alert: {e}")
    
    def _get_alert_severity(self, score: float) -> AlertSeverity:
        """Determine alert severity based on anomaly score."""
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        elif score >= 0.75:
            return AlertSeverity.HIGH
        elif score >= 0.6:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW
