"""
Anomaly Detection for NIPS

This module implements anomaly-based detection for identifying unusual patterns
in network traffic that may indicate zero-day attacks or sophisticated threats.
"""

import logging
import time
import json
import math
import statistics
from collections import deque, defaultdict
from typing import Dict, List, Optional, Tuple, Set, Any, Deque, DefaultDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger('nips.anomaly_detector')

@dataclass
class TrafficStats:
    """Statistics for network traffic analysis."""
    packet_count: int = 0
    byte_count: int = 0
    flow_count: int = 0
    
    # Protocol distribution
    protocol_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Port distribution
    src_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    dst_port_counts: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    # Packet size statistics
    packet_sizes: List[int] = field(default_factory=list)
    
    # Flow duration statistics
    flow_durations: List[float] = field(default_factory=list)
    
    # Packet inter-arrival times
    inter_arrival_times: List[float] = field(default_factory=list)
    
    # Connection states
    connection_states: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Flag distribution
    tcp_flags: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    def update(self, packet: Dict[str, Any]):
        """Update statistics with a new packet."""
        self.packet_count += 1
        self.byte_count += packet.get('length', 0)
        
        # Update protocol distribution
        protocol = packet.get('protocol', 'unknown').lower()
        self.protocol_counts[protocol] += 1
        
        # Update port distributions
        src_port = packet.get('src_port')
        if src_port is not None:
            self.src_port_counts[src_port] += 1
            
        dst_port = packet.get('dst_port')
        if dst_port is not None:
            self.dst_port_counts[dst_port] += 1
        
        # Update packet sizes
        self.packet_sizes.append(packet.get('length', 0))
        
        # Update TCP flags if available
        if 'tcp_flags' in packet:
            for flag, value in packet['tcp_flags'].items():
                if value:
                    self.tcp_flags[flag] += 1
        
        # Update connection states if available
        if 'tcp_flags' in packet and 'syn' in packet['tcp_flags']:
            if packet['tcp_flags'].get('syn') and not packet['tcp_flags'].get('ack'):
                self.connection_states['syn'] += 1
            elif packet['tcp_flags'].get('syn') and packet['tcp_flags'].get('ack'):
                self.connection_states['syn_ack'] += 1
            elif packet['tcp_flags'].get('fin'):
                self.connection_states['fin'] += 1
            elif packet['tcp_flags'].get('rst'):
                self.connection_states['rst'] += 1
    
    def get_features(self) -> Dict[str, float]:
        """Extract features for anomaly detection."""
        features = {
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'flow_count': self.flow_count,
            'avg_packet_size': 0.0,
            'std_packet_size': 0.0,
            'entropy_src_ports': 0.0,
            'entropy_dst_ports': 0.0,
            'entropy_protocols': 0.0,
            'syn_flood_ratio': 0.0,
            'syn_ack_ratio': 0.0,
            'fin_ratio': 0.0,
            'rst_ratio': 0.0,
            'avg_flow_duration': 0.0,
            'std_flow_duration': 0.0,
            'avg_inter_arrival_time': 0.0,
            'std_inter_arrival_time': 0.0,
            'port_scan_score': 0.0,
            'protocol_anomaly_score': 0.0
        }
        
        # Calculate packet size statistics
        if self.packet_sizes:
            features['avg_packet_size'] = float(statistics.mean(self.packet_sizes))
            if len(self.packet_sizes) > 1:
                features['std_packet_size'] = float(statistics.stdev(self.packet_sizes))
        
        # Calculate port entropy (measure of randomness in port usage)
        features['entropy_src_ports'] = self._calculate_entropy(self.src_port_counts.values())
        features['entropy_dst_ports'] = self._calculate_entropy(self.dst_port_counts.values())
        
        # Calculate protocol entropy
        features['entropy_protocols'] = self._calculate_entropy(self.protocol_counts.values())
        
        # Calculate TCP flag ratios
        total_flags = sum(self.tcp_flags.values())
        if total_flags > 0:
            features['syn_flood_ratio'] = self.tcp_flags.get('syn', 0) / total_flags
            features['syn_ack_ratio'] = self.tcp_flags.get('ack', 0) / total_flags
            features['fin_ratio'] = self.tcp_flags.get('fin', 0) / total_flags
            features['rst_ratio'] = self.tcp_flags.get('rst', 0) / total_flags
        
        # Calculate flow duration statistics
        if self.flow_durations:
            features['avg_flow_duration'] = float(statistics.mean(self.flow_durations))
            if len(self.flow_durations) > 1:
                features['std_flow_duration'] = float(statistics.stdev(self.flow_durations))
        
        # Calculate inter-arrival time statistics
        if self.inter_arrival_times:
            features['avg_inter_arrival_time'] = float(statistics.mean(self.inter_arrival_times))
            if len(self.inter_arrival_times) > 1:
                features['std_inter_arrival_time'] = float(statistics.stdev(self.inter_arrival_times))
        
        # Calculate port scan score (higher for many different destination ports)
        unique_dst_ports = len(self.dst_port_counts)
        features['port_scan_score'] = min(1.0, unique_dst_ports / 100.0)  # Cap at 1.0 for 100+ unique ports
        
        # Calculate protocol anomaly score (higher for unusual protocol usage)
        total_packets = sum(self.protocol_counts.values())
        if total_packets > 0:
            # Consider non-TCP/UDP traffic as potentially anomalous
            normal_protocols = {'tcp', 'udp', 'icmp'}
            anomalous_traffic = sum(count for proto, count in self.protocol_counts.items() 
                                  if proto.lower() not in normal_protocols)
            features['protocol_anomaly_score'] = anomalous_traffic / total_packets
        
        return features
    
    @staticmethod
    def _calculate_entropy(counts) -> float:
        """Calculate the entropy of a distribution."""
        total = sum(counts)
        if total == 0:
            return 0.0
        
        entropy = 0.0
        for count in counts:
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        
        return entropy

@dataclass
class AnomalyDetectorConfig:
    """Configuration for the anomaly detector."""
    # General settings
    enabled: bool = True
    mode: str = 'learn'  # 'learn', 'detect', or 'hybrid'
    
    # Time window settings
    window_size: int = 60  # seconds
    slide_interval: int = 10  # seconds
    
    # Thresholds
    anomaly_threshold: float = 0.7  # Score above which to consider traffic anomalous
    min_samples_for_training: int = 1000  # Minimum samples before enabling detection
    
    # Model settings
    contamination: float = 0.1  # Expected proportion of outliers in the data
    random_state: int = 42  # For reproducibility
    
    # Alert settings
    alert_on_high_confidence: bool = True
    alert_on_medium_confidence: bool = True
    alert_on_low_confidence: bool = False
    
    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'AnomalyDetectorConfig':
        """Create an AnomalyDetectorConfig from a dictionary."""
        return cls(**{
            k: v for k, v in config_dict.items() 
            if k in cls.__annotations__
        })

class AnomalyDetector:
    """Anomaly detection engine for network traffic analysis."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize the anomaly detector.
        
        Args:
            config: Configuration dictionary (optional)
        """
        self.config = AnomalyDetectorConfig.from_dict(config or {})
        
        # Model components
        self.model = IsolationForest(
            contamination=self.config.contamination,
            random_state=self.config.random_state,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Traffic statistics
        self.current_window = TrafficStats()
        self.window_start_time = time.time()
        self.windows: Deque[Dict[str, Any]] = deque(maxlen=1000)  # Store recent windows
        
        # Training data
        self.training_data: List[Dict[str, float]] = []
        self.feature_names: List[str] = []
        
        # Alert thresholds
        self.alert_thresholds = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }
        
        # State
        self.learning_mode = self.config.mode in ('learn', 'hybrid')
        self.detection_enabled = self.config.mode in ('detect', 'hybrid')
        
        logger.info(f"Anomaly detector initialized in {self.config.mode} mode")
    
    def process_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a network packet for anomaly detection.
        
        Args:
            packet: The packet to process
            
        Returns:
            Anomaly detection result or None if no anomaly detected
        """
        # Update current window statistics
        self.current_window.update(packet)
        
        # Check if we should slide the window
        current_time = time.time()
        if current_time - self.window_start_time >= self.config.slide_interval:
            return self._process_window()
        
        return None
    
    def _process_window(self) -> Optional[Dict[str, Any]]:
        """Process the current time window and check for anomalies."""
        # Extract features from the current window
        features = self.current_window.get_features()
        
        # Store the window data
        window_data = {
            'timestamp': self.window_start_time,
            'features': features,
            'packet_count': self.current_window.packet_count,
            'byte_count': self.current_window.byte_count
        }
        
        # Add to training data if in learning mode
        if self.learning_mode:
            self.training_data.append(features)
            
            # Train the model if we have enough samples
            if len(self.training_data) >= self.config.min_samples_for_training:
                self._train_model()
        
        # Check for anomalies if detection is enabled and the model is trained
        anomaly_result = None
        if self.detection_enabled and self.is_trained:
            anomaly_result = self._detect_anomalies(features)
            window_data['anomaly'] = anomaly_result
        
        # Add to window history
        self.windows.append(window_data)
        
        # Reset the current window
        self.current_window = TrafficStats()
        self.window_start_time = time.time()
        
        return anomaly_result
    
    def _train_model(self) -> bool:
        """Train the anomaly detection model."""
        if not self.training_data:
            logger.warning("No training data available")
            return False
        
        try:
            # Extract feature names from the first sample
            if not self.feature_names:
                self.feature_names = list(self.training_data[0].keys())
            
            # Convert training data to a numpy array
            X = np.array([[sample[feat] for feat in self.feature_names] 
                         for sample in self.training_data])
            
            # Scale the features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.model.fit(X_scaled)
            self.is_trained = True
            
            logger.info(f"Trained anomaly detection model with {len(self.training_data)} samples")
            
            # If we were in learning mode and now have a trained model, switch to detection
            if self.learning_mode and not self.detection_enabled:
                self.detection_enabled = True
                logger.info("Switching to detection mode")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training anomaly detection model: {e}")
            return False
    
    def _detect_anomalies(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Detect anomalies in the given feature set.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Dictionary containing anomaly detection results
        """
        if not self.is_trained:
            return {
                'is_anomaly': False,
                'score': 0.0,
                'confidence': 'low',
                'reason': 'Model not trained'
            }
        
        try:
            # Prepare the feature vector
            X = np.array([[features.get(feat, 0.0) for feat in self.feature_names]])
            
            # Scale the features
            X_scaled = self.scaler.transform(X)
            
            # Predict anomaly score (higher is more anomalous)
            anomaly_score = -self.model.score_samples(X_scaled)[0]  # Convert to positive scale
            
            # Determine if this is an anomaly
            is_anomaly = anomaly_score >= self.config.anomaly_threshold
            
            # Determine confidence level
            if anomaly_score >= self.alert_thresholds['high']:
                confidence = 'high'
            elif anomaly_score >= self.alert_thresholds['medium']:
                confidence = 'medium'
            else:
                confidence = 'low'
            
            # Determine if we should alert based on confidence
            should_alert = False
            if confidence == 'high' and self.config.alert_on_high_confidence:
                should_alert = True
            elif confidence == 'medium' and self.config.alert_on_medium_confidence:
                should_alert = True
            elif confidence == 'low' and self.config.alert_on_low_confidence:
                should_alert = True
            
            # Prepare the result
            result = {
                'is_anomaly': is_anomaly,
                'score': float(anomaly_score),
                'confidence': confidence,
                'should_alert': should_alert,
                'reason': self._explain_anomaly(features, anomaly_score)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return {
                'is_anomaly': False,
                'score': 0.0,
                'confidence': 'low',
                'reason': f'Error: {str(e)}'
            }
    
    def _explain_anomaly(self, features: Dict[str, float], anomaly_score: float) -> str:
        """Generate a human-readable explanation for an anomaly."""
        if anomaly_score < self.config.anomaly_threshold:
            return "No significant anomalies detected"
        
        # Get the most anomalous features
        feature_scores = []
        for feat in self.feature_names:
            value = features.get(feat, 0.0)
            
            # Calculate z-score for this feature
            if hasattr(self.scaler, 'mean_') and hasattr(self.scaler, 'scale_'):
                mean = self.scaler.mean_[self.feature_names.index(feat)]
                std = self.scaler.scale_[self.feature_names.index(feat)]
                if std > 0:
                    z_score = abs((value - mean) / std)
                    feature_scores.append((feat, z_score, value))
        
        # Sort by z-score (most anomalous first)
        feature_scores.sort(key=lambda x: x[1], reverse=True)
        
        # Get top 3 most anomalous features
        top_features = feature_scores[:3]
        
        # Generate explanation
        if not top_features:
            return "Anomaly detected, but no specific features stand out"
        
        explanations = []
        for feat, z_score, value in top_features:
            # Convert feature names to human-readable format
            readable_name = feat.replace('_', ' ').title()
            
            # Add explanation based on feature type
            if 'port_scan' in feat:
                if value > 0.7:
                    explanations.append(f"Possible port scan detected ({readable_name} = {value:.2f})")
            elif 'syn_flood' in feat and value > 0.5:
                explanations.append(f"Possible SYN flood attack ({readable_name} = {value:.2f})")
            elif 'protocol_anomaly' in feat and value > 0.5:
                explanations.append(f"Unusual protocol usage detected ({readable_name} = {value:.2f})")
            elif 'entropy' in feat and value > 3.0:  # High entropy
                explanations.append(f"High entropy in {readable_name} ({value:.2f}), possible encrypted or obfuscated traffic")
            else:
                explanations.append(f"Anomalous {readable_name} (z-score: {z_score:.2f}, value: {value:.2f})")
        
        return "; ".join(explanations)
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the anomaly detector."""
        return {
            'mode': self.config.mode,
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data),
            'window_size': self.config.window_size,
            'slide_interval': self.config.slide_interval,
            'anomaly_threshold': self.config.anomaly_threshold,
            'recent_windows': len(self.windows),
            'learning_mode': self.learning_mode,
            'detection_enabled': self.detection_enabled
        }
    
    def set_mode(self, mode: str) -> bool:
        """Set the operating mode of the detector.
        
        Args:
            mode: One of 'learn', 'detect', or 'hybrid'
            
        Returns:
            True if the mode was set successfully, False otherwise
        """
        if mode not in ('learn', 'detect', 'hybrid'):
            logger.error(f"Invalid mode: {mode}")
            return False
        
        self.config.mode = mode
        self.learning_mode = mode in ('learn', 'hybrid')
        self.detection_enabled = mode in ('detect', 'hybrid')
        
        logger.info(f"Set anomaly detector mode to '{mode}'")
        return True
    
    def save_model(self, file_path: str) -> bool:
        """Save the trained model to a file.
        
        Args:
            file_path: Path to save the model to
            
        Returns:
            True if the model was saved successfully, False otherwise
        """
        if not self.is_trained:
            logger.warning("Cannot save untrained model")
            return False
        
        try:
            import joblib
            
            # Create a dictionary of model components
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'config': self.config,
                'training_data_size': len(self.training_data)
            }
            
            # Save to file
            joblib.dump(model_data, file_path)
            logger.info(f"Saved anomaly detection model to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def load_model(self, file_path: str) -> bool:
        """Load a trained model from a file.
        
        Args:
            file_path: Path to the model file
            
        Returns:
            True if the model was loaded successfully, False otherwise
        """
        try:
            import joblib
            
            # Load model data
            model_data = joblib.load(file_path)
            
            # Update model components
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.is_trained = True
            
            # Update config if available
            if 'config' in model_data:
                self.config = model_data['config']
            
            logger.info(f"Loaded anomaly detection model from {file_path} "
                       f"(trained on {model_data.get('training_data_size', 0)} samples)")
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def reset(self) -> None:
        """Reset the anomaly detector to its initial state."""
        self.model = IsolationForest(
            contamination=self.config.contamination,
            random_state=self.config.random_state
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = []
        self.feature_names = []
        self.current_window = TrafficStats()
        self.windows.clear()
        self.window_start_time = time.time()
        
        logger.info("Reset anomaly detector to initial state")
