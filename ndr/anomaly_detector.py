"""
Behavioral Anomaly Detection for Network Traffic.

This module implements machine learning-based anomaly detection to identify
suspicious network behavior by comparing current traffic patterns against
learned baselines of normal activity.
"""
import json
import logging
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import deque
import pickle

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import numpy.typing as npt

logger = logging.getLogger('edr.network.anomaly_detector')

@dataclass
class NetworkBaseline:
    """Stores baseline network behavior metrics."""
    # Time-based features (per time window)
    connections_per_second: Dict[str, float] = field(default_factory=dict)  # Mean and std
    bytes_per_second: Dict[str, float] = field(default_factory=dict)
    packets_per_second: Dict[str, float] = field(default_factory=dict)
    
    # Protocol distribution
    protocol_distribution: Dict[str, float] = field(default_factory=dict)
    
    # Port usage patterns
    common_ports: Dict[int, float] = field(default_factory=dict)  # port: frequency
    
    # Traffic patterns by time of day
    time_of_day_patterns: Dict[int, Dict[str, float]] = field(default_factory=dict)  # hour: {metric: value}
    
    # Model artifacts
    isolation_forest: Optional[Any] = None
    scaler: Optional[Any] = None
    kmeans: Optional[Any] = None
    
    # Baseline metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert baseline to a serializable dictionary."""
        return {
            'connections_per_second': self.connections_per_second,
            'bytes_per_second': self.bytes_per_second,
            'packets_per_second': self.packets_per_second,
            'protocol_distribution': self.protocol_distribution,
            'common_ports': {str(k): v for k, v in self.common_ports.items()},
            'time_of_day_patterns': {
                str(hour): metrics 
                for hour, metrics in self.time_of_day_patterns.items()
            },
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'model_version': '1.0'
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NetworkBaseline':
        """Create a NetworkBaseline from a dictionary."""
        baseline = cls()
        baseline.connections_per_second = data.get('connections_per_second', {})
        baseline.bytes_per_second = data.get('bytes_per_second', {})
        baseline.packets_per_second = data.get('packets_per_second', {})
        baseline.protocol_distribution = data.get('protocol_distribution', {})
        baseline.common_ports = {int(k): v for k, v in data.get('common_ports', {}).items()}
        baseline.time_of_day_patterns = {
            int(hour): metrics 
            for hour, metrics in data.get('time_of_day_patterns', {}).items()
        }
        baseline.created_at = datetime.fromisoformat(data.get('created_at', datetime.utcnow().isoformat()))
        baseline.updated_at = datetime.fromisoformat(data.get('updated_at', datetime.utcnow().isoformat()))
        return baseline


class NetworkAnomalyDetector:
    """
    Detects anomalies in network traffic by comparing against learned baselines
    of normal behavior using machine learning techniques.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the anomaly detector with configuration."""
        self.config = config
        self.baseline = NetworkBaseline()
        self.window_size = config.get('window_size', 60)  # seconds
        self.min_baseline_days = config.get('min_baseline_days', 7)
        self.anomaly_threshold = config.get('anomaly_threshold', -0.5)  # Isolation Forest threshold
        
        # Sliding window data
        self.window_start = datetime.utcnow()
        self.current_window = {
            'connections': 0,
            'bytes': 0,
            'packets': 0,
            'protocols': {},
            'ports': {},
            'start_time': datetime.utcnow()
        }
        
        # Historical data for baseline learning
        self.historical_data = {
            'connections': [],
            'bytes': [],
            'packets': [],
            'protocols': {},
            'ports': {},
            'timestamps': []
        }
        
        # Anomaly detection models
        self.isolation_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
        self.scaler = StandardScaler()
        self.kmeans = KMeans(n_clusters=5, random_state=42)
        
        # Load existing baseline if available
        self.baseline_file = Path(config.get('baseline_file', 'network_baseline.json'))
        self._load_baseline()
    
    def _load_baseline(self):
        """Load baseline from file if it exists."""
        try:
            if self.baseline_file.exists():
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                    self.baseline = NetworkBaseline.from_dict(data)
                logger.info(f"Loaded baseline from {self.baseline_file}")
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
    
    def save_baseline(self):
        """Save the current baseline to file."""
        try:
            self.baseline.updated_at = datetime.utcnow()
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline.to_dict(), f, indent=2)
            logger.info(f"Saved baseline to {self.baseline_file}")
            return True
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")
            return False
    
    def update_window(self, flow_data: Dict[str, Any]):
        """Update the current time window with new flow data."""
        now = datetime.utcnow()
        
        # Check if we need to start a new window
        if (now - self.window_start).total_seconds() >= self.window_size:
            self._finalize_window()
            self.window_start = now
            self.current_window = {
                'connections': 0,
                'bytes': 0,
                'packets': 0,
                'protocols': {},
                'ports': {},
                'start_time': now
            }
        
        # Update window metrics
        self.current_window['connections'] += 1
        self.current_window['bytes'] += flow_data.get('bytes', 0)
        self.current_window['packets'] += flow_data.get('packets', 0)
        
        # Update protocol distribution
        protocol = flow_data.get('protocol', 'other')
        self.current_window['protocols'][protocol] = self.current_window['protocols'].get(protocol, 0) + 1
        
        # Update port usage
        src_port = flow_data.get('src_port')
        dst_port = flow_data.get('dst_port')
        
        if src_port:
            self.current_window['ports'][src_port] = self.current_window['ports'].get(src_port, 0) + 1
        if dst_port:
            self.current_window['ports'][dst_port] = self.current_window['ports'].get(dst_port, 0) + 1
    
    def _finalize_window(self):
        """Process the completed time window and update historical data."""
        if self.current_window['connections'] == 0:
            return
            
        window = self.current_window
        duration = (datetime.utcnow() - window['start_time']).total_seconds()
        
        # Calculate rates
        connections_per_sec = window['connections'] / duration if duration > 0 else 0
        bytes_per_sec = window['bytes'] / duration if duration > 0 else 0
        packets_per_sec = window['packets'] / duration if duration > 0 else 0
        
        # Update historical data
        self.historical_data['connections'].append(connections_per_sec)
        self.historical_data['bytes'].append(bytes_per_sec)
        self.historical_data['packets'].append(packets_per_sec)
        self.historical_data['timestamps'].append(window['start_time'])
        
        # Update protocol distribution
        total_connections = sum(window['protocols'].values())
        for protocol, count in window['protocols'].items():
            if protocol not in self.historical_data['protocols']:
                self.historical_data['protocols'][protocol] = []
            self.historical_data['protocols'][protocol].append(count / total_connections)
        
        # Update port distribution
        for port, count in window['ports'].items():
            if port not in self.historical_data['ports']:
                self.historical_data['ports'][port] = 0
            self.historical_data['ports'][port] += count
    
    def learn_baseline(self):
        """Learn the baseline of normal network behavior."""
        if len(self.historical_data['timestamps']) < 2:
            logger.warning("Not enough data to learn baseline")
            return False
        
        # Calculate statistics for time-based features
        self.baseline.connections_per_second = self._calculate_stats(self.historical_data['connections'])
        self.baseline.bytes_per_second = self._calculate_stats(self.historical_data['bytes'])
        self.baseline.packets_per_second = self._calculate_stats(self.historical_data['packets'])
        
        # Calculate protocol distribution
        total_connections = sum(len(v) for v in self.historical_data['protocols'].values())
        for protocol, counts in self.historical_data['protocols'].items():
            self.baseline.protocol_distribution[protocol] = sum(counts) / total_connections
        
        # Calculate common ports (top N by frequency)
        total_port_usage = sum(self.historical_data['ports'].values())
        sorted_ports = sorted(
            self.historical_data['ports'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        # Keep top 100 most common ports or all if less than 100
        top_ports = sorted_ports[:100]
        for port, count in top_ports:
            self.baseline.common_ports[port] = count / total_port_usage
        
        # Learn time-of-day patterns
        self._learn_time_patterns()
        
        # Train machine learning models
        self._train_models()
        
        # Save the updated baseline
        self.save_baseline()
        
        return True
    
    def _calculate_stats(self, values: List[float]) -> Dict[str, float]:
        """Calculate mean and standard deviation of a list of values."""
        if not values:
            return {'mean': 0, 'std': 0}
            
        mean = np.mean(values)
        std = np.std(values)
        return {'mean': float(mean), 'std': float(std) if not np.isnan(std) else 0.0}
    
    def _learn_time_patterns(self):
        """Learn patterns of network behavior by time of day."""
        hourly_data = {i: {'connections': [], 'bytes': [], 'packets': []} for i in range(24)}
        
        for i in range(len(self.historical_data['timestamps'])):
            hour = self.historical_data['timestamps'][i].hour
            hourly_data[hour]['connections'].append(self.historical_data['connections'][i])
            hourly_data[hour]['bytes'].append(self.historical_data['bytes'][i])
            hourly_data[hour]['packets'].append(self.historical_data['packets'][i])
        
        # Calculate hourly statistics
        for hour, metrics in hourly_data.items():
            if metrics['connections']:  # Only if we have data for this hour
                self.baseline.time_of_day_patterns[hour] = {
                    'connections_mean': np.mean(metrics['connections']),
                    'connections_std': np.std(metrics['connections']) if len(metrics['connections']) > 1 else 0.0,
                    'bytes_mean': np.mean(metrics['bytes']),
                    'bytes_std': np.std(metrics['bytes']) if len(metrics['bytes']) > 1 else 0.0,
                    'packets_mean': np.mean(metrics['packets']),
                    'packets_std': np.std(metrics['packets']) if len(metrics['packets']) > 1 else 0.0
                }
    
    def _train_models(self):
        """Train machine learning models for anomaly detection."""
        # Prepare features for clustering and anomaly detection
        features = []
        
        for i in range(len(self.historical_data['timestamps'])):
            # Basic time-series features
            feature_vector = [
                self.historical_data['connections'][i],
                self.historical_data['bytes'][i],
                self.historical_data['packets'][i],
                
                # Add protocol distribution (top 5 most common)
                *[
                    self.historical_data['protocols'].get(proto, [0] * len(self.historical_data['timestamps']))[i]
                    for proto in sorted(
                        self.historical_data['protocols'].keys(),
                        key=lambda x: sum(self.historical_data['protocols'][x]),
                        reverse=True
                    )[:5]
                ],
                
                # Add time of day features
                self.historical_data['timestamps'][i].hour,
                self.historical_data['timestamps'][i].weekday()
            ]
            
            # Pad with zeros if we don't have enough protocol features
            feature_vector.extend([0] * (12 - len(feature_vector)))
            features.append(feature_vector)
        
        if not features:
            logger.warning("No features available for model training")
            return
        
        # Scale features
        self.scaler.fit(features)
        scaled_features = self.scaler.transform(features)
        
        # Train Isolation Forest for anomaly detection
        self.isolation_forest.fit(scaled_features)
        
        # Train K-means for behavior clustering
        self.kmeans.fit(scaled_features)
        
        # Store models in baseline
        self.baseline.isolation_forest = self.isolation_forest
        self.baseline.scaler = self.scaler
        self.baseline.kmeans = self.kmeans
    
    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect anomalies in the current network metrics compared to the baseline.
        
        Args:
            current_metrics: Dictionary containing current network metrics
            
        Returns:
            Dictionary containing anomaly scores and detection results
        """
        if not self.baseline.protocol_distribution:
            logger.warning("No baseline available for anomaly detection")
            return {'anomaly_detected': False, 'reason': 'No baseline available'}
        
        results = {
            'anomaly_detected': False,
            'anomaly_score': 0.0,
            'anomaly_reasons': [],
            'metrics': {}
        }
        
        # 1. Check for traffic volume anomalies
        current_connections = current_metrics.get('connections_per_sec', 0)
        conn_mean = self.baseline.connections_per_second.get('mean', 0)
        conn_std = self.baseline.connections_per_second.get('std', 0)
        
        if conn_std > 0:  # Only check if we have enough data
            z_score = (current_connections - conn_mean) / conn_std
            if abs(z_score) > 3:  # More than 3 standard deviations from mean
                results['anomaly_detected'] = True
                results['anomaly_score'] = max(results['anomaly_score'], min(1.0, abs(z_score) / 10))
                results['anomaly_reasons'].append(
                    f"Unusual connection rate: {current_connections:.1f}/s "
                    f"(normal: {conn_mean:.1f}±{conn_std:.1f}/s)"
                )
        
        # 2. Check for protocol distribution anomalies
        current_protocols = current_metrics.get('protocol_distribution', {})
        for proto, expected_freq in self.baseline.protocol_distribution.items():
            current_freq = current_protocols.get(proto, 0)
            if expected_freq > 0 and current_freq > 0:
                # If protocol usage changes by more than 50% of baseline
                if abs(current_freq - expected_freq) / expected_freq > 0.5:
                    results['anomaly_detected'] = True
                    anomaly_score = min(1.0, abs(current_freq - expected_freq) / expected_freq)
                    results['anomaly_score'] = max(results['anomaly_score'], anomaly_score)
                    results['anomaly_reasons'].append(
                        f"Unusual {proto} traffic: {current_freq*100:.1f}% "
                        f"(normal: {expected_freq*100:.1f}%)"
                    )
        
        # 3. Check for unusual ports
        current_ports = current_metrics.get('port_distribution', {})
        for port, count in current_ports.items():
            if port not in self.baseline.common_ports and count > 5:  # More than 5 connections to an unusual port
                results['anomaly_detected'] = True
                results['anomaly_score'] = max(results['anomaly_score'], 0.7)
                results['anomaly_reasons'].append(
                    f"Unusual port activity: {count} connections to port {port}"
                )
        
        # 4. Use machine learning model for detection
        if self.baseline.isolation_forest and self.baseline.scaler:
            try:
                # Prepare current features in the same way as training
                current_feature = [
                    current_metrics.get('connections_per_sec', 0),
                    current_metrics.get('bytes_per_sec', 0),
                    current_metrics.get('packets_per_sec', 0),
                    *[
                        current_metrics.get('protocol_distribution', {}).get(proto, 0)
                        for proto in sorted(
                            self.baseline.protocol_distribution.keys(),
                            key=lambda x: self.baseline.protocol_distribution[x],
                            reverse=True
                        )[:5]
                    ],
                    datetime.utcnow().hour,
                    datetime.utcnow().weekday()
                ]
                
                # Pad with zeros if needed
                current_feature.extend([0] * (12 - len(current_feature)))
                
                # Scale features
                scaled_feature = self.baseline.scaler.transform([current_feature])
                
                # Get anomaly score from Isolation Forest
                anomaly_score = self.baseline.isolation_forest.score_samples(scaled_feature)[0]
                results['ml_anomaly_score'] = float(anomaly_score)
                
                if anomaly_score < self.anomaly_threshold:
                    results['anomaly_detected'] = True
                    results['anomaly_score'] = max(
                        results['anomaly_score'],
                        min(1.0, (self.anomaly_threshold - anomaly_score) / abs(self.anomaly_threshold))
                    )
                    results['anomaly_reasons'].append(
                        "ML model detected anomalous network behavior "
                        f"(score: {anomaly_score:.2f})"
                    )
                
            except Exception as e:
                logger.error(f"Error in ML-based anomaly detection: {e}")
        
        # Normalize anomaly score to 0-1 range
        results['anomaly_score'] = min(1.0, max(0.0, results['anomaly_score']))
        
        # Add current metrics to results
        results['metrics'] = {
            'connections_per_sec': current_metrics.get('connections_per_sec', 0),
            'bytes_per_sec': current_metrics.get('bytes_per_sec', 0),
            'packets_per_sec': current_metrics.get('packets_per_sec', 0),
            'protocol_distribution': current_metrics.get('protocol_distribution', {})
        }
        
        return results
