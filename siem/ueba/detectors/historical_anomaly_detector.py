"""
Historical Anomaly Detector for UEBA.
Detects anomalies by comparing current behavior to historical baselines.
"""
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timedelta
import logging
import numpy as np
from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path

from ..ueba.base import BaseBehaviorModel

class HistoricalAnomalyDetector(BaseBehaviorModel):
    """
    Detects anomalies by comparing current behavior to historical baselines.
    Uses statistical methods to identify significant deviations from normal patterns.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the historical anomaly detector."""
        super().__init__(config or {})
        self.logger = logging.getLogger("siem.ueba.historical_anomaly")
        
        # Configuration
        self.window_hours = int(self.config.get('window_hours', 24))
        self.learning_rate = float(self.config.get('learning_rate', 0.1))  # For updating baselines
        self.min_samples = int(self.config.get('min_samples', 100))  # Min samples for baseline
        
        # Baselines (hour of week -> {feature: (mean, std)})
        self.baselines = defaultdict(lambda: {'count': 0, 'sum': defaultdict(float), 'sum_sq': defaultdict(float)})
        
        # Short-term history for detecting recent anomalies
        self.short_term_history = defaultdict(lambda: deque(maxlen=1000))
        
        # Load baselines if they exist
        self._load_baselines()
    
    def extract_features(self, event: Dict[str, Any]) -> Optional[Dict[str, float]]:
        """
        Extract features for historical anomaly detection.
        
        Args:
            event: The event to analyze
            
        Returns:
            Dictionary of features and their anomaly scores (0-1)
        """
        try:
            timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
            hour_of_week = self._get_hour_of_week(timestamp)
            
            # Extract basic features
            features = {
                'event_count': 1.0,  # Simple count of events
                'src_ips': 0.0,  # Will be set based on uniqueness
                'dst_ports': 0.0,  # Will be set based on uniqueness
                'data_volume': float(event.get('network', {}).get('bytes', 0)),
                'response_time': float(event.get('event', {}).get('duration', 0)),
            }
            
            # Update short-term history
            source_ip = event.get('source', {}).get('ip')
            dest_port = event.get('destination', {}).get('port')
            
            if source_ip:
                self.short_term_history['src_ips'].append(source_ip)
            if dest_port:
                self.short_term_history['dst_ports'].append(dest_port)
            
            # Calculate uniqueness scores
            if self.short_term_history['src_ips']:
                features['src_ips'] = len(set(self.short_term_history['src_ips'])) / len(self.short_term_history['src_ips'])
            if self.short_term_history['dst_ports']:
                features['dst_ports'] = len(set(self.short_term_history['dst_ports'])) / len(self.short_term_history['dst_ports'])
            
            # Calculate anomaly scores
            anomaly_scores = {}
            for feature, value in features.items():
                baseline = self.baselines[hour_of_week]
                
                if baseline['count'] >= self.min_samples and feature in baseline['sum']:
                    mean = baseline['sum'][feature] / baseline['count']
                    variance = (baseline['sum_sq'][feature] / baseline['count']) - (mean ** 2)
                    std = np.sqrt(max(0, variance))  # Avoid negative variance due to floating point errors
                    
                    if std > 0:
                        # Calculate z-score and convert to probability (0-1)
                        z_score = abs((value - mean) / std)
                        anomaly_score = 1 - np.exp(-0.5 * (z_score ** 2))
                    else:
                        # If no variance, check if value matches the mean
                        anomaly_score = 0.0 if value == mean else 1.0
                else:
                    # Not enough data for this feature yet
                    anomaly_score = 0.0
                
                anomaly_scores[f"anomaly_{feature}"] = anomaly_score
                
                # Update baseline (online learning)
                self._update_baseline(hour_of_week, feature, value)
            
            # Overall anomaly score (max of all feature scores)
            if anomaly_scores:
                anomaly_scores['anomaly_score'] = max(anomaly_scores.values())
            else:
                anomaly_scores['anomaly_score'] = 0.0
            
            return anomaly_scores
            
        except Exception as e:
            self.logger.error(f"Error in extract_features: {e}", exc_info=True)
            return None
    
    def _get_hour_of_week(self, timestamp: datetime) -> int:
        """Convert timestamp to hour of week (0-167)."""
        # Monday = 0, Sunday = 6
        day_of_week = timestamp.weekday()
        hour_of_day = timestamp.hour
        return (day_of_week * 24) + hour_of_day
    
    def _update_baseline(self, hour_of_week: int, feature: str, value: float) -> None:
        """Update baseline statistics using online algorithm."""
        baseline = self.baselines[hour_of_week]
        
        # Update count
        baseline['count'] += 1
        
        # Update sum and sum of squares (for variance calculation)
        if feature not in baseline['sum']:
            baseline['sum'][feature] = 0.0
            baseline['sum_sq'][feature] = 0.0
        
        # Online update of mean and variance
        # Using Welford's online algorithm for numerical stability
        old_mean = baseline['sum'][feature] / baseline['count'] if baseline['count'] > 1 else value
        baseline['sum'][feature] += value
        
        if baseline['count'] > 1:
            # Update sum of squares using the two-pass algorithm
            delta = value - old_mean
            baseline['sum_sq'][feature] += delta * (value - baseline['sum'][feature] / baseline['count'])
    
    def train(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the model on historical data.
        
        Args:
            events: List of historical events
            
        Returns:
            Training results
        """
        self.logger.info(f"Training HistoricalAnomalyDetector on {len(events)} events")
        
        # Group events by hour of week
        hourly_events = defaultdict(list)
        for event in events:
            try:
                timestamp = datetime.fromisoformat(event['@timestamp'].replace('Z', '+00:00'))
                hour = self._get_hour_of_week(timestamp)
                hourly_events[hour].append(event)
            except (KeyError, ValueError) as e:
                continue
        
        # Calculate statistics for each hour
        for hour, hour_events in hourly_events.items():
            # Extract features for all events in this hour
            features = defaultdict(list)
            for event in hour_events:
                # Simple feature extraction (can be extended)
                features['event_count'].append(1.0)
                features['data_volume'].append(float(event.get('network', {}).get('bytes', 0)))
                features['response_time'].append(float(event.get('event', {}).get('duration', 0)))
            
            # Update baselines
            for feature, values in features.items():
                if values:  # Only update if we have data
                    mean = np.mean(values)
                    std = np.std(values) if len(values) > 1 else 0.0
                    
                    # Update baseline with aggregated statistics
                    baseline = self.baselines[hour]
                    baseline['count'] = len(values)
                    baseline['sum'][feature] = mean * len(values)
                    baseline['sum_sq'][feature] = (std ** 2 + mean ** 2) * len(values)
        
        # Save updated baselines
        self._save_baselines()
        
        return {
            'status': 'success',
            'hours_trained': len(hourly_events),
            'total_events': len(events)
        }
    
    def _save_baselines(self) -> None:
        """Save baseline statistics to disk."""
        try:
            baselines_dir = Path('models/ueba/historical_baselines')
            baselines_dir.mkdir(parents=True, exist_ok=True)
            
            # Convert numpy types to native Python types for JSON serialization
            baselines_serializable = {}
            for hour, stats in self.baselines.items():
                baselines_serializable[hour] = {
                    'count': stats['count'],
                    'sum': {k: float(v) for k, v in stats['sum'].items()},
                    'sum_sq': {k: float(v) for k, v in stats['sum_sq'].items()}
                }
            
            with open(baselines_dir / 'baselines.json', 'w') as f:
                json.dump(baselines_serializable, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error saving baselines: {e}", exc_info=True)
    
    def _load_baselines(self) -> None:
        """Load baseline statistics from disk."""
        try:
            baselines_file = Path('models/ueba/historical_baselines/baselines.json')
            if baselines_file.exists():
                with open(baselines_file, 'r') as f:
                    baselines_serializable = json.load(f)
                
                # Convert back to numpy types
                for hour, stats in baselines_serializable.items():
                    self.baselines[int(hour)] = {
                        'count': stats['count'],
                        'sum': {k: float(v) for k, v in stats['sum'].items()},
                        'sum_sq': {k: float(v) for k, v in stats['sum_sq'].items()}
                    }
                
                self.logger.info(f"Loaded baselines for {len(self.baselines)} hours")
            
        except Exception as e:
            self.logger.error(f"Error loading baselines: {e}", exc_info=True)
    
    def detect_trends(self, metric: str, time_window: str = '30d') -> Dict[str, Any]:
        """
        Detect trends in a specific metric over time.
        
        Args:
            metric: The metric to analyze (e.g., 'event_count', 'data_volume')
            time_window: Time window to analyze (e.g., '7d', '30d')
            
        Returns:
            Dictionary containing trend analysis
        """
        # This is a simplified example - in a real implementation, you would
        # query your historical data store for the specified time window
        
        # Calculate baseline statistics for the metric
        metric_values = []
        for hour, stats in self.baselines.items():
            if metric in stats['sum'] and stats['count'] > 0:
                metric_values.append(stats['sum'][metric] / stats['count'])
        
        if not metric_values:
            return {
                'status': 'error',
                'message': f'No data available for metric: {metric}'
            }
        
        # Simple trend analysis (could be enhanced with more sophisticated methods)
        mean = np.mean(metric_values)
        std = np.std(metric_values) if len(metric_values) > 1 else 0.0
        
        # Check for recent anomalies (last hour compared to baseline)
        current_hour = self._get_hour_of_week(datetime.utcnow())
        current_value = 0.0
        if current_hour in self.baselines and metric in self.baselines[current_hour]['sum']:
            current_value = self.baselines[current_hour]['sum'][metric] / max(1, self.baselines[current_hour]['count'])
        
        is_anomaly = False
        if std > 0:
            z_score = abs((current_value - mean) / std) if std > 0 else 0
            is_anomaly = z_score > 3  # 3 standard deviations
        
        return {
            'status': 'success',
            'metric': metric,
            'time_window': time_window,
            'current_value': current_value,
            'baseline_mean': mean,
            'baseline_std': std,
            'is_anomaly': is_anomaly,
            'anomaly_score': min(1.0, abs(z_score) / 5.0) if std > 0 else 0.0,
            'suggestion': 'Investigate further' if is_anomaly else 'No action needed'
        }
