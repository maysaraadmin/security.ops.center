"""
Statistical models for behavior analysis.
"""
import numpy as np
from typing import Dict, Any, List
import json
import os

from .base import BehaviorModel

class StatisticalModel(BehaviorModel):
    """
    Statistical model for behavior analysis using percentiles and z-scores.
    
    This model learns the statistical distribution of features during training
    and uses percentiles and z-scores to detect anomalies.
    """
    
    def __init__(self):
        """Initialize the statistical model."""
        self.feature_stats = {}
        self.trained = False
    
    def train(self, data: List[Dict[str, Any]]) -> 'StatisticalModel':
        """
        Train the statistical model on the given data.
        
        For each feature, calculate mean, std, min, max, and percentiles.
        
        Args:
            data: List of training samples (dictionaries of features)
            
        Returns:
            The trained model (self)
        """
        if not data:
            return self
            
        # Initialize feature stats
        features = set()
        for sample in data:
            features.update(sample.keys())
            
        # Initialize stats for each feature
        self.feature_stats = {
            feature: {
                'values': [],
                'mean': 0,
                'std': 0,
                'min': 0,
                'max': 0,
                'percentiles': {}
            }
            for feature in features
        }
        
        # Collect values for each feature
        for sample in data:
            for feature, value in sample.items():
                if isinstance(value, (int, float)):
                    self.feature_stats[feature]['values'].append(value)
        
        # Calculate statistics
        for feature, stats in self.feature_stats.items():
            values = np.array(stats['values'])
            if len(values) > 0:
                stats['mean'] = float(np.mean(values))
                stats['std'] = float(np.std(values)) if len(values) > 1 else 1.0
                stats['min'] = float(np.min(values)) if len(values) > 0 else 0
                stats['max'] = float(np.max(values)) if len(values) > 0 else 0
                
                # Calculate percentiles (5th to 95th in 5% increments)
                for p in range(5, 100, 5):
                    stats['percentiles'][p] = float(np.percentile(values, p)) if len(values) > 0 else 0
                
        self.trained = True
        return self
    
    def score(self, features: Dict[str, Any]) -> float:
        """
        Calculate an anomaly score for the given features.
        
        The score is based on how many standard deviations each feature value
        is from the mean, weighted by the inverse of the standard deviation.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Anomaly score (higher means more anomalous)
        """
        if not self.trained:
            return 0.0
            
        scores = []
        
        for feature, value in features.items():
            if feature not in self.feature_stats or not isinstance(value, (int, float)):
                continue
                
            stats = self.feature_stats[feature]
            
            # Skip if we don't have enough data
            if stats['std'] == 0 or len(stats['values']) < 2:
                continue
                
            # Calculate z-score
            z_score = abs((value - stats['mean']) / stats['std'])
            
            # Higher weight for features with low variance
            weight = 1.0 / (1.0 + stats['std'])
            
            scores.append(z_score * weight)
        
        # Return the maximum score across all features
        return max(scores) if scores else 0.0
    
    def save(self, filepath: str) -> None:
        """
        Save the model to a file.
        
        Args:
            filepath: Path to save the model to
        """
        # Convert numpy types to Python native types for JSON serialization
        def convert(obj):
            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [convert(x) for x in obj]
            elif hasattr(obj, 'item') and callable(getattr(obj, 'item')):
                return obj.item()
            elif hasattr(obj, 'tolist') and callable(getattr(obj, 'tolist')):
                return obj.tolist()
            else:
                return obj
        
        model_data = {
            'feature_stats': convert(self.feature_stats),
            'trained': self.trained
        }
        
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'w') as f:
            json.dump(model_data, f, indent=2)
    
    @classmethod
    def load(cls, filepath: str) -> 'StatisticalModel':
        """
        Load a model from a file.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded model instance
        """
        with open(filepath, 'r') as f:
            model_data = json.load(f)
        
        model = cls()
        model.feature_stats = model_data['feature_stats']
        model.trained = model_data['trained']
        
        return model
