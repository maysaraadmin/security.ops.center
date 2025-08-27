"""
Base classes for behavior models.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List
import pickle

class BehaviorModel(ABC):
    """Abstract base class for behavior models."""
    
    @abstractmethod
    def train(self, data: List[Dict[str, Any]]) -> 'BehaviorModel':
        """
        Train the model on the given data.
        
        Args:
            data: List of training samples
            
        Returns:
            The trained model (self)
        """
        pass
    
    @abstractmethod
    def score(self, features: Dict[str, Any]) -> float:
        """
        Score the given features for anomaly detection.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Anomaly score (higher means more anomalous)
        """
        pass
    
    @abstractmethod
    def save(self, filepath: str) -> None:
        """
        Save the model to a file.
        
        Args:
            filepath: Path to save the model to
        """
        pass
    
    @classmethod
    @abstractmethod
    def load(cls, filepath: str) -> 'BehaviorModel':
        """
        Load a model from a file.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded model instance
        """
        pass
