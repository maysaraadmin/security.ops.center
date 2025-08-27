"""
Base analyzer class for user and entity behavior analysis.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import os
import pickle

from ..models.base import BehaviorModel

class BaseAnalyzer(ABC):
    """
    Abstract base class for behavior analyzers.
    
    Each analyzer is responsible for a specific type of behavior analysis,
    such as login patterns, resource access, etc.
    """
    
    def __init__(self, model_type: str = 'statistical'):
        """
        Initialize the analyzer.
        
        Args:
            model_type: Type of model to use ('statistical', 'isolation_forest', 'one_class_svm')
        """
        self.model_type = model_type
        self.model: Optional[BehaviorModel] = None
        self._init_model()
    
    def _init_model(self) -> None:
        """Initialize the behavior model based on the specified type."""
        if self.model_type == 'statistical':
            from ..models.statistical import StatisticalModel
            self.model = StatisticalModel()
        elif self.model_type == 'isolation_forest':
            from ..models.machine_learning import IsolationForestModel
            self.model = IsolationForestModel()
        elif self.model_type == 'one_class_svm':
            from ..models.machine_learning import OneClassSVMModel
            self.model = OneClassSVMModel()
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    @abstractmethod
    def extract_features(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract relevant features from an event for this analyzer.
        
        Args:
            event_data: Raw event data
            
        Returns:
            Dictionary of feature names to values
        """
        pass
    
    @abstractmethod
    def describe_anomaly(self, features: Dict[str, Any], score: float) -> str:
        """
        Generate a human-readable description of an anomaly.
        
        Args:
            features: The features that triggered the anomaly
            score: The anomaly score
            
        Returns:
            Human-readable description of the anomaly
        """
        pass
    
    def train(self, data: List[Dict[str, Any]]) -> 'BaseAnalyzer':
        """
        Train the analyzer's model on the given data.
        
        Args:
            data: List of training samples (dictionaries of features)
            
        Returns:
            The trained analyzer (self)
        """
        if self.model:
            self.model.train(data)
        return self
    
    def score(self, features: Dict[str, Any]) -> float:
        """
        Calculate an anomaly score for the given features.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Anomaly score (higher means more anomalous)
        """
        if not self.model:
            return 0.0
        return self.model.score(features)
    
    def save_model(self, filepath: str) -> None:
        """
        Save the analyzer's model to a file.
        
        Args:
            filepath: Path to save the model to
        """
        if self.model:
            self.model.save(filepath)
    
    def load_model(self, filepath: str) -> 'BaseAnalyzer':
        """
        Load a model from a file.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            The analyzer with the loaded model (self)
        """
        if not os.path.exists(filepath):
            return self
            
        if self.model_type == 'statistical':
            from ..models.statistical import StatisticalModel
            self.model = StatisticalModel.load(filepath)
        elif self.model_type == 'isolation_forest':
            from ..models.machine_learning import IsolationForestModel
            self.model = IsolationForestModel.load(filepath)
        elif self.model_type == 'one_class_svm':
            from ..models.machine_learning import OneClassSVMModel
            self.model = OneClassSVMModel.load(filepath)
            
        return self
