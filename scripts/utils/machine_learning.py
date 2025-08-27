"""
Machine learning models for behavior analysis.
"""
import numpy as np
from typing import Dict, Any, List, Optional
import pickle
import os

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from .base import BehaviorModel

class IsolationForestModel(BehaviorModel):
    """
    Isolation Forest model for anomaly detection.
    
    This model is effective for detecting anomalies in high-dimensional data
    and is particularly good at handling outliers.
    """
    
    def __init__(self, n_estimators: int = 100, 
                 contamination: float = 0.1,
                 random_state: Optional[int] = 42):
        """
        Initialize the Isolation Forest model.
        
        Args:
            n_estimators: Number of base estimators in the ensemble
            contamination: Expected proportion of outliers in the data
            random_state: Random seed for reproducibility
        """
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.trained = False
    
    def train(self, data: List[Dict[str, Any]]) -> 'IsolationForestModel':
        """
        Train the Isolation Forest model.
        
        Args:
            data: List of training samples (dictionaries of features)
            
        Returns:
            The trained model (self)
        """
        if not data:
            return self
            
        # Convert to feature matrix
        self.feature_names = sorted(list(set().union(*(d.keys() for d in data))))
        X = self._convert_to_feature_matrix(data)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X_scaled)
        self.trained = True
        
        return self
    
    def score(self, features: Dict[str, Any]) -> float:
        """
        Calculate an anomaly score for the given features.
        
        The score is based on the decision function of the Isolation Forest.
        Higher values indicate more normal behavior.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Anomaly score (higher means more normal, lower means more anomalous)
        """
        if not self.trained or not self.model:
            return 0.0
            
        # Convert to feature vector
        X = self._convert_to_feature_matrix([features])
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (higher is more normal, lower is more anomalous)
        # We invert the sign to match the convention that higher = more anomalous
        score = -self.model.decision_function(X_scaled)[0]
        
        # Normalize to [0, 1] range
        return (score + 1) / 2
    
    def _convert_to_feature_matrix(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dictionaries to a numpy array."""
        if not self.feature_names:
            self.feature_names = sorted(list(set().union(*(d.keys() for d in data))))
            
        X = np.zeros((len(data), len(self.feature_names)))
        
        for i, sample in enumerate(data):
            for j, feature in enumerate(self.feature_names):
                X[i, j] = sample.get(feature, 0.0)
                
        return X
    
    def save(self, filepath: str) -> None:
        """
        Save the model to a file.
        
        Args:
            filepath: Path to save the model to
        """
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'trained': self.trained,
                'n_estimators': self.n_estimators,
                'contamination': self.contamination,
                'random_state': self.random_state
            }, f)
    
    @classmethod
    def load(cls, filepath: str) -> 'IsolationForestModel':
        """
        Load a model from a file.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded model instance
        """
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        model = cls(
            n_estimators=data['n_estimators'],
            contamination=data['contamination'],
            random_state=data['random_state']
        )
        
        model.model = data['model']
        model.scaler = data['scaler']
        model.feature_names = data['feature_names']
        model.trained = data['trained']
        
        return model


class OneClassSVMModel(BehaviorModel):
    """
    One-Class SVM model for anomaly detection.
    
    This model is effective for detecting anomalies when the training data
    contains mostly normal examples.
    """
    
    def __init__(self, nu: float = 0.1, 
                 kernel: str = 'rbf',
                 gamma: str = 'scale'):
        """
        Initialize the One-Class SVM model.
        
        Args:
            nu: An upper bound on the fraction of training errors and a lower
                bound of the fraction of support vectors
            kernel: Kernel type ('rbf', 'linear', 'poly', etc.)
            gamma: Kernel coefficient for 'rbf', 'poly' and 'sigmoid'
        """
        self.nu = nu
        self.kernel = kernel
        self.gamma = gamma
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = None
        self.trained = False
    
    def train(self, data: List[Dict[str, Any]]) -> 'OneClassSVMModel':
        """
        Train the One-Class SVM model.
        
        Args:
            data: List of training samples (dictionaries of features)
            
        Returns:
            The trained model (self)
        """
        if not data:
            return self
            
        # Convert to feature matrix
        self.feature_names = sorted(list(set().union(*(d.keys() for d in data))))
        X = self._convert_to_feature_matrix(data)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model
        self.model = OneClassSVM(
            nu=self.nu,
            kernel=self.kernel,
            gamma=self.gamma
        )
        self.model.fit(X_scaled)
        self.trained = True
        
        return self
    
    def score(self, features: Dict[str, Any]) -> float:
        """
        Calculate an anomaly score for the given features.
        
        The score is based on the decision function of the One-Class SVM.
        Higher values indicate more normal behavior.
        
        Args:
            features: Dictionary of feature names to values
            
        Returns:
            Anomaly score (higher means more normal, lower means more anomalous)
        """
        if not self.trained or not self.model:
            return 0.0
            
        # Convert to feature vector
        X = self._convert_to_feature_matrix([features])
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly score (higher is more normal, lower is more anomalous)
        # We invert the sign to match the convention that higher = more anomalous
        score = -self.model.decision_function(X_scaled)[0]
        
        # Normalize to [0, 1] range
        return (score + 1) / 2
    
    def _convert_to_feature_matrix(self, data: List[Dict[str, Any]]) -> np.ndarray:
        """Convert a list of feature dictionaries to a numpy array."""
        if not self.feature_names:
            self.feature_names = sorted(list(set().union(*(d.keys() for d in data))))
            
        X = np.zeros((len(data), len(self.feature_names)))
        
        for i, sample in enumerate(data):
            for j, feature in enumerate(self.feature_names):
                X[i, j] = sample.get(feature, 0.0)
                
        return X
    
    def save(self, filepath: str) -> None:
        """
        Save the model to a file.
        
        Args:
            filepath: Path to save the model to
        """
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'trained': self.trained,
                'nu': self.nu,
                'kernel': self.kernel,
                'gamma': self.gamma
            }, f)
    
    @classmethod
    def load(cls, filepath: str) -> 'OneClassSVMModel':
        """
        Load a model from a file.
        
        Args:
            filepath: Path to the saved model
            
        Returns:
            Loaded model instance
        """
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        model = cls(
            nu=data['nu'],
            kernel=data['kernel'],
            gamma=data['gamma']
        )
        
        model.model = data['model']
        model.scaler = data['scaler']
        model.feature_names = data['feature_names']
        model.trained = data['trained']
        
        return model
