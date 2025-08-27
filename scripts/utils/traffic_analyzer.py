"""
Traffic Analyzer Module

This module provides analysis capabilities for network traffic, including
behavioral analysis, anomaly detection, and traffic pattern recognition.
"""

import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import statistics
import ipaddress
import json
from collections import defaultdict, deque

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .network_monitor import NetworkFlow, Protocol

logger = logging.getLogger('ndr.traffic_analyzer')

@dataclass
class TrafficStats:
    """Statistics for network traffic analysis."""
    # Basic statistics
    total_packets: int = 0
    total_bytes: int = 0
    avg_packet_size: float = 0.0
    packet_size_std: float = 0.0
    
    # Protocol distribution
    protocol_dist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Port statistics
    src_port_dist: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    dst_port_dist: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    # IP statistics
    src_ip_dist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    dst_ip_dist: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    # Timestamps for rate calculations
    timestamps: List[datetime] = field(default_factory=list)
    
    # Rate calculations
    packet_rate: float = 0.0  # packets per second
    byte_rate: float = 0.0    # bytes per second
    
    # Anomaly scores
    anomaly_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to a dictionary."""
        return {
            'total_packets': self.total_packets,
            'total_bytes': self.total_bytes,
            'avg_packet_size': self.avg_packet_size,
            'packet_size_std': self.packet_size_std,
            'protocol_dist': dict(self.protocol_dist),
            'src_port_dist': dict(self.src_port_dist),
            'dst_port_dist': dict(self.dst_port_dist),
            'src_ip_dist': dict(self.src_ip_dist),
            'dst_ip_dist': dict(self.dst_ip_dist),
            'packet_rate': self.packet_rate,
            'byte_rate': self.byte_rate,
            'anomaly_score': self.anomaly_score
        }

class TrafficAnalyzer:
    """Analyzes network traffic patterns and detects anomalies."""
    
    def __init__(self, window_size: int = 60, sensitivity: float = 0.9):
        """Initialize the traffic analyzer.
        
        Args:
            window_size: Time window in seconds for traffic analysis
            sensitivity: Sensitivity for anomaly detection (0.0 to 1.0)
        """
        self.window_size = window_size
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        
        # Traffic statistics
        self.window_stats: Dict[str, TrafficStats] = {}
        self.current_window = self._new_window()
        
        # Anomaly detection
        self.anomaly_detector = AnomalyDetector(sensitivity=self.sensitivity)
        
        # Historical data for trend analysis
        self.history: deque[Dict[str, Any]] = deque(maxlen=1000)
        
        # Callbacks for detected anomalies
        self.anomaly_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
        # Background task for window management
        self._task: Optional[asyncio.Task] = None
        self._running = False
    
    def _new_window(self) -> TrafficStats:
        """Create a new statistics window."""
        return TrafficStats()
    
    async def start(self) -> None:
        """Start the traffic analyzer."""
        if self._running:
            logger.warning("Traffic analyzer is already running")
            return
            
        self._running = True
        self._task = asyncio.create_task(self._window_manager())
        logger.info("Traffic analyzer started")
    
    async def stop(self) -> None:
        """Stop the traffic analyzer."""
        if not self._running:
            return
            
        self._running = False
        
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        logger.info("Traffic analyzer stopped")
    
    async def _window_manager(self) -> None:
        """Manage time-based analysis windows."""
        while self._running:
            try:
                # Rotate the current window
                now = datetime.utcnow()
                window_key = now.strftime("%Y%m%d%H%M")
                
                if window_key not in self.window_stats:
                    # Finalize the current window
                    if self.current_window.timestamps:
                        self._finalize_window()
                        
                        # Store the window
                        self.window_stats[window_key] = self.current_window
                        
                        # Keep only the last 60 windows (1 hour with 1-minute windows)
                        if len(self.window_stats) > 60:
                            oldest = min(self.window_stats.keys())
                            del self.window_stats[oldest]
                    
                    # Start a new window
                    self.current_window = self._new_window()
                
                # Sleep until the next minute
                next_minute = (now + timedelta(minutes=1)).replace(second=0, microsecond=0)
                await asyncio.sleep((next_minute - now).total_seconds())
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in window manager: {e}", exc_info=True)
                await asyncio.sleep(1)
    
    def _finalize_window(self) -> None:
        """Finalize the current window's statistics."""
        window = self.current_window
        
        # Calculate packet size statistics
        if window.total_packets > 0:
            window.avg_packet_size = window.total_bytes / window.total_packets
            
            # In a real implementation, we would track individual packet sizes for std dev
            # For now, we'll use a placeholder
            window.packet_size_std = window.avg_packet_size * 0.5
        
        # Calculate rates
        if window.timestamps:
            time_span = (max(window.timestamps) - min(window.timestamps)).total_seconds()
            if time_span > 0:
                window.packet_rate = window.total_packets / time_span
                window.byte_rate = window.total_bytes / time_span
        
        # Calculate anomaly score
        features = self._extract_features(window)
        window.anomaly_score = self.anomaly_detector.detect(features)
        
        # Store in history
        self.history.append({
            'timestamp': datetime.utcnow().isoformat(),
            'stats': window.to_dict(),
            'features': features
        })
        
        # Trigger anomaly callbacks if needed
        if window.anomaly_score > 0.7:  # Threshold for anomaly
            self._notify_anomaly(window)
    
    def _extract_features(self, stats: TrafficStats) -> List[float]:
        """Extract feature vector for anomaly detection."""
        # Basic features
        features = [
            stats.total_packets,
            stats.total_bytes,
            stats.avg_packet_size,
            stats.packet_size_std,
            stats.packet_rate,
            stats.byte_rate,
            
            # Port distribution entropy
            self._calculate_entropy(stats.src_port_dist.values()),
            self._calculate_entropy(stats.dst_port_dist.values()),
            
            # IP distribution entropy
            self._calculate_entropy(stats.src_ip_dist.values()),
            self._calculate_entropy(stats.dst_ip_dist.values()),
            
            # Protocol distribution
            stats.protocol_dist.get('tcp', 0),
            stats.protocol_dist.get('udp', 0),
            stats.protocol_dist.get('icmp', 0),
        ]
        
        return features
    
    @staticmethod
    def _calculate_entropy(counts) -> float:
        """Calculate the entropy of a distribution."""
        total = sum(counts) or 1.0
        probs = [c / total for c in counts if c > 0]
        return -sum(p * np.log2(p) for p in probs) if probs else 0.0
    
    def _notify_anomaly(self, stats: TrafficStats) -> None:
        """Notify registered callbacks about a detected anomaly."""
        anomaly_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'anomaly_score': stats.anomaly_score,
            'stats': stats.to_dict(),
            'top_src_ips': sorted(
                stats.src_ip_dist.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'top_dst_ips': sorted(
                stats.dst_ip_dist.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
            'top_ports': sorted(
                stats.dst_port_dist.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:10],
        }
        
        for callback in self.anomaly_callbacks:
            try:
                callback(anomaly_info)
            except Exception as e:
                logger.error(f"Error in anomaly callback: {e}", exc_info=True)
    
    def add_anomaly_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add a callback function for anomaly notifications."""
        self.anomaly_callbacks.append(callback)
    
    def remove_anomaly_callback(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """Remove an anomaly callback function."""
        try:
            self.anomaly_callbacks.remove(callback)
            return True
        except ValueError:
            return False
    
    def process_flow(self, flow: NetworkFlow) -> None:
        """Process a network flow and update statistics."""
        window = self.current_window
        
        # Update basic statistics
        window.total_packets += flow.packets_sent + flow.packets_received
        window.total_bytes += flow.bytes_sent + flow.bytes_received
        
        # Update protocol distribution
        proto_name = flow.protocol.name.lower()
        window.protocol_dist[proto_name] += 1
        
        # Update port distributions
        window.src_port_dist[flow.src_port] += 1
        window.dst_port_dist[flow.dst_port] += 1
        
        # Update IP distributions
        window.src_ip_dist[flow.src_ip] += 1
        window.dst_ip_dist[flow.dst_ip] += 1
        
        # Add timestamp for rate calculations
        window.timestamps.append(datetime.utcnow())
        
        # Check for anomalies in real-time
        if len(window.timestamps) % 100 == 0:  # Check every 100 packets
            features = self._extract_features(window)
            anomaly_score = self.anomaly_detector.detect(features)
            
            if anomaly_score > 0.8:  # Higher threshold for real-time detection
                window.anomaly_score = anomaly_score
                self._notify_anomaly(window)
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current traffic statistics."""
        return self.current_window.to_dict()
    
    def get_historical_stats(self, limit: int = 60) -> List[Dict[str, Any]]:
        """Get historical traffic statistics."""
        return [
            {
                'window': window,
                'stats': stats.to_dict()
            }
            for window, stats in list(self.window_stats.items())[-limit:]
        ]


class AnomalyDetector:
    """Detects anomalies in network traffic patterns using machine learning."""
    
    def __init__(self, sensitivity: float = 0.9):
        """Initialize the anomaly detector.
        
        Args:
            sensitivity: Detection sensitivity (0.0 to 1.0)
        """
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        self.model = IsolationForest(
            contamination=1 - sensitivity,  # Expected proportion of anomalies
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_count = 0
    
    def train(self, X: List[List[float]]) -> None:
        """Train the anomaly detection model.
        
        Args:
            X: List of feature vectors (list of lists)
        """
        if not X:
            return
            
        self.feature_count = len(X[0])
        
        # Scale the features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train the model
        self.model.fit(X_scaled)
        self.is_fitted = True
    
    def detect(self, x: List[float]) -> float:
        """Detect anomalies in a feature vector.
        
        Args:
            x: Feature vector
            
        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (highly anomalous)
        """
        if not self.is_fitted or not x:
            return 0.0
        
        # Ensure the input has the expected number of features
        if len(x) != self.feature_count and self.feature_count > 0:
            x = x[:self.feature_count]  # Truncate or pad if needed
            x = x + [0.0] * (self.feature_count - len(x))
        
        try:
            # Scale the features
            x_scaled = self.scaler.transform([x])
            
            # Predict anomaly score (1.0 = normal, -1.0 = anomaly)
            score = self.model.score_samples(x_scaled)[0]
            
            # Convert to 0.0 (normal) to 1.0 (anomaly)
            return max(0.0, min(1.0, (1.0 - score) / 2.0))
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}", exc_info=True)
            return 0.0
