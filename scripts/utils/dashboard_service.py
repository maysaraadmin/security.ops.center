import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
import logging
import psutil
import platform
from collections import deque
from src.models.metrics import DashboardMetrics
from src.models.security_models import Severity

logger = logging.getLogger(__name__)

class DashboardService:
    def __init__(self, root, data_collector, update_interval=5000):
        self.root = root
        self.data_collector = data_collector
        self.update_interval = update_interval
        self.metrics_history = deque(maxlen=100)  # Store last 100 metrics
        self.callbacks = []
        self._update_job = None
        
    def start(self):
        """Start the dashboard service."""
        self._schedule_update()
        
    def stop(self):
        """Stop the dashboard service."""
        if self._update_job is not None:
            self.root.after_cancel(self._update_job)
            self._update_job = None
    
    def register_callback(self, callback: Callable[[DashboardMetrics], None]):
        """Register a callback to be called when metrics are updated."""
        self.callbacks.append(callback)
    
    def _schedule_update(self):
        """Schedule the next metrics update."""
        self._update_metrics()
        self._update_job = self.root.after(self.update_interval, self._schedule_update)
    
    def _update_metrics(self):
        """Update metrics and notify callbacks."""
        try:
            # Collect new metrics
            metrics = self.data_collector.collect_all_metrics()
            self.metrics_history.append(metrics)
            
            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(metrics)
                except Exception as e:
                    logger.error(f"Error in dashboard callback: {e}")
                    
        except Exception as e:
            logger.error(f"Error updating dashboard metrics: {e}")
    
    def get_latest_metrics(self) -> DashboardMetrics:
        """Get the latest metrics."""
        if self.metrics_history:
            return self.metrics_history[-1]
        return self.data_collector.collect_all_metrics()
    
    def get_metric_history(self, metric_path: str, max_points: int = 60) -> List[Dict[str, Any]]:
        """Get historical data for a specific metric."""
        history = []
        for metrics in list(self.metrics_history)[-max_points:]:
            try:
                # Navigate the metric path (e.g., 'siem_metrics.cpu_percent')
                value = metrics
                for part in metric_path.split('.'):
                    value = getattr(value, part, {})
                
                history.append({
                    'timestamp': metrics.timestamp,
                    'value': value
                })
            except (AttributeError, KeyError):
                continue
        
        return history


class DashboardWidget(ttk.Frame):
    """Base class for dashboard widgets."""
    def __init__(self, parent, dashboard_service: DashboardService, **kwargs):
        super().__init__(parent, **kwargs)
        self.dashboard_service = dashboard_service
        self.dashboard_service.register_callback(self.on_metrics_updated)
        self.metrics = self.dashboard_service.get_latest_metrics()
        
    def on_metrics_updated(self, metrics: DashboardMetrics):
        """Called when metrics are updated."""
        self.metrics = metrics
        self.update_display()
    
    def update_display(self):
        """Update the widget's display with the latest metrics."""
        raise NotImplementedError("Subclasses must implement update_display()")


class SystemMetricsWidget(DashboardWidget):
    """Widget for displaying system metrics."""
    def __init__(self, parent, dashboard_service: DashboardService, **kwargs):
        super().__init__(parent, dashboard_service, **kwargs)
        self.columnconfigure(0, weight=1)
        
        # Create metrics displays
        self.cpu_label = ttk.Label(self, text="CPU: --%", font=('Arial', 10))
        self.cpu_label.grid(row=0, column=0, sticky='w', padx=5, pady=2)
        
        self.mem_label = ttk.Label(self, text="Memory: --%", font=('Arial', 10))
        self.mem_label.grid(row=1, column=0, sticky='w', padx=5, pady=2)
        
        self.disk_label = ttk.Label(self, text="Disk: --%", font=('Arial', 10))
        self.disk_label.grid(row=2, column=0, sticky='w', padx=5, pady=2)
        
        self.process_label = ttk.Label(self, text="Processes: --", font=('Arial', 10))
        self.process_label.grid(row=3, column=0, sticky='w', padx=5, pady=2)
        
        # Initial update
        self.update_display()
    
    def update_display(self):
        """Update the display with the latest metrics."""
        try:
            metrics = self.metrics.siem_metrics
            self.cpu_label.config(text=f"CPU: {metrics.get('cpu_percent', 0):.1f}%")
            self.mem_label.config(text=f"Memory: {metrics.get('memory_percent', 0):.1f}%")
            self.disk_label.config(text=f"Disk: {metrics.get('disk_percent', 0):.1f}%")
            self.process_label.config(text=f"Processes: {metrics.get('process_count', 0)}")
        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")


class SecurityAlertsWidget(DashboardWidget):
    """Widget for displaying security alerts."""
    def __init__(self, parent, dashboard_service: DashboardService, **kwargs):
        super().__init__(parent, dashboard_service, **kwargs)
        
        # Create treeview for alerts
        self.tree = ttk.Treeview(self, columns=('time', 'source', 'severity', 'message'), show='headings')
        self.tree.heading('time', text='Time')
        self.tree.heading('source', text='Source')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('message', text='Message')
        
        # Configure column widths
        self.tree.column('time', width=120)
        self.tree.column('source', width=100)
        self.tree.column('severity', width=80)
        self.tree.column('message', width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky='nsew')
        scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Configure grid weights
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Initial update
        self.update_display()
    
    def update_display(self):
        """Update the display with the latest alerts."""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Add sample alerts (in a real app, these would come from the metrics)
            sample_alerts = [
                (datetime.now().strftime('%H:%M:%S'), 'EDR', 'High', 'Suspicious process detected: malware.exe'),
                (datetime.now().strftime('%H:%M:%S'), 'NIPS', 'Critical', 'Blocked port scan from 192.168.1.100'),
                (datetime.now().strftime('%H:%M:%S'), 'DLP', 'Medium', 'Potential data leak detected')
            ]
            
            for alert in sample_alerts:
                self.tree.insert('', 'end', values=alert)
                
        except Exception as e:
            logger.error(f"Error updating security alerts: {e}")
