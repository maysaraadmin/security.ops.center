"""
SIEM Component Manager

This module manages the SIEM components and their status.
"""
from typing import Dict, Any, List, Optional
from pathlib import Path
import importlib
import threading
import time
from dataclasses import dataclass, asdict
import json

@dataclass
class ComponentStatus:
    """Represents the status of a SIEM component."""
    name: str
    status: str  # 'running', 'stopped', 'error'
    uptime: float = 0.0
    metrics: Dict[str, Any] = None
    last_error: Optional[str] = None
    
    def to_dict(self):
        """Convert the status to a dictionary."""
        return asdict(self)

class SIEMComponent:
    """Base class for SIEM components."""
    
    def __init__(self, name: str):
        self.name = name
        self.status = ComponentStatus(name=name, status='stopped', metrics={})
        self._thread = None
        self._stop_event = threading.Event()
        
    def start(self):
        """Start the component."""
        if self._thread and self._thread.is_alive():
            return False
            
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self.status.status = 'starting'
        return True
        
    def stop(self):
        """Stop the component."""
        if not self._thread or not self._thread.is_alive():
            return False
            
        self._stop_event.set()
        self._thread.join(timeout=5.0)
        self.status.status = 'stopped'
        return True
        
    def _run(self):
        """Main component loop. Override this in subclasses."""
        self.status.status = 'running'
        start_time = time.time()
        
        try:
            while not self._stop_event.is_set():
                self.status.uptime = time.time() - start_time
                # Update metrics here
                time.sleep(1)
        except Exception as e:
            self.status.status = 'error'
            self.status.last_error = str(e)
        finally:
            self.status.status = 'stopped'

class SIEMManager:
    """Manages all SIEM components."""
    
    def __init__(self):
        self.components: Dict[str, SIEMComponent] = {}
        self._status_callbacks = []
        self._update_thread = None
        self._stop_event = threading.Event()
        
    def register_component(self, component: SIEMComponent):
        """Register a new component."""
        self.components[component.name] = component
        
    def get_status(self) -> Dict[str, Any]:
        """Get the status of all components."""
        return {
            'status': 'running' if any(c.status.status == 'running' for c in self.components.values()) else 'stopped',
            'components': {
                name: {
                    'status': comp.status.status,
                    'uptime': comp.status.uptime,
                    **comp.status.metrics
                }
                for name, comp in self.components.items()
            },
            'stats': {
                'events_processed': sum(
                    comp.status.metrics.get('events_processed', 0)
                    for comp in self.components.values()
                ),
                'alerts_triggered': sum(
                    comp.status.metrics.get('alerts_triggered', 0)
                    for comp in self.components.values()
                ),
                'uptime': max(
                    (comp.status.uptime for comp in self.components.values()),
                    default=0
                )
            }
        }
        
    def start_all(self):
        """Start all components."""
        for component in self.components.values():
            component.start()
            
    def stop_all(self):
        """Stop all components."""
        for component in self.components.values():
            component.stop()
            
    def register_status_callback(self, callback):
        """Register a callback to be called when status updates are available."""
        self._status_callbacks.append(callback)
        
    def start_status_updates(self, interval: float = 1.0):
        """Start sending status updates to registered callbacks."""
        if self._update_thread and self._update_thread.is_alive():
            return
            
        self._stop_event.clear()
        self._update_thread = threading.Thread(
            target=self._update_loop,
            args=(interval,),
            daemon=True
        )
        self._update_thread.start()
        
    def stop_status_updates(self):
        """Stop sending status updates."""
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=2.0)
            
    def _update_loop(self, interval: float):
        """Background thread for sending status updates."""
        while not self._stop_event.is_set():
            status = self.get_status()
            for callback in self._status_callbacks:
                try:
                    callback(status)
                except Exception as e:
                    print(f"Error in status callback: {e}")
            time.sleep(interval)

# Global instance
siem_manager = SIEMManager()

def init_components():
    """Initialize all SIEM components."""
    # Import and register all enabled plugins
    from src.siem.config import load_config
    
    try:
        config = load_config()
        
        for plugin_name in config.plugins:
            try:
                # Try to import the plugin
                module = importlib.import_module(f"src.siem.plugins.{plugin_name}")
                
                # Look for a component class (e.g., SysmonComponent, FirewallComponent)
                component_class = getattr(module, f"{plugin_name.capitalize()}Component", None)
                if component_class and issubclass(component_class, SIEMComponent):
                    siem_manager.register_component(component_class(plugin_name))
                    print(f"Registered component: {plugin_name}")
                else:
                    print(f"No component class found for plugin: {plugin_name}")
                    
            except ImportError as e:
                print(f"Failed to load plugin {plugin_name}: {e}")
                
    except Exception as e:
        print(f"Error initializing components: {e}")

# Initialize components when this module is imported
init_components()
