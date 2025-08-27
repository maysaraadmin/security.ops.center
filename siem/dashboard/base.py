"""
Base classes for SIEM dashboards and visualizations.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import json
import logging
from pathlib import Path

# Third-party imports (will be used in implementations)
try:
    import dash
    from dash import dcc, html, Input, Output, State, callback_context
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    pass

class DashboardComponent(ABC):
    """Base class for all dashboard components."""
    
    def __init__(self, component_id: str, title: str = None, config: Dict = None):
        """Initialize the dashboard component.
        
        Args:
            component_id: Unique identifier for the component
            title: Display title for the component
            config: Configuration dictionary
        """
        self.component_id = component_id
        self.title = title or component_id.replace('_', ' ').title()
        self.config = config or {}
        self.logger = logging.getLogger(f"siem.dashboard.{component_id}")
    
    @abstractmethod
    def layout(self) -> 'dash.html.Div':
        """Return the Dash layout for this component."""
        pass
    
    @abstractmethod
    def register_callbacks(self, app):
        """Register any necessary Dash callbacks for this component."""
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the component to a dictionary for serialization."""
        return {
            'component_id': self.component_id,
            'title': self.title,
            'type': self.__class__.__name__,
            'config': self.config
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DashboardComponent':
        """Create a component from a dictionary."""
        return cls(
            component_id=data['component_id'],
            title=data.get('title'),
            config=data.get('config', {})
        )


class Dashboard:
    """A collection of dashboard components."""
    
    def __init__(self, dashboard_id: str, title: str = None, layout: str = 'grid'):
        """Initialize the dashboard.
        
        Args:
            dashboard_id: Unique identifier for the dashboard
            title: Dashboard title
            layout: Layout type ('grid', 'tabs', 'rows')
        """
        self.dashboard_id = dashboard_id
        self.title = title or dashboard_id.replace('_', ' ').title()
        self.layout_type = layout
        self.components: Dict[str, DashboardComponent] = {}
        self.logger = logging.getLogger(f"siem.dashboard.{dashboard_id}")
    
    def add_component(self, component: DashboardComponent) -> None:
        """Add a component to the dashboard."""
        if component.component_id in self.components:
            raise ValueError(f"Component with ID '{component.component_id}' already exists")
        self.components[component.component_id] = component
    
    def remove_component(self, component_id: str) -> bool:
        """Remove a component from the dashboard."""
        if component_id in self.components:
            del self.components[component_id]
            return True
        return False
    
    def get_layout(self) -> 'dash.html.Div':
        """Generate the Dash layout for the dashboard."""
        if not DASH_AVAILABLE:
            return html.Div([
                html.H1("Dashboard Error"),
                html.P("Required dependencies (dash, plotly, pandas) are not installed.")
            ])
        
        # Header
        header = html.Header([
            html.H1(self.title, className="dashboard-title"),
            dcc.Interval(
                id='dashboard-refresh-interval',
                interval=60 * 1000,  # 1 minute
                n_intervals=0
            )
        ], className="dashboard-header")
        
        # Components
        if self.layout_type == 'grid':
            # Simple grid layout (2 columns)
            rows = []
            current_row = []
            
            for i, (comp_id, component) in enumerate(self.components.items()):
                current_row.append(
                    html.Div(
                        component.layout(),
                        className="dashboard-grid-item",
                        style={'width': '48%', 'display': 'inline-block', 'margin': '1%'}
                    )
                )
                
                if len(current_row) >= 2 or i == len(self.components) - 1:
                    rows.append(html.Div(current_row, className="dashboard-row"))
                    current_row = []
            
            content = html.Div(rows, className="dashboard-grid")
            
        elif self.layout_type == 'tabs':
            # Tabbed layout
            tabs = []
            tab_contents = []
            
            for i, (comp_id, component) in enumerate(self.components.items()):
                tab_id = f"tab-{comp_id}"
                tabs.append(dcc.Tab(label=component.title, value=tab_id))
                tab_contents.append(
                    html.Div(
                        component.layout(),
                        id=tab_id,
                        className="tab-content"
                    )
                )
            
            content = html.Div([
                dcc.Tabs(
                    id="dashboard-tabs",
                    value=tabs[0].value if tabs else None,
                    children=tabs
                ),
                html.Div(tab_contents)
            ])
            
        else:  # rows
            # Simple vertical stack
            content = html.Div([
                component.layout()
                for component in self.components.values()
            ], className="dashboard-rows")
        
        # Combine everything
        return html.Div([
            header,
            content,
            dcc.Store(id='dashboard-state')
        ], className="dashboard-container")
    
    def register_callbacks(self, app):
        """Register all callbacks for the dashboard and its components."""
        for component in self.components.values():
            try:
                component.register_callbacks(app)
                self.logger.debug(f"Registered callbacks for component: {component.component_id}")
            except Exception as e:
                self.logger.error(f"Error registering callbacks for {component.component_id}: {e}")
    
    def save_layout(self, directory: Union[str, Path] = None) -> str:
        """Save the dashboard layout to a file."""
        if directory is None:
            directory = Path("dashboards")
        else:
            directory = Path(directory)
        
        dashboard_dir = directory / self.dashboard_id
        dashboard_dir.mkdir(parents=True, exist_ok=True)
        
        # Save dashboard metadata
        dashboard_meta = {
            'dashboard_id': self.dashboard_id,
            'title': self.title,
            'layout_type': self.layout_type,
            'components': [
                component.to_dict()
                for component in self.components.values()
            ]
        }
        
        with open(dashboard_dir / 'dashboard.json', 'w') as f:
            json.dump(dashboard_meta, f, indent=2)
        
        return str(dashboard_dir)
    
    @classmethod
    def load_layout(cls, directory: Union[str, Path]):
        """Load a dashboard from a directory."""
        directory = Path(directory)
        
        with open(directory / 'dashboard.json') as f:
            data = json.load(f)
        
        # Create dashboard instance
        dashboard = cls(
            dashboard_id=data['dashboard_id'],
            title=data.get('title'),
            layout=data.get('layout_type', 'grid')
        )
        
        # Load components
        component_classes = {
            'ThreatTimeline': ThreatTimeline,
            'AlertHeatmap': AlertHeatmap,
            'TopAlertsTable': TopAlertsTable,
            'UserActivityGauge': UserActivityGauge,
            'NetworkTrafficMap': NetworkTrafficMap,
            'ComplianceStatus': ComplianceStatus,
            'IncidentTrends': IncidentTrends,
            'ThreatIntelFeed': ThreatIntelFeed,
            'SystemHealth': SystemHealth,
            'CustomQueryViewer': CustomQueryViewer
        }
        
        for comp_data in data.get('components', []):
            comp_type = comp_data.get('type')
            if comp_type in component_classes:
                try:
                    component = component_classes[comp_type].from_dict(comp_data)
                    dashboard.add_component(component)
                except Exception as e:
                    logging.error(f"Error loading component {comp_data.get('component_id')}: {e}")
        
        return dashboard


# Import component implementations here to avoid circular imports
from .components import (
    ThreatTimeline, AlertHeatmap, TopAlertsTable, UserActivityGauge,
    NetworkTrafficMap, ComplianceStatus, IncidentTrends, ThreatIntelFeed,
    SystemHealth, CustomQueryViewer
)
