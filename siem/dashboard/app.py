"""SIEM Dashboard Application.

This module provides a web-based dashboard for the SIEM system, allowing security teams to
visualize and analyze security events, alerts, and system health metrics.
"""
import os
import sys
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Try to import Dash and related dependencies
try:
    import dash
    from dash import dcc, html, Input, Output, State, callback_context, dash_table
    import dash_bootstrap_components as dbc
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    from flask import Flask, send_from_directory
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False

from .base import Dashboard
from .components import (
    ThreatTimeline, AlertHeatmap, TopAlertsTable, UserActivityGauge,
    NetworkTrafficMap, ComplianceStatus, IncidentTrends, ThreatIntelFeed,
    SystemHealth, CustomQueryViewer
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_dashboard.log')
    ]
)
logger = logging.getLogger("siem.dashboard")

class SIEMDashboard:
    """Main SIEM Dashboard application."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the SIEM Dashboard.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.app = self._create_app()
        self.dashboards: Dict[str, Dashboard] = {}
        self._setup_dashboards()
    
    def _create_app(self) -> dash.Dash:
        """Create and configure the Dash application."""
        if not DASH_AVAILABLE:
            return None
            
        # Initialize the Dash app with Bootstrap theme
        app = dash.Dash(
            __name__,
            external_stylesheets=[
                dbc.themes.DARKLY,
                'https://use.fontawesome.com/releases/v5.15.4/css/all.css'
            ],
            meta_tags=[
                {"name": "viewport", "content": "width=device-width, initial-scale=1"},
                {"name": "description", "content": "SIEM Security Dashboard"}
            ]
        )
        
        # Configure app
        app.title = "SIEM Security Dashboard"
        app.config.suppress_callback_exceptions = True
        
        # Add custom CSS
        app.index_string = '''
        <!DOCTYPE html>
        <html>
            <head>
                {%metas%}
                <title>{%title%}</title>
                {%favicon%}
                {%css%}
                <style>
                    /* Custom styles */
                    .dashboard-header {
                        padding: 1.5rem;
                        border-bottom: 1px solid #444;
                        margin-bottom: 1.5rem;
                    }
                    .dashboard-title {
                        margin: 0;
                        color: #00bc8c;
                    }
                    .card {
                        margin-bottom: 1.5rem;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
                        border: none;
                        border-radius: 8px;
                        overflow: hidden;
                    }
                    .card-header {
                        background-color: #2c3e50;
                        border-bottom: 1px solid #444;
                        padding: 0.75rem 1.25rem;
                    }
                    .card-title {
                        margin: 0;
                        font-size: 1.25rem;
                        font-weight: 500;
                    }
                    .card-body {
                        padding: 1.25rem;
                    }
                    .navbar {
                        background-color: #2c3e50 !important;
                        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                        padding: 0.75rem 1.5rem;
                    }
                    .navbar-brand {
                        font-size: 1.5rem;
                        font-weight: 600;
                        color: #00bc8c !important;
                    }
                    .nav-link {
                        color: #ecf0f1 !important;
                        margin: 0 0.5rem;
                        font-weight: 500;
                    }
                    .nav-link:hover, .nav-link.active {
                        color: #00bc8c !important;
                    }
                    .sidebar {
                        background-color: #2c3e50;
                        min-height: calc(100vh - 56px);
                        padding: 1.5rem 0;
                        box-shadow: 2px 0 5px rgba(0, 0, 0, 0.1);
                    }
                    .sidebar .nav-link {
                        color: #ecf0f1 !important;
                        padding: 0.5rem 1.5rem;
                        margin: 0.25rem 0;
                        border-left: 3px solid transparent;
                    }
                    .sidebar .nav-link:hover, .sidebar .nav-link.active {
                        background-color: rgba(255, 255, 255, 0.05);
                        border-left: 3px solid #00bc8c;
                        color: #00bc8c !important;
                    }
                    .sidebar .nav-link i {
                        margin-right: 0.5rem;
                        width: 20px;
                        text-align: center;
                    }
                    .content {
                        padding: 2rem;
                        background-color: #222;
                        min-height: calc(100vh - 56px);
                    }
                    .status-indicator {
                        display: inline-block;
                        width: 10px;
                        height: 10px;
                        border-radius: 50%;
                        margin-right: 5px;
                    }
                    .status-online {
                        background-color: #00bc8c;
                    }
                    .status-offline {
                        background-color: #e74c3c;
                    }
                    .status-warning {
                        background-color: #f39c12;
                    }
                </style>
            </head>
            <body>
                {%app_entry%}
                <footer>
                    {%config%}
                    {%scripts%}
                    {%renderer%}
                </footer>
            </body>
        </html>
        '''
        
        return app
    
    def _setup_dashboards(self) -> None:
        """Set up the default dashboards and components."""
        if not DASH_AVAILABLE:
            return
            
        # Create the main security dashboard
        security_dashboard = Dashboard(
            dashboard_id="security_overview",
            title="Security Overview",
            layout="grid"
        )
        
        # Add components to the security dashboard
        security_dashboard.add_component(ThreatTimeline("threat_timeline", "Threat Timeline"))
        security_dashboard.add_component(AlertHeatmap("alert_heatmap", "Alert Heatmap"))
        security_dashboard.add_component(TopAlertsTable("top_alerts", "Recent Alerts"))
        security_dashboard.add_component(UserActivityGauge("user_activity", "User Activity"))
        security_dashboard.add_component(NetworkTrafficMap("network_map", "Network Traffic"))
        security_dashboard.add_component(ComplianceStatus("compliance", "Compliance Status"))
        
        # Add the security dashboard
        self.add_dashboard(security_dashboard)
        
        # Create a separate dashboard for threat intelligence
        threat_intel_dashboard = Dashboard(
            dashboard_id="threat_intel",
            title="Threat Intelligence",
            layout="tabs"
        )
        
        # Add components to the threat intel dashboard
        threat_intel_dashboard.add_component(ThreatIntelFeed("threat_feed", "Threat Feed"))
        threat_intel_dashboard.add_component(IncidentTrends("incident_trends", "Incident Trends"))
        
        # Add the threat intel dashboard
        self.add_dashboard(threat_intel_dashboard)
        
        # Create a system health dashboard
        system_health_dashboard = Dashboard(
            dashboard_id="system_health",
            title="System Health",
            layout="rows"
        )
        
        # Add components to the system health dashboard
        system_health_dashboard.add_component(SystemHealth("system_metrics", "System Metrics"))
        system_health_dashboard.add_component(CustomQueryViewer("custom_queries", "Custom Queries"))
        
        # Add the system health dashboard
        self.add_dashboard(system_health_dashboard)
    
    def add_dashboard(self, dashboard: Dashboard) -> None:
        """Add a dashboard to the application."""
        if dashboard.dashboard_id in self.dashboards:
            raise ValueError(f"Dashboard with ID '{dashboard.dashboard_id}' already exists")
        
        self.dashboards[dashboard.dashboard_id] = dashboard
        logger.info(f"Added dashboard: {dashboard.title}")
    
    def _create_layout(self) -> Union[html.Div, str]:
        """Create the main application layout."""
        if not DASH_AVAILABLE:
            return html.Div([
                html.H1("SIEM Dashboard Error"),
                html.P("Required dependencies (dash, dash-bootstrap-components, plotly, pandas) are not installed.")
            ])
        
        # Navigation links
        nav_links = []
        for dashboard_id, dashboard in self.dashboards.items():
            nav_links.append(
                dbc.NavLink(
                    [
                        html.I(className="fas fa-tachometer-alt me-2"),
                        dashboard.title
                    ],
                    href=f"/{dashboard_id}",
                    id=f"nav-{dashboard_id}",
                    className="nav-link"
                )
            )
        
        # Sidebar with navigation
        sidebar = html.Div(
            [
                html.Div(
                    [
                        html.H4("SIEM Dashboard", className="display-6"),
                        html.Hr(),
                        dbc.Nav(
                            nav_links,
                            vertical=True,
                            pills=True,
                            className="mb-3"
                        ),
                        html.Hr(),
                        html.Div(
                            [
                                html.P("System Status", className="text-muted mb-1"),
                                html.Div([
                                    html.Span(className="status-indicator status-online"),
                                    html.Span("Operational", className="text-success")
                                ], className="mb-2"),
                                html.Div([
                                    html.Span(className="status-indicator status-warning"),
                                    html.Span("Monitoring: 12 active threats", className="text-warning")
                                ])
                            ],
                            className="mt-auto"
                        )
                    ],
                    className="sidebar"
                )
            ],
            className="col-md-3 col-lg-2 d-md-block bg-dark sidebar collapse"
        )
        
        # Main content area
        content = html.Div(
            id="page-content",
            className="col-md-9 ms-sm-auto col-lg-10 px-md-4"
        )
        
        # Main layout
        layout = html.Div([
            # Navigation bar
            dbc.Navbar(
                dbc.Container([
                    dbc.NavbarBrand("SIEM Dashboard", href="/", className="me-auto"),
                    dbc.Nav([
                        dbc.NavItem(dbc.NavLink("Alerts", href="#")),
                        dbc.NavItem(dbc.NavLink("Incidents", href="#")),
                        dbc.NavItem(dbc.NavLink("Reports", href="#")),
                        dbc.DropdownMenu(
                            [
                                dbc.DropdownMenuItem("Settings", href="#"),
                                dbc.DropdownMenuItem("Help", href="#"),
                                dbc.DropdownMenuItem(divider=True),
                                dbc.DropdownMenuItem("Logout", href="#")
                            ],
                            nav=True,
                            in_navbar=True,
                            label=html.Span([
                                html.I(className="fas fa-user-circle me-2"),
                                "Admin"
                            ]),
                            align_end=True,
                            className="dropdown-menu-end"
                        )
                    ], navbar=True)
                ], fluid=True),
                color="dark",
                dark=True,
                className="mb-4"
            ),
            
            # Main content
            dbc.Container(fluid=True, className="g-0", children=[
                dbc.Row([
                    sidebar,
                    content
                ], className="g-0")
            ]),
            
            # Store for dashboard state
            dcc.Store(id='dashboard-state'),
            
            # Interval for auto-refresh
            dcc.Interval(
                id='global-refresh-interval',
                interval=60 * 1000,  # 1 minute
                n_intervals=0
            )
        ])
        
        return layout
    
    def _register_callbacks(self) -> None:
        """Register all callbacks for the application."""
        if not DASH_AVAILABLE or not hasattr(self, 'app') or not self.app:
            return
        
        # Callback to update the page content based on URL
        @self.app.callback(
            Output("page-content", "children"),
            [Input("url", "pathname")]
        )
        def render_page_content(pathname):
            if not pathname or pathname == "/":
                # Default to the first dashboard
                dashboard_id = next(iter(self.dashboards.keys()))
            else:
                # Extract dashboard ID from the URL
                dashboard_id = pathname.strip("/")
            
            if dashboard_id in self.dashboards:
                return self.dashboards[dashboard_id].get_layout()
            
            # If the path doesn't match any dashboard, return a 404
            return html.Div([
                html.H1("404: Not found", className="text-danger"),
                html.Hr(),
                html.P(f"The path {pathname} was not recognized...")
            ], className="p-3")
        
        # Callback to update the active state of navigation links
        @self.app.callback(
            [Output(f"nav-{dashboard_id}", "active") for dashboard_id in self.dashboards],
            [Input("url", "pathname")]
        )
        def update_nav_links(pathname):
            if not pathname or pathname == "/":
                return [dashboard_id == next(iter(self.dashboards.keys())) 
                       for dashboard_id in self.dashboards]
            
            return [dashboard_id == pathname.strip("/") 
                   for dashboard_id in self.dashboards]
        
        # Register callbacks for each dashboard
        for dashboard in self.dashboards.values():
            dashboard.register_callbacks(self.app)
    
    def run(self, host: str = "0.0.0.0", port: int = 8050, debug: bool = False) -> None:
        """Run the dashboard application.
        
        Args:
            host: Host to run the server on
            port: Port to run the server on
            debug: Whether to run in debug mode
        """
        if not DASH_AVAILABLE or not hasattr(self, 'app') or not self.app:
            logger.error("Required dependencies are not installed. Please install with: pip install dash dash-bootstrap-components plotly pandas")
            return
        
        # Set up the layout
        self.app.layout = self._create_layout()
        
        # Register callbacks
        self._register_callbacks()
        
        # Run the server
        logger.info(f"Starting SIEM Dashboard on http://{host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="SIEM Dashboard")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to run the server on")
    parser.add_argument("--port", type=int, default=8050, help="Port to run the server on")
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    return parser.parse_args()

def main():
    """Main entry point for the SIEM Dashboard."""
    args = parse_args()
    
    # Create and run the dashboard
    dashboard = SIEMDashboard()
    dashboard.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
