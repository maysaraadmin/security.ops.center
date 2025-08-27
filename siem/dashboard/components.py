"""
Dashboard components for the SIEM system.
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
import numpy as np
import pandas as pd
from pathlib import Path

from .base import DashboardComponent

# Try to import optional dependencies
try:
    import dash
    from dash import dcc, html, Input, Output, State, callback_context
    import plotly.graph_objects as go
    import plotly.express as px
    import dash_bootstrap_components as dbc
    import dash_ag_grid as dag
    from dash.exceptions import PreventUpdate
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False

class ThreatTimeline(DashboardComponent):
    """Timeline visualization of security events and alerts."""
    
    def __init__(self, component_id: str, title: str = "Threat Timeline", **kwargs):
        super().__init__(component_id, title, kwargs)
        self.time_window = self.config.get('time_window_hours', 24)
        self.update_interval = self.config.get('update_interval_seconds', 60)
    
    def layout(self):
        if not DASH_AVAILABLE:
            return self._missing_deps_component()
            
        return dbc.Card([
            dbc.CardHeader([
                html.H4(self.title, className="card-title"),
                dcc.Interval(
                    id=f"{self.component_id}-interval",
                    interval=self.update_interval * 1000,
                    n_intervals=0
                )
            ]),
            dbc.CardBody([
                dcc.Graph(
                    id=f"{self.component_id}-graph",
                    style={'height': '400px'}
                ),
                html.Div([
                    dbc.Row([
                        dbc.Col([
                            html.Label("Time Window:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-time-window",
                                options=[
                                    {'label': 'Last 1 hour', 'value': 1},
                                    {'label': 'Last 4 hours', 'value': 4},
                                    {'label': 'Last 12 hours', 'value': 12},
                                    {'label': 'Last 24 hours', 'value': 24},
                                    {'label': 'Last 7 days', 'value': 168}
                                ],
                                value=self.time_window,
                                clearable=False
                            )
                        ], width=4),
                        dbc.Col([
                            html.Label("Group By:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-group-by",
                                options=[
                                    {'label': 'Event Type', 'value': 'event_type'},
                                    {'label': 'Severity', 'value': 'severity'},
                                    {'label': 'Source IP', 'value': 'source_ip'},
                                    {'label': 'Destination IP', 'value': 'destination_ip'}
                                ],
                                value='event_type',
                                clearable=False
                            )
                        ], width=4),
                        dbc.Col([
                            html.Label("Aggregation:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-aggregation",
                                options=[
                                    {'label': 'Count', 'value': 'count'},
                                    {'label': 'Sum', 'value': 'sum'},
                                    {'label': 'Average', 'value': 'avg'}
                                ],
                                value='count',
                                clearable=False
                            )
                        ], width=4)
                    ])
                ], className="mb-3")
            ])
        ], className="mb-4")
    
    def register_callbacks(self, app):
        if not DASH_AVAILABLE:
            return
            
        @app.callback(
            Output(f"{self.component_id}-graph", 'figure'),
            [Input(f"{self.component_id}-interval", 'n_intervals'),
             Input(f"{self.component_id}-time-window", 'value'),
             Input(f"{self.component_id}-group-by", 'value'),
             Input(f"{self.component_id}-aggregation", 'value')]
        )
        def update_timeline(n, hours, group_by, aggregation):
            # In a real implementation, this would query your SIEM data
            # For now, we'll generate sample data
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=hours)
            
            # Generate sample data
            categories = ['Malware', 'Brute Force', 'DDoS', 'Data Exfiltration', 'Phishing']
            severities = ['Critical', 'High', 'Medium', 'Low', 'Info']
            
            # Create time series data
            time_points = pd.date_range(start_time, end_time, freq='5min')
            data = []
            
            for time_point in time_points:
                for category in categories:
                    for severity in severities:
                        count = np.random.poisson(1)  # Random count with Poisson distribution
                        if count > 0:
                            data.append({
                                'timestamp': time_point,
                                'event_type': category,
                                'severity': severity,
                                'source_ip': f"192.168.1.{np.random.randint(1, 10)}",
                                'destination_ip': f"10.0.0.{np.random.randint(1, 50)}",
                                'count': count,
                                'value': np.random.uniform(1, 100)
                            })
            
            if not data:
                return go.Figure(layout={
                    'xaxis': {'visible': False},
                    'yaxis': {'visible': False},
                    'annotations': [{
                        'text': 'No data available',
                        'showarrow': False,
                        'font': {'size': 16}
                    }]
                })
            
            df = pd.DataFrame(data)
            
            # Resample based on time window
            if hours <= 1:
                freq = '1min'
            elif hours <= 6:
                freq = '5min'
            elif hours <= 24:
                freq = '15min'
            else:
                freq = '1H'
            
            # Group and aggregate
            df['time_bucket'] = df['timestamp'].dt.floor(freq)
            
            if aggregation == 'count':
                grouped = df.groupby(['time_bucket', group_by]).size().reset_index(name='count')
                y_col = 'count'
                title = f"Event Count by {group_by.replace('_', ' ').title()}"
            else:
                agg_func = 'sum' if aggregation == 'sum' else 'mean'
                grouped = df.groupby(['time_bucket', group_by])['value'].agg(agg_func).reset_index()
                y_col = 'value'
                title = f"{agg_func.title()} Value by {group_by.replace('_', ' ').title()}"
            
            # Create the figure
            fig = px.line(
                grouped,
                x='time_bucket',
                y=y_col,
                color=group_by,
                title=title,
                labels={
                    'time_bucket': 'Time',
                    y_col: y_col.title(),
                    group_by: group_by.replace('_', ' ').title()
                }
            )
            
            fig.update_layout(
                xaxis_title='Time',
                yaxis_title=y_col.title(),
                legend_title=group_by.replace('_', ' ').title(),
                hovermode='x unified',
                template='plotly_dark',
                margin=dict(l=40, r=20, t=40, b=40)
            )
            
            return fig


class AlertHeatmap(DashboardComponent):
    """Heatmap showing alert distribution by time and category."""
    
    def __init__(self, component_id: str, title: str = "Alert Heatmap", **kwargs):
        super().__init__(component_id, title, kwargs)
        self.time_window = self.config.get('time_window_days', 7)
    
    def layout(self):
        if not DASH_AVAILABLE:
            return self._missing_deps_component()
            
        return dbc.Card([
            dbc.CardHeader(html.H4(self.title, className="card-title")),
            dbc.CardBody([
                dcc.Graph(
                    id=f"{self.component_id}-graph",
                    style={'height': '500px'}
                ),
                html.Div([
                    dbc.Row([
                        dbc.Col([
                            html.Label("Time Window:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-time-window",
                                options=[
                                    {'label': 'Last 7 days', 'value': 7},
                                    {'label': 'Last 14 days', 'value': 14},
                                    {'label': 'Last 30 days', 'value': 30}
                                ],
                                value=self.time_window,
                                clearable=False
                            )
                        ], width=4),
                        dbc.Col([
                            html.Label("Group By:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-group-by",
                                options=[
                                    {'label': 'Hour of Day', 'value': 'hour'},
                                    {'label': 'Day of Week', 'value': 'day'},
                                    {'label': 'Day of Month', 'value': 'day_of_month'}
                                ],
                                value='hour',
                                clearable=False
                            )
                        ], width=4),
                        dbc.Col([
                            html.Label("Metric:"),
                            dcc.Dropdown(
                                id=f"{self.component_id}-metric",
                                options=[
                                    {'label': 'Alert Count', 'value': 'count'},
                                    {'label': 'Unique Sources', 'value': 'sources'},
                                    {'label': 'Average Severity', 'value': 'severity'}
                                ],
                                value='count',
                                clearable=False
                            )
                        ], width=4)
                    ])
                ])
            ])
        ], className="mb-4")
    
    def register_callbacks(self, app):
        if not DASH_AVAILABLE:
            return
            
        @app.callback(
            Output(f"{self.component_id}-graph", 'figure'),
            [Input(f"{self.component_id}-time-window", 'value'),
             Input(f"{self.component_id}-group-by", 'value'),
             Input(f"{self.component_id}-metric", 'value')]
        )
        def update_heatmap(days, group_by, metric):
            # In a real implementation, this would query your SIEM data
            end_date = datetime.utcnow().date()
            start_date = end_date - timedelta(days=days)
            
            # Generate sample data
            date_range = pd.date_range(start_date, end_date, freq='D')
            categories = ['Malware', 'Brute Force', 'DDoS', 'Data Exfiltration', 'Phishing']
            
            data = []
            for date in date_range:
                for hour in range(24):
                    for category in categories:
                        # Generate random data
                        count = np.random.poisson(5)  # Random count with Poisson distribution
                        severity = np.random.choice([1, 2, 3, 4, 5], p=[0.1, 0.2, 0.3, 0.25, 0.15])
                        sources = np.random.randint(1, 10)
                        
                        data.append({
                            'date': date,
                            'hour': hour,
                            'day_of_week': date.weekday(),
                            'day_of_month': date.day,
                            'category': category,
                            'count': count,
                            'severity': severity,
                            'sources': sources
                        })
            
            df = pd.DataFrame(data)
            
            # Group data based on selection
            if group_by == 'hour':
                x = df['hour']
                x_title = 'Hour of Day'
                x_tickvals = list(range(24))
                x_ticktext = [f"{h:02d}:00" for h in range(24)]
            elif group_by == 'day':
                x = df['day_of_week']
                x_title = 'Day of Week'
                x_tickvals = list(range(7))
                x_ticktext = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
            else:  # day_of_month
                x = df['day_of_month']
                x_title = 'Day of Month'
                x_tickvals = list(range(1, 32))
                x_ticktext = [str(d) for d in range(1, 32)]
            
            # Pivot the data for heatmap
            if metric == 'count':
                pivot_data = df.pivot_table(
                    index='category',
                    columns=x,
                    values='count',
                    aggfunc='sum',
                    fill_value=0
                )
                color_scale = 'YlOrRd'
                hover_template = "<b>%{y}</b><br>%{x}:00 - %{x+1}:00<br>Count: %{z}<extra></extra>"
            elif metric == 'sources':
                pivot_data = df.pivot_table(
                    index='category',
                    columns=x,
                    values='sources',
                    aggfunc='mean',
                    fill_value=0
                )
                color_scale = 'Blues'
                hover_template = "<b>%{y}</b><br>%{x}:00 - %{x+1}:00<br>Avg Sources: %{z:.1f}<extra></extra>"
            else:  # severity
                pivot_data = df.pivot_table(
                    index='category',
                    columns=x,
                    values='severity',
                    aggfunc='mean',
                    fill_value=0
                )
                color_scale = 'RdYlGn_r'  # Reversed for severity (red is worse)
                hover_template = "<b>%{y}</b><br>%{x}:00 - %{x+1}:00<br>Avg Severity: %{z:.1f}<extra></extra>"
            
            # Create the heatmap
            fig = go.Figure(data=go.Heatmap(
                z=pivot_data.values,
                x=pivot_data.columns,
                y=pivot_data.index,
                colorscale=color_scale,
                hoverongaps=False,
                hovertemplate=hover_template,
                colorbar=dict(
                    title='Count' if metric == 'count' else 'Avg. Sources' if metric == 'sources' else 'Severity',
                    titleside='right'
                )
            ))
            
            fig.update_layout(
                title=f"Alert Distribution by {x_title} and Category",
                xaxis_title=x_title,
                yaxis_title='Category',
                xaxis=dict(
                    tickmode='array',
                    tickvals=x_tickvals,
                    ticktext=x_ticktext
                ),
                template='plotly_dark',
                margin=dict(l=80, r=20, t=60, b=60)
            )
            
            return fig


class TopAlertsTable(DashboardComponent):
    """Table showing the most recent or highest severity alerts."""
    
    def __init__(self, component_id: str, title: str = "Top Alerts", **kwargs):
        super().__init__(component_id, title, kwargs)
        self.max_alerts = self.config.get('max_alerts', 10)
    
    def layout(self):
        if not DASH_AVAILABLE:
            return self._missing_deps_component()
            
        return dbc.Card([
            dbc.CardHeader([
                html.Div([
                    html.H4(self.title, className="card-title"),
                    dcc.Interval(
                        id=f"{self.component_id}-interval",
                        interval=30000,  # 30 seconds
                        n_intervals=0
                    )
                ], className="d-flex justify-content-between align-items-center")
            ]),
            dbc.CardBody([
                html.Div(id=f"{self.component_id}-table-container")
            ])
        ], className="mb-4")
    
    def register_callbacks(self, app):
        if not DASH_AVAILABLE:
            return
            
        @app.callback(
            Output(f"{self.component_id}-table-container", 'children'),
            [Input(f"{self.component_id}-interval", 'n_intervals')]
        )
        def update_table(n):
            # In a real implementation, this would query your SIEM for recent alerts
            # Generate sample alerts
            alerts = self._generate_sample_alerts()
            
            # Convert to DataFrame for AG Grid
            df = pd.DataFrame(alerts)
            
            # Define columns for the table
            column_defs = [
                {"headerName": "Time", "field": "timestamp", "sortable": True, "filter": True, "width": 150},
                {"headerName": "Severity", "field": "severity", "sortable": True, "filter": True, "width": 120,
                 "cellStyle": self._get_severity_style},
                {"headerName": "Source IP", "field": "source_ip", "sortable": True, "filter": True, "width": 130},
                {"headerName": "Destination IP", "field": "destination_ip", "sortable": True, "filter": True, "width": 150},
                {"headerName": "Type", "field": "alert_type", "sortable": True, "filter": True, "width": 150},
                {"headerName": "Description", "field": "description", "sortable": True, "filter": True, "flex": 1},
                {"headerName": "Status", "field": "status", "sortable": True, "filter": True, "width": 120,
                 "cellStyle": self._get_status_style}
            ]
            
            # Create the AG Grid table
            table = dag.AgGrid(
                id=f"{self.component_id}-table",
                columnDefs=column_defs,
                rowData=df.to_dict('records'),
                defaultColDef={
                    "resizable": True,
                    "sortable": True,
                    "filter": True,
                    "floatingFilter": True,
                    "suppressMenu": True
                },
                dashGridOptions={
                    "pagination": True,
                    "paginationPageSize": self.max_alerts,
                    "rowHeight": 40,
                    "headerHeight": 40,
                    "suppressCellFocus": True,
                    "domLayout": 'autoHeight',
                    "animateRows": True
                },
                style={"width": "100%", "height": f"{min(50 + len(df) * 42, 500)}px"},
                className="ag-theme-alpine-dark",
                filterModel={"alert_type": {"filterType": "set", "values": ["Malware", "Brute Force"]}}
            )
            
            return table
    
    def _generate_sample_alerts(self):
        """Generate sample alert data."""
        alert_types = [
            ("Malware", "Malware detected on endpoint"),
            ("Brute Force", "Multiple failed login attempts"),
            ("DDoS", "Potential DDoS attack detected"),
            ("Data Exfiltration", "Unusual data transfer detected"),
            ("Phishing", "Phishing email detected")
        ]
        
        severities = ["Critical", "High", "Medium", "Low", "Info"]
        statuses = ["New", "In Progress", "Escalated", "Resolved", "False Positive"]
        
        alerts = []
        now = datetime.utcnow()
        
        for i in range(self.max_alerts):
            alert_type, description = random.choice(alert_types)
            severity = random.choices(
                severities,
                weights=[0.1, 0.2, 0.3, 0.3, 0.1],  # More medium/low severity alerts
                k=1
            )[0]
            
            status = random.choices(
                statuses,
                weights=[0.4, 0.3, 0.15, 0.1, 0.05],  # More new/in progress
                k=1
            )[0]
            
            alerts.append({
                "timestamp": (now - timedelta(minutes=random.randint(0, 1440))).strftime("%Y-%m-%d %H:%M:%S"),
                "severity": severity,
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "destination_ip": f"10.0.0.{random.randint(1, 254)}",
                "alert_type": alert_type,
                "description": f"{description} from {random.choice(['internal', 'external'])} source",
                "status": status
            })
        
        return alerts
    
    def _get_severity_style(self, params):
        """Return style for severity column."""
        severity = params.value
        colors = {
            "Critical": "#ff4444",
            "High": "#ffbb33",
            "Medium": "#ffcc80",
            "Low": "#4CAF50",
            "Info": "#2196F3"
        }
        
        return {
            'backgroundColor': colors.get(severity, '#ffffff'),
            'color': '#000000' if severity in ["Medium", "Low", "Info"] else '#ffffff',
            'fontWeight': 'bold',
            'textAlign': 'center',
            'borderRadius': '4px',
            'padding': '2px 8px',
            'display': 'inline-block',
            'minWidth': '80px'
        }
    
    def _get_status_style(self, params):
        """Return style for status column."""
        status = params.value
        colors = {
            "New": "#2196F3",
            "In Progress": "#FFC107",
            "Escalated": "#9C27B0",
            "Resolved": "#4CAF50",
            "False Positive": "#607D8B"
        }
        
        return {
            'backgroundColor': colors.get(status, '#e0e0e0'),
            'color': '#000000',
            'fontWeight': '500',
            'textAlign': 'center',
            'borderRadius': '4px',
            'padding': '2px 8px',
            'display': 'inline-block',
            'minWidth': '100px'
        }


# Additional components would be defined here (NetworkTrafficMap, UserActivityGauge, etc.)
# For brevity, I'll include stubs for the remaining components

class UserActivityGauge(DashboardComponent):
    """Gauge showing user activity metrics."""
    pass

class NetworkTrafficMap(DashboardComponent):
    """Geographical map showing network traffic and threats."""
    pass

class ComplianceStatus(DashboardComponent):
    """Compliance status and violations overview."""
    pass

class IncidentTrends(DashboardComponent):
    """Trend analysis of security incidents over time."""
    pass

class ThreatIntelFeed(DashboardComponent):
    """Threat intelligence feed and indicators of compromise."""
    pass

class SystemHealth(DashboardComponent):
    """System health and performance metrics."""
    pass

class CustomQueryViewer(DashboardComponent):
    """Interface for running custom queries against the SIEM."""
    pass
