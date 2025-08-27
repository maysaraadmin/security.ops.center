import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, Callable, Optional
import logging

class SIEMDashboard:
    """
    SIEM Dashboard UI component that displays security events, alerts, and system status.
    """
    
    def __init__(self, parent: ttk.Frame, event_handler: Optional[Callable] = None):
        """
        Initialize the SIEM dashboard.
        
        Args:
            parent: Parent widget
            event_handler: Callback function for UI events
        """
        self.parent = parent
        self.event_handler = event_handler
        self.logger = logging.getLogger('siem.ui.dashboard')
        self._setup_ui()
    
    def _setup_ui(self) -> None:
        """Set up the dashboard UI components."""
        # Main container
        self.main_frame = ttk.Frame(self.parent, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top status bar
        self._create_status_bar()
        
        # Main content area with notebook for different views
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Create tabs
        self._create_overview_tab()
        self._create_events_tab()
        self._create_alerts_tab()
        self._create_compliance_tab()
    
    def _create_status_bar(self) -> None:
        """Create the status bar at the top of the dashboard."""
        status_frame = ttk.Frame(self.main_frame)
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        # System status
        ttk.Label(status_frame, text="Status:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=5)
        self.status_label = ttk.Label(status_frame, text="Initializing...", foreground="orange")
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Last updated
        ttk.Label(status_frame, text="Last Updated:", font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT, padx=(20, 5))
        self.last_updated_label = ttk.Label(status_frame, text="Never")
        self.last_updated_label.pack(side=tk.LEFT, padx=5)
        
        # Refresh button
        refresh_btn = ttk.Button(
            status_frame, 
            text="🔄 Refresh",
            command=self._on_refresh
        )
        refresh_btn.pack(side=tk.RIGHT, padx=5)
    
    def _create_overview_tab(self) -> None:
        """Create the overview tab with key metrics."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Overview")
        
        # Metrics frame
        metrics_frame = ttk.LabelFrame(tab, text="Security Metrics", padding="10")
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create metric cards
        self.metrics = {
            'total_events': self._create_metric_card(metrics_frame, "Total Events", "0"),
            'alerts_24h': self._create_metric_card(metrics_frame, "Alerts (24h)", "0", "red"),
            'threats_blocked': self._create_metric_card(metrics_frame, "Threats Blocked", "0", "green"),
            'compliance_score': self._create_metric_card(metrics_frame, "Compliance Score", "0%")
        }
        
        # Recent events table
        events_frame = ttk.LabelFrame(tab, text="Recent Security Events", padding="10")
        events_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("time", "source", "event_type", "severity", "message")
        self.events_table = ttk.Treeview(
            events_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.events_table.heading("time", text="Time")
        self.events_table.heading("source", text="Source")
        self.events_table.heading("event_type", text="Event Type")
        self.events_table.heading("severity", text="Severity")
        self.events_table.heading("message", text="Message")
        
        # Set column widths
        self.events_table.column("time", width=150)
        self.events_table.column("source", width=120)
        self.events_table.column("event_type", width=120)
        self.events_table.column("severity", width=80)
        self.events_table.column("message", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(events_frame, orient=tk.VERTICAL, command=self.events_table.yview)
        self.events_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.events_table.pack(fill=tk.BOTH, expand=True)
        
        # Double-click event for event details
        self.events_table.bind("<Double-1>", self._on_event_double_click)
    
    def _create_events_tab(self) -> None:
        """Create the events tab with detailed event listing."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Events")
        
        # Search and filter controls
        filter_frame = ttk.Frame(tab)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(filter_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            filter_frame, 
            text="Search", 
            command=self._on_search_events
        ).pack(side=tk.LEFT, padx=5)
        
        # Events table
        columns = ("id", "timestamp", "source", "event_type", "severity", "message")
        self.events_table_detailed = ttk.Treeview(
            tab, 
            columns=columns, 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        for col in columns:
            self.events_table_detailed.heading(col, text=col.replace('_', ' ').title())
            self.events_table_detailed.column(col, width=100)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.events_table_detailed.yview)
        x_scroll = ttk.Scrollbar(tab, orient=tk.HORIZONTAL, command=self.events_table_detailed.xview)
        self.events_table_detailed.configure(yscroll=y_scroll.set, xscroll=x_scroll.set)
        
        # Layout
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.events_table_detailed.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Double-click event for event details
        self.events_table_detailed.bind("<Double-1>", self._on_event_double_click)
    
    def _create_alerts_tab(self) -> None:
        """Create the alerts tab with active security alerts."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Alerts")
        
        # Alerts table
        columns = ("id", "timestamp", "severity", "source", "description", "status")
        self.alerts_table = ttk.Treeview(
            tab, 
            columns=columns, 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        for col in columns:
            self.alerts_table.heading(col, text=col.title())
            self.alerts_table.column(col, width=100)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.alerts_table.yview)
        x_scroll = ttk.Scrollbar(tab, orient=tk.HORIZONTAL, command=self.alerts_table.xview)
        self.alerts_table.configure(yscroll=y_scroll.set, xscroll=x_scroll.set)
        
        # Layout
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.alerts_table.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alert actions frame
        actions_frame = ttk.Frame(tab)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            actions_frame,
            text="Acknowledge",
            command=self._on_acknowledge_alert
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            actions_frame,
            text="Escalate",
            command=self._on_escalate_alert
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            actions_frame,
            text="View Details",
            command=self._on_view_alert_details
        ).pack(side=tk.LEFT, padx=5)
    
    def _create_compliance_tab(self) -> None:
        """Create the compliance tab with compliance status."""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Compliance")
        
        # Compliance frameworks list
        frameworks_frame = ttk.LabelFrame(tab, text="Compliance Frameworks", padding="10")
        frameworks_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ("framework", "status", "last_audit", "score")
        self.compliance_table = ttk.Treeview(
            frameworks_frame, 
            columns=columns, 
            show="headings"
        )
        
        # Configure columns
        self.compliance_table.heading("framework", text="Framework")
        self.compliance_table.heading("status", text="Status")
        self.compliance_table.heading("last_audit", text="Last Audit")
        self.compliance_table.heading("score", text="Score")
        
        # Set column widths
        self.compliance_table.column("framework", width=200)
        self.compliance_table.column("status", width=100)
        self.compliance_table.column("last_audit", width=150)
        self.compliance_table.column("score", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frameworks_frame, orient=tk.VERTICAL, command=self.compliance_table.yview)
        self.compliance_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.compliance_table.pack(fill=tk.BOTH, expand=True)
        
        # Compliance details frame
        details_frame = ttk.LabelFrame(tab, text="Compliance Details", padding="10")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.compliance_text = tk.Text(
            details_frame, 
            wrap=tk.WORD, 
            height=10,
            font=('Consolas', 10)
        )
        
        scrollbar = ttk.Scrollbar(details_frame, command=self.compliance_text.yview)
        self.compliance_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.compliance_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection change
        self.compliance_table.bind("<<TreeviewSelect>>", self._on_compliance_select)
    
    def _create_metric_card(self, parent: ttk.Frame, title: str, value: str, color: str = "black") -> ttk.Frame:
        """Create a metric card widget."""
        card = ttk.Frame(parent, padding="10", relief="solid", borderwidth=1)
        card.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5, pady=5)
        
        # Title
        ttk.Label(
            card, 
            text=title,
            font=('Helvetica', 10, 'bold')
        ).pack(anchor=tk.W)
        
        # Value
        value_label = ttk.Label(
            card, 
            text=value,
            font=('Helvetica', 16, 'bold'),
            foreground=color
        )
        value_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Store reference to update later
        return value_label
    
    def update_metrics(self, metrics: Dict[str, Any]) -> None:
        """Update the metrics display."""
        for key, value in metrics.items():
            if key in self.metrics:
                self.metrics[key].config(text=str(value))
    
    def add_event(self, event: Dict[str, Any]) -> None:
        """Add a new event to the events table."""
        values = (
            event.get('timestamp', ''),
            event.get('source', ''),
            event.get('event_type', ''),
            event.get('severity', ''),
            event.get('message', '')
        )
        self.events_table.insert("", tk.END, values=values)
        
        # Keep only the last 100 events
        if len(self.events_table.get_children()) > 100:
            self.events_table.delete(self.events_table.get_children()[0])
    
    def add_alert(self, alert: Dict[str, Any]) -> None:
        """Add a new alert to the alerts table."""
        values = (
            alert.get('id', ''),
            alert.get('timestamp', ''),
            alert.get('severity', ''),
            alert.get('source', ''),
            alert.get('description', '')[:100] + '...',
            alert.get('status', 'new')
        )
        self.alerts_table.insert("", tk.END, values=values)
    
    def update_compliance(self, compliance_data: Dict[str, Any]) -> None:
        """Update the compliance tab with new data."""
        # Clear existing items
        for item in self.compliance_table.get_children():
            self.compliance_table.delete(item)
        
        # Add new items
        for framework, data in compliance_data.items():
            self.compliance_table.insert("", tk.END, values=(
                framework,
                data.get('status', 'Unknown'),
                data.get('last_audit', 'N/A'),
                f"{data.get('score', 0)}%"
            ))
    
    def _on_refresh(self) -> None:
        """Handle refresh button click."""
        if self.event_handler:
            self.event_handler({"type": "refresh"})
    
    def _on_search_events(self) -> None:
        """Handle search events."""
        query = self.search_entry.get().strip()
        if query and self.event_handler:
            self.event_handler({"type": "search_events", "query": query})
    
    def _on_event_double_click(self, event) -> None:
        """Handle double-click on an event."""
        selected = self.events_table.selection()
        if selected and self.event_handler:
            event_data = self.events_table.item(selected[0], 'values')
            self.event_handler({"type": "view_event", "data": event_data})
    
    def _on_acknowledge_alert(self) -> None:
        """Handle acknowledge alert action."""
        selected = self.alerts_table.selection()
        if selected and self.event_handler:
            alert_ids = [self.alerts_table.item(item, 'values')[0] for item in selected]
            self.event_handler({"type": "acknowledge_alert", "alert_ids": alert_ids})
    
    def _on_escalate_alert(self) -> None:
        """Handle escalate alert action."""
        selected = self.alerts_table.selection()
        if selected and self.event_handler:
            alert_ids = [self.alerts_table.item(item, 'values')[0] for item in selected]
            self.event_handler({"type": "escalate_alert", "alert_ids": alert_ids})
    
    def _on_view_alert_details(self) -> None:
        """Handle view alert details action."""
        selected = self.alerts_table.selection()
        if selected and self.event_handler:
            alert_id = self.alerts_table.item(selected[0], 'values')[0]
            self.event_handler({"type": "view_alert_details", "alert_id": alert_id})
    
    def _on_compliance_select(self, event) -> None:
        """Handle selection change in compliance table."""
        selected = self.compliance_table.selection()
        if selected and self.event_handler:
            framework = self.compliance_table.item(selected[0], 'values')[0]
            self.event_handler({"type": "select_compliance", "framework": framework})
