import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
import logging
import psutil
import platform

from models.security_models import Severity, EDREvent, AlertStatus
from services.dashboard_service import DashboardWidget

logger = logging.getLogger(__name__)

class EDRDashboard(DashboardWidget):
    """EDR Dashboard widget showing endpoint security events and status."""
    
    def __init__(self, parent, dashboard_service, **kwargs):
        """Initialize the EDR dashboard."""
        super().__init__(parent, dashboard_service, **kwargs)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        
        # Initialize data
        self.events = []
        self.endpoint_status = {}
        
        # Create UI
        self._create_widgets()
        
        # Initial data load
        self.update_display()
    
    def _create_widgets(self):
        """Create the EDR dashboard widgets."""
        # Header
        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        
        ttk.Label(
            header, 
            text="Endpoint Detection & Response", 
            font=('Arial', 12, 'bold')
        ).pack(side='left')
        
        # Refresh button
        ttk.Button(
            header, 
            text="Refresh", 
            command=lambda: self.dashboard_service._update_metrics()
        ).pack(side='right')
        
        # Create notebook for different views
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky='nsew')
        
        # Events tab
        self.events_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.events_frame, text="Security Events")
        self._create_events_view()
        
        # Endpoints tab
        self.endpoints_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.endpoints_frame, text="Endpoints")
        self._create_endpoints_view()
        
        # Stats tab
        self.stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.stats_frame, text="Statistics")
        self._create_stats_view()
    
    def _create_events_view(self):
        """Create the security events view."""
        # Create treeview with scrollbars
        self.events_tree = ttk.Treeview(
            self.events_frame,
            columns=('time', 'process', 'user', 'severity', 'type', 'details'),
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.events_tree.heading('time', text='Time', anchor='w')
        self.events_tree.heading('process', text='Process', anchor='w')
        self.events_tree.heading('user', text='User', anchor='w')
        self.events_tree.heading('severity', text='Severity', anchor='w')
        self.events_tree.heading('type', text='Type', anchor='w')
        self.events_tree.heading('details', text='Details', anchor='w')
        
        # Set column widths
        self.events_tree.column('time', width=150, minwidth=100)
        self.events_tree.column('process', width=150, minwidth=100)
        self.events_tree.column('user', width=100, minwidth=80)
        self.events_tree.column('severity', width=80, minwidth=60)
        self.events_tree.column('type', width=150, minwidth=100)
        self.events_tree.column('details', width=400, minwidth=200)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(
            self.events_frame, 
            orient='vertical', 
            command=self.events_tree.yview
        )
        x_scroll = ttk.Scrollbar(
            self.events_frame, 
            orient='horizontal', 
            command=self.events_tree.xview
        )
        self.events_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        self.events_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        x_scroll.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        self.events_frame.columnconfigure(0, weight=1)
        self.events_frame.rowconfigure(0, weight=1)
        
        # Add context menu
        self._setup_events_context_menu()
    
    def _create_endpoints_view(self):
        """Create the endpoints status view."""
        # Create treeview with scrollbars
        self.endpoints_tree = ttk.Treeview(
            self.endpoints_frame,
            columns=('endpoint', 'status', 'last_seen', 'os', 'ip', 'alerts'),
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.endpoints_tree.heading('endpoint', text='Endpoint', anchor='w')
        self.endpoints_tree.heading('status', text='Status', anchor='w')
        self.endpoints_tree.heading('last_seen', text='Last Seen', anchor='w')
        self.endpoints_tree.heading('os', text='OS', anchor='w')
        self.endpoints_tree.heading('ip', text='IP Address', anchor='w')
        self.endpoints_tree.heading('alerts', text='Active Alerts', anchor='w')
        
        # Set column widths
        self.endpoints_tree.column('endpoint', width=200, minwidth=150)
        self.endpoints_tree.column('status', width=100, minwidth=80)
        self.endpoints_tree.column('last_seen', width=150, minwidth=100)
        self.endpoints_tree.column('os', width=150, minwidth=100)
        self.endpoints_tree.column('ip', width=150, minwidth=100)
        self.endpoints_tree.column('alerts', width=100, minwidth=80)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(
            self.endpoints_frame,
            orient='vertical',
            command=self.endpoints_tree.yview
        )
        self.endpoints_tree.configure(yscrollcommand=y_scroll.set)
        
        # Grid layout
        self.endpoints_tree.grid(row=0, column=0, sticky='nsew')
        y_scroll.grid(row=0, column=1, sticky='ns')
        
        # Configure grid weights
        self.endpoints_frame.columnconfigure(0, weight=1)
        self.endpoints_frame.rowconfigure(0, weight=1)
    
    def _create_stats_view(self):
        """Create the statistics view."""
        # Create frames for different stats
        self.stats_container = ttk.Frame(self.stats_frame)
        self.stats_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Severity distribution
        ttk.Label(
            self.stats_container,
            text="Alerts by Severity",
            font=('Arial', 10, 'bold')
        ).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        self.severity_frame = ttk.Frame(self.stats_container)
        self.severity_frame.grid(row=1, column=0, sticky='nsew', pady=(0, 20))
        
        # Top processes
        ttk.Label(
            self.stats_container,
            text="Top Processes by Alerts",
            font=('Arial', 10, 'bold')
        ).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        self.processes_tree = ttk.Treeview(
            self.stats_container,
            columns=('process', 'count'),
            show='headings',
            height=5
        )
        self.processes_tree.heading('process', text='Process')
        self.processes_tree.heading('count', text='Alert Count')
        self.processes_tree.column('process', width=200)
        self.processes_tree.column('count', width=100)
        self.processes_tree.grid(row=3, column=0, sticky='ew')
        
        # Configure grid weights
        self.stats_container.columnconfigure(0, weight=1)
    
    def _setup_events_context_menu(self):
        """Set up the right-click context menu for events."""
        self.context_menu = tk.Menu(self.events_tree, tearoff=0)
        self.context_menu.add_command(
            label="View Details",
            command=self._show_event_details
        )
        self.context_menu.add_command(
            label="Mark as Resolved",
            command=self._mark_event_resolved
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Export to CSV",
            command=self._export_events
        )
        
        # Bind right-click event
        self.events_tree.bind(
            "<Button-3>",
            lambda e: self._show_context_menu(e, self.context_menu)
        )
    
    def _show_context_menu(self, event, menu):
        """Show the context menu at the cursor position."""
        try:
            item = self.events_tree.identify_row(event.y)
            if item:
                self.events_tree.selection_set(item)
                menu.post(event.x_root, event.y_root)
        except Exception as e:
            logger.error(f"Error showing context menu: {e}")
    
    def _show_event_details(self):
        """Show detailed information about the selected event."""
        selected = self.events_tree.selection()
        if not selected:
            return
            
        item = self.events_tree.item(selected[0])
        event_id = item['tags'][0] if item['tags'] else None
        
        if event_id and event_id in [str(e.id) for e in self.events]:
            event = next(e for e in self.events if str(e.id) == event_id)
            self._show_event_dialog(event)
    
    def _mark_event_resolved(self):
        """Mark the selected event as resolved."""
        selected = self.events_tree.selection()
        if not selected:
            return
            
        item = self.events_tree.item(selected[0])
        event_id = item['tags'][0] if item['tags'] else None
        
        if event_id:
            # In a real implementation, update the event status in the database
            logger.info(f"Marking event {event_id} as resolved")
            # Update the UI
            self.events_tree.item(selected[0], tags=('resolved',))
            self.events_tree.item(selected[0], tags=('resolved',))
    
    def _export_events(self):
        """Export events to a CSV file."""
        # In a real implementation, this would export to a file
        logger.info("Exporting events to CSV")
    
    def _show_event_dialog(self, event):
        """Show a dialog with detailed event information."""
        dialog = tk.Toplevel(self)
        dialog.title("Event Details")
        dialog.geometry("600x400")
        
        # Create text widget for details
        text = tk.Text(dialog, wrap='word')
        text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Add event details
        text.insert('end', f"Event ID: {event.id}\n")
        text.insert('end', f"Timestamp: {event.timestamp}\n")
        text.insert('end', f"Endpoint: {event.endpoint_id}\n")
        text.insert('end', f"Process: {event.process_name} (PID: {event.process_id})\n")
        text.insert('end', f"User: {event.user}\n")
        text.insert('end', f"Severity: {event.severity.name}\n")
        text.insert('end', f"Type: {event.detection_type}\n\n")
        text.insert('end', "Details:\n")
        
        # Add formatted details
        if isinstance(event.details, dict):
            for key, value in event.details.items():
                text.insert('end', f"  {key}: {value}\n")
        else:
            text.insert('end', str(event.details))
        
        # Make text read-only
        text.config(state='disabled')
        
        # Add close button
        ttk.Button(
            dialog,
            text="Close",
            command=dialog.destroy
        ).pack(pady=10)
    
    def update_display(self):
        """Update the display with the latest data."""
        try:
            # Get the latest metrics from the dashboard service
            metrics = self.metrics
            if not metrics or not hasattr(metrics, 'edr_metrics'):
                return
                
            # Update events
            self._update_events(metrics.edr_metrics.get('recent_events', []))
            
            # Update endpoints
            self._update_endpoints(metrics.edr_metrics.get('endpoints', []))
            
            # Update statistics
            self._update_statistics(metrics.edr_metrics)
            
        except Exception as e:
            logger.error(f"Error updating EDR dashboard: {e}", exc_info=True)
    
    def _update_events(self, events):
        """Update the events list."""
        # Clear existing items
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        # Store events for reference
        self.events = events
        
        # Add new events
        for event in sorted(events, key=lambda x: x.timestamp, reverse=True):
            # Truncate details for display
            details = str(event.details)[:100] + '...' if len(str(event.details)) > 100 else str(event.details)
            
            # Add item to treeview
            item_id = self.events_tree.insert('', 'end', values=(
                event.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                event.process_name,
                event.user,
                event.severity.name,
                event.detection_type,
                details
            ), tags=(str(event.id),))
            
            # Color code by severity
            if event.severity == Severity.CRITICAL:
                self.events_tree.item(item_id, tags=('critical',))
            elif event.severity == Severity.HIGH:
                self.events_tree.item(item_id, tags=('high',))
            elif event.severity == Severity.MEDIUM:
                self.events_tree.item(item_id, tags=('medium',))
            else:
                self.events_tree.item(item_id, tags=('low',))
        
        # Configure tag colors
        self.events_tree.tag_configure('critical', background='#ffb3b3')
        self.events_tree.tag_configure('high', background='#ffd699')
        self.events_tree.tag_configure('medium', background='#ffff99')
        self.events_tree.tag_configure('low', background='#e6f3ff')
        self.events_tree.tag_configure('resolved', background='#e6ffe6')
    
    def _update_endpoints(self, endpoints):
        """Update the endpoints list."""
        # Clear existing items
        for item in self.endpoints_tree.get_children():
            self.endpoints_tree.delete(item)
        
        # Add endpoints
        for endpoint in endpoints:
            last_seen = endpoint.get('last_seen', '')
            if isinstance(last_seen, str):
                try:
                    last_seen = datetime.fromisoformat(last_seen).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    last_seen = str(last_seen)
            
            status = endpoint.get('status', 'offline')
            alert_count = endpoint.get('alert_count', 0)
            
            # Add item to treeview
            self.endpoints_tree.insert('', 'end', values=(
                endpoint.get('id', 'N/A'),
                status.capitalize(),
                last_seen,
                endpoint.get('os', 'N/A'),
                endpoint.get('ip', 'N/A'),
                alert_count
            ), tags=(status,))
        
        # Configure tag colors
        self.endpoints_tree.tag_configure('online', background='#e6ffe6')
        self.endpoints_tree.tag_configure('offline', background='#ffe6e6')
    
    def _update_statistics(self, metrics):
        """Update the statistics view."""
        # Update severity distribution
        self._update_severity_distribution(metrics.get('severity_distribution', {}))
        
        # Update top processes
        self._update_top_processes(metrics.get('top_processes', []))
    
    def _update_severity_distribution(self, distribution):
        """Update the severity distribution chart."""
        # Clear existing widgets
        for widget in self.severity_frame.winfo_children():
            widget.destroy()
        
        if not distribution:
            ttk.Label(
                self.severity_frame,
                text="No data available"
            ).pack()
            return
        
        # Create a horizontal bar chart
        max_count = max(distribution.values()) if distribution else 1
        max_width = 300  # pixels
        
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = distribution.get(severity.name.lower(), 0)
            if count == 0:
                continue
                
            frame = ttk.Frame(self.severity_frame)
            frame.pack(fill='x', pady=2)
            
            ttk.Label(
                frame,
                text=severity.name,
                width=10,
                anchor='w'
            ).pack(side='left')
            
            # Calculate bar width
            width = int((count / max_count) * max_width) if max_count > 0 else 0
            
            # Create a colored frame for the bar
            bar = ttk.Frame(frame, height=20)
            bar.pack(side='left', padx=5, fill='x', expand=True)
            
            # Add colored label inside the bar
            color = {
                'CRITICAL': '#ff4d4d',
                'HIGH': '#ff944d',
                'MEDIUM': '#ffcc00',
                'LOW': '#4da6ff',
                'INFO': '#99cc00'
            }.get(severity.name, '#cccccc')
            
            ttk.Label(
                bar,
                text=str(count),
                background=color,
                foreground='black',
                anchor='w',
                padding=(5, 0)
            ).place(x=0, y=0, width=width, height=20)
    
    def _update_top_processes(self, processes):
        """Update the top processes list."""
        # Clear existing items
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        # Add top processes
        for i, (process, count) in enumerate(processes[:10]):
            self.processes_tree.insert('', 'end', values=(process, count))
