import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import psutil
import platform
import os
import logging
from typing import Dict, List, Optional, Tuple, Any

# Import shared styles and utilities
from .dashboard_view import COLORS, ModernStyle, create_card

class SIEMView(ttk.Frame):
    """Dedicated SIEM view with security-focused dashboard components."""
    
    def __init__(self, parent, event_model, rule_model, service_manager=None, **kwargs):
        """Initialize the SIEM view with security monitoring components."""
        super().__init__(parent, **kwargs)
        self.event_model = event_model
        self.rule_model = rule_model
        self.service_manager = service_manager
        self.last_update = None
        
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        
        # Initialize data structures
        self.figures = []
        self.canvases = []
        self._scheduled_update = None
        
        # Initialize UI
        self._create_widgets()
        
        # Initial data load
        self.update_view()
    
    def _create_widgets(self):
        """Create and layout all SIEM view components."""
        # Main container with scrollbar
        self.canvas = tk.Canvas(self, bg=COLORS['background'], highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, style='TFrame')
        
        # Configure canvas scrolling
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Mouse wheel scrolling
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        self.canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Pack the canvas and scrollbar
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Header
        self._create_header(self.scrollable_frame)
        
        # Stats row
        self._create_stats_row(self.scrollable_frame)
        
        # Main content area
        content_frame = ttk.Frame(self.scrollable_frame, style='TFrame')
        content_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Left column - Security Overview
        left_column = ttk.Frame(content_frame, style='TFrame')
        left_column.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Right column - Alerts and Events
        right_column = ttk.Frame(content_frame, style='TFrame')
        right_column.pack(side='right', fill='both', expand=False, padx=5, pady=5)
        
        # Add components to columns
        self._create_security_overview(left_column)
        self._create_threat_intel(left_column)
        self._create_alerts_section(right_column)
        self._create_events_section(right_column)
        
        # Footer
        self._create_footer(self.scrollable_frame)
    
    def _create_header(self, parent):
        """Create the SIEM view header with title and controls."""
        header = ttk.Frame(parent, style='TFrame')
        header.pack(fill='x', padx=10, pady=10)
        
        # Title and subtitle
        title_frame = ttk.Frame(header, style='TFrame')
        title_frame.pack(side='left', fill='x', expand=True)
        
        ttk.Label(
            title_frame, 
            text="SIEM Security Dashboard", 
            font=('Segoe UI', 18, 'bold'),
            foreground=COLORS['primary'],
            background=COLORS['background']
        ).pack(anchor='w')
        
        ttk.Label(
            title_frame,
            text="Real-time security monitoring and threat detection",
            font=('Segoe UI', 9),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        ).pack(anchor='w', pady=(0, 5))
        
        # Controls
        controls_frame = ttk.Frame(header, style='TFrame')
        controls_frame.pack(side='right')
        
        refresh_btn = ttk.Button(
            controls_frame,
            text="🔄 Refresh",
            style='Accent.TButton',
            command=self.update_view
        )
        refresh_btn.pack(side='left', padx=5)
        
        settings_btn = ttk.Button(
            controls_frame,
            text="⚙️ Settings",
            command=self._show_settings
        )
        settings_btn.pack(side='left')
    
    def _create_stats_row(self, parent):
        """Create the stats cards row with security metrics."""
        stats_frame = ttk.Frame(parent, style='TFrame')
        stats_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        # Define stats cards
        stats = [
            {"title": "Alerts (24h)", "value": "0", "trend": "0%", "trend_up": False, "icon": "⚠️"},
            {"title": "Threats Blocked", "value": "0", "trend": "0%", "trend_up": False, "icon": "🛡️"},
            {"title": "Active Incidents", "value": "0", "trend": "0%", "trend_up": False, "icon": "🚨"},
            {"title": "Security Score", "value": "0/100", "trend": "0%", "trend_up": True, "icon": "📊"}
        ]
        
        for stat in stats:
            card = self._create_stat_card(stats_frame, stat)
            card.pack(side='left', fill='both', expand=True, padx=5)
    
    def _create_stat_card(self, parent, stat):
        """Create a single stat card."""
        card = create_card(parent, padding=10)
        
        # Header with icon and title
        header = ttk.Frame(card, style='TFrame')
        header.pack(fill='x')
        
        ttk.Label(
            header,
            text=stat["icon"],
            font=('Segoe UI Emoji', 14),
            background=COLORS['surface']
        ).pack(side='left', padx=(0, 5))
        
        ttk.Label(
            header,
            text=stat["title"],
            font=('Segoe UI', 9, 'bold'),
            foreground=COLORS['text_secondary'],
            background=COLORS['surface']
        ).pack(side='left')
        
        # Value
        ttk.Label(
            card,
            text=stat["value"],
            font=('Segoe UI', 24, 'bold'),
            foreground=COLORS['primary'],
            background=COLORS['surface']
        ).pack(anchor='w', pady=(5, 0))
        
        # Trend
        trend_frame = ttk.Frame(card, style='TFrame')
        trend_frame.pack(fill='x', pady=(2, 0))
        
        arrow = "▲" if stat["trend_up"] else "▼"
        color = COLORS['success'] if stat["trend_up"] else COLORS['error']
        
        ttk.Label(
            trend_frame,
            text=f"{arrow} {stat['trend']}",
            font=('Segoe UI', 8, 'bold'),
            foreground=color,
            background=COLORS['surface']
        ).pack(side='left')
        
        return card
    
    def _create_security_overview(self, parent):
        """Create the security overview section with charts."""
        card = create_card(parent, title="Security Overview")
        card.pack(fill='both', expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Add tabs for different views
        notebook = ttk.Notebook(card)
        notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Threat Detection tab
        threat_frame = ttk.Frame(notebook)
        notebook.add(threat_frame, text="Threat Detection")
        
        # Add a placeholder for the threat detection chart
        fig = Figure(figsize=(8, 4), dpi=100)
        ax = fig.add_subplot(111)
        ax.set_title('Threat Detection Over Time')
        ax.set_xlabel('Time')
        ax.set_ylabel('Count')
        
        canvas = FigureCanvasTkAgg(fig, master=threat_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)
        
        self.figures.append(fig)
        self.canvases.append(canvas)
        
        # Add more tabs as needed...
    
    def _create_threat_intel(self, parent):
        """Create the threat intelligence section."""
        card = create_card(parent, title="Threat Intelligence")
        card.pack(fill='both', expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Add threat intel components
        ttk.Label(
            card,
            text="Latest Threat Feeds",
            font=('Segoe UI', 10, 'bold'),
            background=COLORS['surface']
        ).pack(anchor='w', padx=10, pady=(5, 0))
        
        # Add a treeview for threat intel
        columns = ('source', 'type', 'severity', 'first_seen', 'description')
        tree = ttk.Treeview(
            card,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=5
        )
        
        # Configure columns
        tree.heading('source', text='Source')
        tree.heading('type', text='Type')
        tree.heading('severity', text='Severity')
        tree.heading('first_seen', text='First Seen')
        tree.heading('description', text='Description')
        
        # Set column widths
        tree.column('source', width=120, anchor='w')
        tree.column('type', width=100, anchor='w')
        tree.column('severity', width=80, anchor='center')
        tree.column('first_seen', width=120, anchor='w')
        tree.column('description', width=200, anchor='w')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(card, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
        
        # Store reference
        self.threat_intel_tree = tree
    
    def _create_alerts_section(self, parent):
        """Create the alerts section."""
        card = create_card(parent, title="Security Alerts")
        card.pack(fill='both', expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Add alert filters
        filter_frame = ttk.Frame(card, style='TFrame')
        filter_frame.pack(fill='x', padx=5, pady=(0, 5))
        
        # Severity filter
        ttk.Label(
            filter_frame,
            text="Severity:",
            font=('Segoe UI', 8),
            background=COLORS['surface']
        ).pack(side='left', padx=(0, 5))
        
        severity_var = tk.StringVar(value='All')
        severity_menu = ttk.OptionMenu(
            filter_frame,
            severity_var,
            'All',
            'All', 'Critical', 'High', 'Medium', 'Low'
        )
        severity_menu.pack(side='left', padx=(0, 10))
        
        # Search box
        search_frame = ttk.Frame(filter_frame, style='TFrame')
        search_frame.pack(side='right')
        
        search_icon = ttk.Label(
            search_frame,
            text="🔍",
            font=('Segoe UI', 10),
            background=COLORS['surface']
        )
        search_icon.pack(side='left', padx=(0, 5))
        
        search_entry = ttk.Entry(
            search_frame,
            width=20,
            style='Modern.TEntry'
        )
        search_entry.pack(side='left')
        search_entry.insert(0, 'Search alerts...')
        
        # Alerts table
        columns = ('time', 'severity', 'source', 'name', 'status')
        self.alerts_tree = ttk.Treeview(
            card,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=8
        )
        
        # Configure columns
        self.alerts_tree.heading('time', text='Time', anchor='w')
        self.alerts_tree.heading('severity', text='Severity', anchor='center')
        self.alerts_tree.heading('source', text='Source', anchor='w')
        self.alerts_tree.heading('name', text='Alert Name', anchor='w')
        self.alerts_tree.heading('status', text='Status', anchor='center')
        
        # Set column widths
        self.alerts_tree.column('time', width=120, anchor='w')
        self.alerts_tree.column('severity', width=80, anchor='center')
        self.alerts_tree.column('source', width=100, anchor='w')
        self.alerts_tree.column('name', width=200, anchor='w')
        self.alerts_tree.column('status', width=80, anchor='center')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(card, orient='vertical', command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.alerts_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
        
        # Double-click event for alert details
        self.alerts_tree.bind('<Double-1>', self._on_alert_double_click)
    
    def _create_events_section(self, parent):
        """Create the security events section."""
        card = create_card(parent, title="Recent Security Events")
        card.pack(fill='both', expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Events table
        columns = ('time', 'source', 'event_type', 'severity', 'description', 'ip_address')
        self.events_tree = ttk.Treeview(
            card,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=8
        )
        
        # Configure columns
        self.events_tree.heading('time', text='Time', anchor='w')
        self.events_tree.heading('source', text='Source', anchor='w')
        self.events_tree.heading('event_type', text='Event Type', anchor='w')
        self.events_tree.heading('severity', text='Severity', anchor='center')
        self.events_tree.heading('description', text='Description', anchor='w')
        self.events_tree.heading('ip_address', text='IP Address', anchor='w')
        
        # Set column widths
        self.events_tree.column('time', width=120, anchor='w')
        self.events_tree.column('source', width=100, anchor='w')
        self.events_tree.column('event_type', width=120, anchor='w')
        self.events_tree.column('severity', width=80, anchor='center')
        self.events_tree.column('description', width=200, anchor='w')
        self.events_tree.column('ip_address', width=100, anchor='w')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(card, orient='vertical', command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.events_tree.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        scrollbar.pack(side='right', fill='y')
        
        # Double-click event for event details
        self.events_tree.bind('<Double-1>', self._on_event_double_click)
    
    def _create_footer(self, parent):
        """Create the footer with status information."""
        footer = ttk.Frame(parent, style='TFrame')
        footer.pack(fill='x', padx=10, pady=(10, 5))
        
        # Last updated time
        self.last_updated_var = tk.StringVar(value="Last updated: Never")
        ttk.Label(
            footer,
            textvariable=self.last_updated_var,
            font=('Segoe UI', 8),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        ).pack(side='left')
        
        # Version info
        version = "1.0.0"  # This should come from a config file
        ttk.Label(
            footer,
            text=f"SIEM v{version}",
            font=('Segoe UI', 8),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        ).pack(side='right')
    
    def update_view(self):
        """Update the SIEM view with fresh data."""
        try:
            # Update last updated time
            self.last_update = datetime.now()
            self.last_updated_var.set(f"Last updated: {self.last_update.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Update alerts
            self._update_alerts()
            
            # Update events
            self._update_events()
            
            # Update threat intel
            self._update_threat_intel()
            
        except Exception as e:
            logging.error(f"Error updating SIEM view: {e}")
        finally:
            # Schedule next update
            self._schedule_update(5000)  # Update every 5 seconds
    
    def _update_alerts(self):
        """Update the alerts table with the latest alerts."""
        # Clear existing alerts
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Get alerts from the model (this is a placeholder - replace with actual data)
        alerts = self._get_sample_alerts()
        
        # Add alerts to the treeview
        for alert in alerts:
            self.alerts_tree.insert('', 'end', values=(
                alert.get('time', ''),
                alert.get('severity', 'Medium'),
                alert.get('source', 'Unknown'),
                alert.get('name', 'Unknown Alert'),
                alert.get('status', 'New')
            ))
    
    def _update_events(self):
        """Update the events table with the latest security events."""
        # Clear existing events
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)
        
        try:
            # Get events from the last hour
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            
            # This is a placeholder - replace with actual data from your model
            events = self._get_sample_events()
            
            # Add events to the treeview
            for event in events:
                self.events_tree.insert('', 'end', values=(
                    event.get('timestamp', ''),
                    event.get('source', 'Unknown'),
                    event.get('event_type', 'Unknown'),
                    event.get('severity', 'Medium'),
                    event.get('description', 'No description available'),
                    event.get('ip_address', 'N/A')
                ))
                
        except Exception as e:
            logging.error(f"Error updating events: {e}")
    
    def _update_threat_intel(self):
        """Update the threat intelligence feed."""
        # Clear existing threat intel
        for item in self.threat_intel_tree.get_children():
            self.threat_intel_tree.delete(item)
        
        # This is a placeholder - replace with actual threat intel data
        threats = [
            {
                'source': 'CISA',
                'type': 'Vulnerability',
                'severity': 'High',
                'first_seen': (datetime.now() - timedelta(days=2)).strftime('%Y-%m-%d'),
                'description': 'CVE-2023-1234: Critical vulnerability in Apache Log4j'
            },
            {
                'source': 'MITRE',
                'type': 'TTP',
                'severity': 'Medium',
                'first_seen': (datetime.now() - timedelta(days=5)).strftime('%Y-%m-%d'),
                'description': 'T1190: Exploit Public-Facing Application'
            },
            {
                'source': 'AlienVault',
                'type': 'IOC',
                'severity': 'High',
                'first_seen': (datetime.now() - timedelta(hours=12)).strftime('%Y-%m-%d %H:%M'),
                'description': 'Malicious IP: 192.168.1.100 detected in network'
            }
        ]
        
        # Add threats to the treeview
        for threat in threats:
            self.threat_intel_tree.insert('', 'end', values=(
                threat['source'],
                threat['type'],
                threat['severity'],
                threat['first_seen'],
                threat['description']
            ))
    
    def _schedule_update(self, delay_ms):
        """Schedule the next view update."""
        if self._scheduled_update is not None:
            self.after_cancel(self._scheduled_update)
        self._scheduled_update = self.after(delay_ms, self.update_view)
    
    def _on_alert_double_click(self, event):
        """Handle double-click on an alert."""
        item = self.alerts_tree.selection()[0]
        alert_data = self.alerts_tree.item(item, 'values')
        self._show_alert_details(alert_data)
    
    def _on_event_double_click(self, event):
        """Handle double-click on an event."""
        item = self.events_tree.selection()[0]
        event_data = self.events_tree.item(item, 'values')
        self._show_event_details(event_data)
    
    def _show_alert_details(self, alert_data):
        """Show details for the selected alert."""
        # This would open a detailed view of the alert
        print(f"Showing details for alert: {alert_data}")
    
    def _show_event_details(self, event_data):
        """Show details for the selected event."""
        # This would open a detailed view of the event
        print(f"Showing details for event: {event_data}")
    
    def _show_settings(self):
        """Show the settings dialog."""
        # This would open a settings dialog
        print("Opening settings...")
    
    # Sample data methods - replace with actual data from your models
    def _get_sample_alerts(self):
        """Generate sample alert data for demonstration."""
        return [
            {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'severity': 'High',
                'source': 'EDR',
                'name': 'Suspicious Process Execution',
                'status': 'New'
            },
            {
                'time': (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'),
                'severity': 'Critical',
                'source': 'NIPS',
                'name': 'Port Scan Detected',
                'status': 'In Progress'
            },
            {
                'time': (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S'),
                'severity': 'Medium',
                'source': 'DLP',
                'name': 'Potential Data Leak',
                'status': 'New'
            }
        ]
    
    def _get_sample_events(self):
        """Generate sample event data for demonstration."""
        return [
            {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source': 'Firewall',
                'event_type': 'Connection Blocked',
                'severity': 'High',
                'description': 'Blocked connection to known malicious IP',
                'ip_address': '192.168.1.100'
            },
            {
                'timestamp': (datetime.now() - timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S'),
                'source': 'EDR',
                'event_type': 'Process Execution',
                'severity': 'Medium',
                'description': 'Suspicious process started: powershell.exe',
                'ip_address': '192.168.1.101'
            },
            {
                'timestamp': (datetime.now() - timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'),
                'source': 'Authentication',
                'event_type': 'Failed Login',
                'severity': 'Low',
                'description': 'Failed login attempt for user: admin',
                'ip_address': '192.168.1.102'
            }
        ]
    
    def cleanup(self):
        """Clean up resources used by the view."""
        # Cancel any pending updates
        if self._scheduled_update is not None:
            self.after_cancel(self._scheduled_update)
            self._scheduled_update = None
        
        # Clean up matplotlib figures
        for fig in self.figures:
            try:
                plt.close(fig)
            except Exception as e:
                logging.warning(f"Error closing figure: {e}")
        
        # Clear references
        self.figures.clear()
        self.canvases.clear()
        
        logging.info("SIEM view resources cleaned up")
