import tkinter as tk
from tkinter import ttk, font as tkfont
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
import psutil
import platform
import os
import logging
import random
from tkinter import messagebox

# Modern color scheme
COLORS = {
    'primary': '#1a237e',      # Deep Blue
    'primary_light': '#534bae',  # Lighter Blue
    'primary_dark': '#000051',   # Darker Blue
    'secondary': '#00897b',     # Teal
    'accent': '#ffab00',        # Amber
    'background': '#f5f5f5',    # Light Gray
    'surface': '#ffffff',       # White
    'error': '#d32f2f',         # Red
    'success': '#388e3c',       # Green
    'warning': '#f57c00',       # Orange
    'text_primary': '#212121',  # Dark Gray
    'text_secondary': '#757575',# Medium Gray
    'divider': '#e0e0e0',       # Light Gray
    'shadow': 'gainsboro',      # Shadow color
}

# Custom styles
class ModernStyle:
    @staticmethod
    def configure_styles():
        style = ttk.Style()
        
        # Configure the main frame style
        style.configure('TFrame', background=COLORS['background'])
        
        # Configure card style
        style.configure('Card.TFrame', 
                       background=COLORS['surface'],
                       borderwidth=0,
                       relief='flat')
        
        # Configure header labels
        style.configure('CardHeader.TLabel',
                      background=COLORS['surface'],
                      foreground=COLORS['primary'],
                      font=('Segoe UI', 10, 'bold'),
                      padding=(10, 10, 10, 5))
                      
        # Configure metric labels
        style.configure('Metric.TLabel',
                      background=COLORS['surface'],
                      foreground=COLORS['text_primary'],
                      font=('Segoe UI', 24, 'bold'),
                      padding=(10, 0, 10, 10))
                      
        # Configure status labels
        style.configure('Status.TLabel',
                      font=('Segoe UI', 9),
                      padding=(0, 2, 0, 2))
        
        # Configure button style
        style.configure('Accent.TButton',
                      background=COLORS['primary'],
                      foreground='white',
                      font=('Segoe UI', 9, 'bold'),
                      borderwidth=0,
                      padding=(12, 6))
        
        # Configure entry style
        style.configure('Modern.TEntry',
                      fieldbackground=COLORS['surface'],
                      foreground=COLORS['text_primary'],
                      borderwidth=1,
                      relief='solid',
                      padding=5)

# Initialize styles
ModernStyle.configure_styles()

def create_card(parent, title: str = None, padding: int = 10, **kwargs) -> ttk.Frame:
    """Create a modern card container with optional title and shadow."""
    # Create main card frame
    card = ttk.Frame(parent, style='Card.TFrame', **kwargs)
    
    # Add subtle shadow effect (simulated with borders)
    shadow = ttk.Frame(card, style='TFrame')
    shadow.grid(row=0, column=0, sticky='nsew', padx=1, pady=1, ipadx=1, ipady=1)
    
    # Content frame
    content = ttk.Frame(shadow, style='Card.TFrame')
    content.pack(fill='both', expand=True)
    
    # Add title if provided
    if title:
        header = ttk.Label(content, text=title.upper(), style='CardHeader.TLabel')
        header.pack(fill='x', pady=(0, 5))
        
        # Add divider
        ttk.Separator(content, orient='horizontal').pack(fill='x', padx=10)
    
    return content

class ServiceStatusWidget(ttk.Frame):
    """Modern widget to display the status of SIEM services with improved UI."""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.logger = logging.getLogger('siem.ui.service_status')
        
        # Configure grid
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        
        # Create card container
        self.card = create_card(self, title="Service Status")
        self.card.pack(fill='both', expand=True, padx=5, pady=5, ipadx=5, ipady=5)
        
        # Service status frame with scrollbar
        self.status_frame = ttk.Frame(self.card)
        self.status_frame.pack(fill='both', expand=True, padx=5, pady=(0, 5))
        
        # Initialize service status
        self.services = {
            'SIEM Core': {'status': 'stopped', 'last_check': None, 'icon': '🛡️'},
            'EDR': {'status': 'stopped', 'last_check': None, 'icon': '💻'},
            'NDR': {'status': 'stopped', 'last_check': None, 'icon': '🌐'},
            'DLP': {'status': 'stopped', 'last_check': None, 'icon': '🔒'},
            'FIM': {'status': 'stopped', 'last_check': None, 'icon': '📁'},
            'HIPS': {'status': 'stopped', 'last_check': None, 'icon': '🖥️'},
            'NIPS': {'status': 'stopped', 'last_check': None, 'icon': '🛡️'}
        }
        
        # Create status rows
        self.status_rows = {}
        for i, (service, data) in enumerate(self.services.items()):
            # Create row container
            row_frame = ttk.Frame(self.status_frame, style='Card.TFrame')
            row_frame.pack(fill='x', pady=2, padx=2)
            
            # Service icon and name
            icon_label = ttk.Label(
                row_frame,
                text=data['icon'],
                font=('Segoe UI Emoji', 12),
                background=COLORS['surface']
            )
            icon_label.pack(side='left', padx=(10, 5), pady=5)
            
            name_label = ttk.Label(
                row_frame, 
                text=service,
                font=('Segoe UI', 10, 'bold'),
                background=COLORS['surface'],
                foreground=COLORS['text_primary']
            )
            name_label.pack(side='left', padx=5, pady=5)
            
            # Status indicator with pill design
            status_frame = ttk.Frame(row_frame, style='Card.TFrame')
            status_frame.pack(side='right', padx=10, pady=5)
            
            status_indicator = ttk.Label(
                status_frame,
                text=data['status'].upper(),
                foreground='white',
                background=COLORS['error'],
                font=('Segoe UI', 8, 'bold'),
                padding=(8, 2),
                borderwidth=0,
                relief='flat'
            )
            status_indicator.pack(side='left')
            
            # Last check time
            time_label = ttk.Label(
                status_frame,
                text='Never',
                font=('Segoe UI', 8),
                foreground=COLORS['text_secondary'],
                background=COLORS['surface']
            )
            time_label.pack(side='left', padx=(8, 0))
            
            # Store references
            self.status_rows[service] = {
                'status': status_indicator,
                'time': time_label,
                'row': row_frame
            }
    
    def update_status(self, service_name: str, status: str, last_check: Optional[datetime] = None):
        """Update the status of a service with visual feedback.
        
        Args:
            service_name: Name of the service to update
            status: New status (running, stopped, error, warning)
            last_check: When the status was last checked
        """
        if service_name not in self.services:
            self.logger.warning(f"Unknown service: {service_name}")
            return
            
        # Update status with timestamp
        now = datetime.now()
        self.services[service_name]['status'] = status
        self.services[service_name]['last_check'] = last_check or now
        
        # Get UI elements
        status_label = self.status_rows[service_name]['status']
        time_label = self.status_rows[service_name]['time']
        
        # Set status colors and text
        status = status.lower()
        status_colors = {
            'running': COLORS['success'],
            'stopped': COLORS['error'],
            'error': COLORS['error'],
            'warning': COLORS['warning'],
            'starting': COLORS['accent'],
            'stopping': COLORS['warning']
        }
        
        # Update status indicator
        bg_color = status_colors.get(status, COLORS['text_secondary'])
        status_label.config(
            text=status.upper(),
            background=bg_color,
            foreground='white' if status != 'warning' else COLORS['text_primary']
        )
        
        # Update timestamp
        time_str = 'Just now' if (now - (last_check or now)).total_seconds() < 60 else \
                 f"{(now - (last_check or now)).seconds // 60}m ago"
        time_label.config(text=time_str)
        
        # Add visual feedback for status changes
        if status == 'running':
            self._animate_status_change(service_name, bg_color)
            
    def _animate_status_change(self, service_name: str, color: str):
        """Add a subtle animation when status changes."""
        row = self.status_rows[service_name]['row']
        original_bg = row.cget('style')
        
        def reset():
            row.configure(style='Card.TFrame')
            
        # Flash the row background
        row.configure(style='Card.TFrame' if original_bg == 'Card.TFrame' else 'Card.TFrame')
        row.after(100, reset)
        
        # Set status color
        if status.lower() == 'running':
            status_label.config(foreground='green')
        elif status.lower() == 'error':
            status_label.config(foreground='orange')
        else:
            status_label.config(foreground='red')
            
        # Update status text
        status_label.config(text=status.upper())
        
        # Update last check time
        if last_check:
            time_label.config(text=last_check.strftime('%H:%M:%S'))
    
    def update_all_services(self, services_status: Dict[str, Dict[str, str]]):
        """Update status for multiple services at once.
        
        Args:
            services_status: Dictionary mapping service names to status dictionaries
        """
        if not hasattr(self, 'status_labels') or not self.status_labels:
            self.logger.warning("Status labels not initialized")
            return
            
        try:
            for service_name, status_data in services_status.items():
                if service_name in self.status_labels:
                    self.update_status(
                        service_name=service_name,
                        status=status_data.get('status', 'stopped'),
                        last_check=status_data.get('last_check')
                    )
                else:
                    self.logger.warning(f"Unknown service: {service_name}")
        except Exception as e:
            self.logger.error(f"Error updating service statuses: {e}", exc_info=True)
    
    def cleanup(self):
        """Clean up resources used by the widget."""
        try:
            # Clear all status labels
            if hasattr(self, 'status_labels'):
                for service_name, labels in self.status_labels.items():
                    if 'status' in labels:
                        labels['status'].destroy()
                    if 'time' in labels:
                        labels['time'].destroy()
                self.status_labels.clear()
            
            # Clear the status frame
            if hasattr(self, 'status_frame'):
                for widget in self.status_frame.winfo_children():
                    try:
                        widget.destroy()
                    except Exception as e:
                        self.logger.warning(f"Error destroying widget: {e}")
            
            self.logger.info("ServiceStatusWidget resources cleaned up")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}", exc_info=True)

class DashboardView:
    """Modern dashboard view with improved UI components and visual hierarchy."""
    
    def __init__(self, parent, event_model, rule_model, service_manager=None):
        """Initialize the dashboard view with modern styling."""
        self.event_model = event_model
        self.rule_model = rule_model
        self.service_manager = service_manager
        self.last_update = None
        self.is_updating = False
        self._scheduled_update = None
        
        # Initialize system status variables
        self.cpu_var = tk.StringVar(value="0%")
        self.mem_var = tk.StringVar(value="0%")
        self.disk_var = tk.StringVar(value="0%")
        self.network_var = tk.StringVar(value="0 KB/s")
        
        # Initialize the last check time
        self._last_service_check = datetime.now()
        self._last_network_check = (0, 0)  # (bytes_sent, bytes_recv)
        
        # Default service list with icons
        self.service_list = [
            ('SIEM Core', '🛡️'), 
            ('EDR', '💻'), 
            ('NDR', '🌐'), 
            ('DLP', '🔒'),
            ('FIM', '📁'),
            ('HIPS', '🖥️'),
            ('NIPS', '🛡️')
        ]
        
        # Main container with modern styling
        self.frame = ttk.Frame(parent, style='TFrame')
        self.frame.pack(fill='both', expand=True)
        
        # Service status tracking with more detailed info
        self.service_status = {
            'SIEM Core': {
                'status': 'running', 
                'last_check': datetime.now(),
                'uptime': '0d 0h 0m',
                'version': '1.0.0',
                'resources': 'Normal'
            },
            'EDR': {
                'status': 'stopped', 
                'last_check': None,
                'endpoints': 0,
                'threats_blocked': 0,
                'version': '1.0.0'
            },
            'NDR': {
                'status': 'stopped', 
                'last_check': None,
                'alerts': 0,
                'threats_blocked': 0,
                'version': '1.0.0'
            },
            'DLP': {
                'status': 'stopped', 
                'last_check': None,
                'incidents': 0,
                'policies': 0,
                'version': '1.0.0'
            },
            'FIM': {
                'status': 'stopped', 
                'last_check': None,
                'monitored': 0,
                'changes': 0,
                'version': '1.0.0'
            },
            'HIPS': {
                'status': 'stopped', 
                'last_check': None,
                'endpoints': 0,
                'threats_blocked': 0,
                'version': '1.0.0'
            },
            'NIPS': {
                'status': 'stopped', 
                'last_check': None,
                'alerts': 0,
                'threats_blocked': 0,
                'version': '1.0.0'
            }
        }
        
        # Initialize matplotlib figures
        self.figures = []
        self.canvases = []
        
        self._create_widgets()
        
        # Initialize with empty data
        self._init_empty_charts()
        
        # Schedule the first update
        self._schedule_update(100)
    
    def _create_timeline_chart(self, parent):
        """Create event timeline chart with modern styling"""
        # Create a frame to hold the chart
        chart_frame = ttk.Frame(parent)
        chart_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a figure and axis for the timeline chart
        self.timeline_fig, self.timeline_ax = plt.subplots(figsize=(8, 4), dpi=100)
        self.timeline_fig.patch.set_facecolor('#ffffff')
        self.timeline_ax.set_facecolor('#ffffff')
        
        # Customize the chart appearance
        self.timeline_ax.spines['top'].set_visible(False)
        self.timeline_ax.spines['right'].set_visible(False)
        self.timeline_ax.spines['left'].set_color('#d1d5db')
        self.timeline_ax.spines['bottom'].set_color('#d1d5db')
        
        # Set up the canvas for embedding in Tkinter
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=chart_frame)
        self.timeline_canvas.draw()
        self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add a placeholder text
        self.timeline_ax.text(0.5, 0.5, 'Loading event data...', 
                             ha='center', va='center',
                             transform=self.timeline_ax.transAxes,
                             color='#6c757d')
        
        return chart_frame
        
    def _update_timeline_chart(self, start_time, end_time):
        """Update the timeline chart with event counts over time
        
        Args:
            start_time: Start time for the timeline
            end_time: End time for the timeline
        """
        try:
            # Get hourly event counts
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                    COUNT(*) as count
                FROM events
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY hour
                ORDER BY hour
            """
            
            with self.event_model.db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(query, (start_time, end_time))
                data = cursor.fetchall()
            
            if not data:
                self.timeline_ax.clear()
                self.timeline_ax.text(0.5, 0.5, 'No data available', 
                                      ha='center', va='center')
                self.timeline_canvas.draw()
                return
            
            # Prepare data for plotting
            hours = [row[0] for row in data]
            counts = [row[1] for row in data]
            
            # Clear previous chart
            self.timeline_ax.clear()
            
            # Create bar chart
            x = range(len(hours))
            bars = self.timeline_ax.bar(x, counts, color='#4e73df', width=0.6)
            
            # Format x-axis
            if len(hours) > 1:
                step = max(1, len(hours) // 6)  # Show ~6 labels
                self.timeline_ax.set_xticks(x[::step])
                self.timeline_ax.set_xticklabels(
                    [datetime.strptime(h, '%Y-%m-%d %H:%M:%S').strftime('%H:%M') 
                     for h in hours[::step]],
                    rotation=45,
                    ha='right'
                )
            
            # Add labels and title
            self.timeline_ax.set_title('Events Timeline (Last 24h)', fontsize=10, pad=10)
            self.timeline_ax.set_ylabel('Event Count')
            
            # Add grid
            self.timeline_ax.grid(True, linestyle='--', alpha=0.6)
            
            # Adjust layout to prevent label cutoff
            self.timeline_fig.tight_layout()
            
            # Update the canvas
            self.timeline_canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating timeline chart: {e}")
            self.timeline_ax.clear()
            self.timeline_ax.text(0.5, 0.5, 'Error loading data', 
                                  ha='center', va='center',
                                  color='#dc3545')
            self.timeline_canvas.draw()
    
    def _create_widgets(self):
        """Create and layout all dashboard widgets with modern styling."""
        # Configure grid weights for main container
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)
        
        # Create main container with scrollbar
        main_container = ttk.Frame(self.frame, style='TFrame')
        main_container.pack(fill='both', expand=True)
        
        # Add canvas and scrollbar
        canvas = tk.Canvas(main_container, bg=COLORS['background'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(main_container, orient='vertical', command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame')
        
        # Configure canvas scrolling
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        # Create window in canvas for the scrollable frame
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack the canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Configure grid for scrollable frame
        scrollable_frame.columnconfigure(0, weight=1)
        
        # Add padding to the scrollable frame
        container = ttk.Frame(scrollable_frame, padding=15)
        container.pack(fill='both', expand=True)
        
        # Header section
        self._create_header(container)
        
        # Stats cards row
        self._create_stats_row(container)
        
        # Main content area
        content_frame = ttk.Frame(container, style='TFrame')
        content_frame.pack(fill='both', expand=True, pady=(15, 0))
        
        # Left column: Service Status and System Metrics
        left_column = ttk.Frame(content_frame, style='TFrame')
        left_column.pack(side='left', fill='both', expand=False, padx=(0, 10))
        
        # Right column: Alerts and Events
        right_column = ttk.Frame(content_frame, style='TFrame')
        right_column.pack(side='right', fill='both', expand=True)
        
        # Create service status widget
        self.service_widget = ServiceStatusWidget(left_column)
        self.service_widget.pack(fill='x', pady=(0, 15))
        
        # Create system metrics widget
        self._create_system_metrics(left_column)
        
        # Create alerts section
        self._create_alerts_section(right_column)
        
        # Create events section
        self._create_events_section(right_column)
        
        # Footer
        self._create_footer(container)
        
        # Configure mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        # Bind mousewheel for Windows and MacOS
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
        canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        
        # Initial update of all widgets
        self.update_dashboard()
    
    def _create_header(self, parent):
        """Create the dashboard header with title and controls."""
        header = ttk.Frame(parent, style='TFrame')
        header.pack(fill='x', pady=(0, 20))
        
        # Title and subtitle
        title_frame = ttk.Frame(header, style='TFrame')
        title_frame.pack(side='left')
        
        ttk.Label(
            title_frame, 
            text="SECURITY DASHBOARD", 
            font=('Segoe UI', 16, 'bold'),
            foreground=COLORS['primary'],
            background=COLORS['background']
        ).pack(anchor='w')
        
        ttk.Label(
            title_frame,
            text="Real-time security monitoring and alerting",
            font=('Segoe UI', 9),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        ).pack(anchor='w')
        
        # Controls frame
        controls_frame = ttk.Frame(header, style='TFrame')
        controls_frame.pack(side='right')
        
        # Refresh button
        refresh_btn = ttk.Button(
            controls_frame,
            text="🔄 Refresh",
            style='Accent.TButton',
            command=self.update_dashboard
        )
        refresh_btn.pack(side='left', padx=5)
        
        # Settings button
        settings_btn = ttk.Button(
            controls_frame,
            text="⚙️ Settings",
            style='Accent.TButton'
        )
        settings_btn.pack(side='left', padx=5)
    
    def _create_stats_row(self, parent):
        """Create the stats cards row with system metrics."""
        stats_frame = ttk.Frame(parent, style='TFrame')
        stats_frame.pack(fill='x', pady=(0, 20))
        
        # CPU Usage Card
        cpu_card = create_card(stats_frame, title="CPU Usage")
        cpu_card.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        ttk.Label(
            cpu_card, 
            textvariable=self.cpu_var, 
            style='Metric.TLabel'
        ).pack(pady=10)
        
        # Memory Usage Card
        mem_card = create_card(stats_frame, title="Memory Usage")
        mem_card.pack(side='left', fill='both', expand=True, padx=5)
        
        ttk.Label(
            mem_card, 
            textvariable=self.mem_var, 
            style='Metric.TLabel'
        ).pack(pady=10)
        
        # Disk Usage Card
        disk_card = create_card(stats_frame, title="Disk Usage")
        disk_card.pack(side='left', fill='both', expand=True, padx=5)
        
        ttk.Label(
            disk_card, 
            textvariable=self.disk_var, 
            style='Metric.TLabel'
        ).pack(pady=10)
        
        # Network Activity Card
        net_card = create_card(stats_frame, title="Network Activity")
        net_card.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        ttk.Label(
            net_card, 
            textvariable=self.network_var, 
            style='Metric.TLabel',
            font=('Segoe UI', 18, 'bold')
        ).pack(pady=10)
    
    def _create_system_metrics(self, parent):
        """Create the system metrics section."""
        metrics_card = create_card(parent, title="System Metrics")
        metrics_card.pack(fill='both', expand=True)
        
        # Add metrics visualization (placeholder)
        ttk.Label(
            metrics_card,
            text="CPU, Memory, and Network Graphs",
            font=('Segoe UI', 9),
            foreground=COLORS['text_secondary'],
            background=COLORS['surface']
        ).pack(pady=40)
    
    def _create_alerts_section(self, parent):
        """Create the alerts section with a table."""
        alerts_card = create_card(parent, title="Recent Alerts")
        alerts_card.pack(fill='both', expand=True, pady=(0, 15))
        
        # Create treeview for alerts
        columns = ('time', 'severity', 'source', 'message')
        self.alerts_tree = ttk.Treeview(
            alerts_card,
            columns=columns,
            show='headings',
            selectmode='browse',
            style='Treeview'
        )
        
        # Configure columns
        self.alerts_tree.heading('time', text='Time')
        self.alerts_tree.heading('severity', text='Severity')
        self.alerts_tree.heading('source', text='Source')
        self.alerts_tree.heading('message', text='Message')
        
        # Set column widths
        self.alerts_tree.column('time', width=120, anchor='w')
        self.alerts_tree.column('severity', width=100, anchor='w')
        self.alerts_tree.column('source', width=120, anchor='w')
        self.alerts_tree.column('message', width=300, anchor='w')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(alerts_card, orient='vertical', command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.alerts_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Configure tags for severity colors
        self.alerts_tree.tag_configure('critical', background='#ffebee')
        self.alerts_tree.tag_configure('high', background='#fff3e0')
        self.alerts_tree.tag_configure('medium', background='#fff8e1')
    
    def _create_events_section(self, parent):
        """Create the events section with a table."""
        events_card = create_card(parent, title="Recent Events")
        events_card.pack(fill='both', expand=True)
        
        # Create treeview for events
        columns = ('time', 'source', 'type', 'severity', 'message')
        self.events_tree = ttk.Treeview(
            events_card,
            columns=columns,
            show='headings',
            selectmode='browse',
            style='Treeview'
        )
        
        # Configure columns
        self.events_tree.heading('time', text='Time')
        self.events_tree.heading('source', text='Source')
        self.events_tree.heading('type', text='Type')
        self.events_tree.heading('severity', text='Severity')
        self.events_tree.heading('message', text='Message')
        
        # Set column widths
        self.events_tree.column('time', width=100, anchor='w')
        self.events_tree.column('source', width=120, anchor='w')
        self.events_tree.column('type', width=100, anchor='w')
        self.events_tree.column('severity', width=80, anchor='w')
        self.events_tree.column('message', width=300, anchor='w')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(events_card, orient='vertical', command=self.events_tree.yview)
        self.events_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack the treeview and scrollbar
        self.events_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Configure tags for severity colors
        self.events_tree.tag_configure('critical', background='#ffebee')
        self.events_tree.tag_configure('warning', background='#fff3e0')
        self.events_tree.tag_configure('info', background='#e8f5e9')
    
    def _create_footer(self, parent):
        """Create the dashboard footer."""
        footer = ttk.Frame(parent, style='TFrame')
        footer.pack(fill='x', pady=(20, 0))
        
        # Last updated time
        self.last_updated = ttk.Label(
            footer,
            text="Last updated: Never",
            font=('Segoe UI', 8),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        )
        self.last_updated.pack(side='left')
        
        # Version info
        version = ttk.Label(
            footer,
            text=f"SIEM Dashboard v1.0.0",
            font=('Segoe UI', 8),
            foreground=COLORS['text_secondary'],
            background=COLORS['background']
        )
        version.pack(side='right')
        top_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Left side: Stats cards (3/4 width)
        stats_frame = ttk.Frame(top_frame)
        stats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Stats cards with improved styling
        self._create_stat_card(stats_frame, "Total Events", "0", 0, '#4e73df')
        self._create_stat_card(stats_frame, "Critical", "0", 1, '#e74a3b')
        self._create_stat_card(stats_frame, "Warnings", "0", 2, '#f6c23e')
        self._create_stat_card(stats_frame, "Sources", "0", 3, '#1cc88a')
        
        # Right side: Service Status (1/4 width)
        status_frame = ttk.LabelFrame(top_frame, text="Service Status", padding=10, style='Card.TFrame')
        status_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(10, 0), ipady=5)
        
        # Add service status widget
        self.service_status_widget = ServiceStatusWidget(status_frame, style='Card.TFrame')
        self.service_status_widget.pack(fill=tk.BOTH, expand=True)
        
        # Initial service status update
        self.update_service_status()
        
        # Middle row: Charts - using grid for better layout
        middle_frame = ttk.Frame(container)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Left column: Timeline chart (2/3 width)
        left_frame = ttk.Frame(middle_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Timeline chart with card style
        timeline_card = ttk.Frame(left_frame, style='Card.TFrame', padding=5)
        timeline_card.pack(fill=tk.BOTH, expand=True)
        ttk.Label(timeline_card, text="EVENT TIMELINE (24H)", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_timeline_chart(timeline_card)
        
        # Right column: Two smaller cards stacked vertically
        right_frame = ttk.Frame(middle_frame, width=300)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))
        
        # Severity distribution card
        severity_card = ttk.Frame(right_frame, style='Card.TFrame', padding=5)
        severity_card.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(severity_card, text="SEVERITY DISTRIBUTION", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_severity_chart(severity_card)
        
        # System status card
        status_card = ttk.Frame(right_frame, style='Card.TFrame', padding=5)
        status_card.pack(fill=tk.X, pady=(0, 15))
        ttk.Label(status_card, text="SYSTEM STATUS", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_system_status(status_card)
        
        # Bottom row: Top sources and recent alerts
        bottom_frame = ttk.Frame(container)
        bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top sources card (left)
        self.sources_card = ttk.Frame(bottom_frame, style='Card.TFrame', padding=5)
        self.sources_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        ttk.Label(self.sources_card, text="TOP EVENT SOURCES", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_top_sources_chart(self.sources_card)
        
        # Recent alerts card (right)
        alerts_card = ttk.Frame(bottom_frame, style='Card.TFrame', padding=5)
        alerts_card.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        ttk.Label(alerts_card, text="RECENT ALERTS", style='CardHeader.TLabel').pack(anchor='w', pady=(0, 10))
        self._create_recent_alerts(alerts_card)
    
    def _create_severity_chart(self, parent):
        """Create severity distribution donut chart with modern styling"""
        # Create figure with custom style
        self.severity_fig = Figure(figsize=(6, 3), dpi=100, facecolor='#ffffff')
        self.severity_ax = self.severity_fig.add_subplot(111)
        
        # Configure plot style
        self.severity_ax.set_facecolor('#f8f9fc')
        self.severity_fig.set_facecolor('#ffffff')
        
        # Remove axis
        self.severity_ax.axis('equal')
        
        # Adjust layout
        self.severity_fig.subplots_adjust(
            left=0.1, 
            right=0.9, 
            top=0.9, 
            bottom=0.1
        )
        
        # Create canvas
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=parent)
        self.severity_canvas.draw()
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _update_severity_chart(self, severity_data):
        """Update the severity distribution chart with real data
        
        Args:
            severity_data: Tuple containing (critical, warning, info, total) counts
        """
        try:
            if not severity_data or len(severity_data) < 4:
                return
                
            critical, warning, info, _ = severity_data
            
            # Clear previous chart
            self.severity_ax.clear()
            
            # Create data for pie chart
            labels = ['Critical', 'Warning', 'Info']
            sizes = [critical, warning, info]
            colors = ['#dc3545', '#ffc107', '#17a2b8']
            
            # Only show non-zero values
            data = [(label, size) for label, size in zip(labels, sizes) if size > 0]
            
            if not data:
                self.severity_ax.text(0.5, 0.5, 'No data available', 
                                      ha='center', va='center')
                self.severity_canvas.draw()
                return
                
            labels, sizes = zip(*data)
            
            # Create pie chart
            wedges, texts, autotexts = self.severity_ax.pie(
                sizes, 
                labels=labels, 
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                wedgeprops=dict(width=0.4, edgecolor='w'),
                textprops={'fontsize': 9}
            )
            
            # Equal aspect ratio ensures that pie is drawn as a circle
            self.severity_ax.axis('equal')
            self.severity_ax.set_title('Event Severity Distribution', fontsize=10, pad=10)
            
            # Update the canvas
            self.severity_canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating severity chart: {e}")
            self.severity_ax.clear()
            self.severity_ax.text(0.5, 0.5, 'Error loading data', 
                                  ha='center', va='center',
                                  color='#dc3545')
            self.severity_canvas.draw()
    
    def _create_top_sources_chart(self, parent):
        """Create top sources bar chart"""
        frame = ttk.LabelFrame(parent, text="Top Event Sources", padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        self.sources_fig = Figure(figsize=(6, 3), dpi=100)
        self.sources_ax = self.sources_fig.add_subplot(111)
        self.sources_fig.subplots_adjust(left=0.15, right=0.95, top=0.9, bottom=0.2)
        
        self.sources_canvas = FigureCanvasTkAgg(self.sources_fig, master=frame)
        self.sources_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def _update_top_sources_chart(self, sources_data):
        """Update the top sources chart with real data
        
        Args:
            sources_data: List of tuples containing (source, count)
        """
        try:
            if not sources_data:
                self.sources_ax.clear()
                self.sources_ax.text(0.5, 0.5, 'No data available', 
                                     ha='center', va='center')
                self.sources_canvas.draw()
                return
            
            # Prepare data for plotting
            sources = [row[0] for row in sources_data]
            counts = [row[1] for row in sources_data]
            
            # Clear previous chart
            self.sources_ax.clear()
            
            # Create horizontal bar chart
            y_pos = range(len(sources))
            colors = ['#4e73df' for _ in sources]  # Blue bars
            
            # Make the bar chart horizontal
            bars = self.sources_ax.barh(y_pos, counts, color=colors, height=0.6)
            
            # Add value labels on the bars
            for i, (count, bar) in enumerate(zip(counts, bars.patches)):
                width = bar.get_width()
                self.sources_ax.text(
                    width + (0.05 * max(counts)),  # Position text just after the bar
                    bar.get_y() + bar.get_height()/2,
                    f' {count:,}',
                    va='center',
                    fontsize=9
                )
            
            # Set y-ticks and labels
            self.sources_ax.set_yticks(y_pos)
            self.sources_ax.set_yticklabels(sources)
            
            # Add title and labels
            self.sources_ax.set_title('Top Event Sources', fontsize=10, pad=10)
            self.sources_ax.set_xlabel('Event Count')
            
            # Remove top and right spines
            for spine in ['top', 'right']:
                self.sources_ax.spines[spine].set_visible(False)
            
            # Add grid
            self.sources_ax.grid(True, linestyle='--', alpha=0.3, axis='x')
            
            # Adjust layout
            self.sources_fig.tight_layout()
            
            # Update the canvas
            self.sources_canvas.draw()
            
        except Exception as e:
            logger.error(f"Error updating sources chart: {e}")
            self.sources_ax.clear()
            self.sources_ax.text(0.5, 0.5, 'Error loading data', 
                                 ha='center', va='center',
                                 color='#dc3545')
            self.sources_canvas.draw()
    
    def _update_dashboard(self):
        """Update the dashboard with the latest data from the database"""
        try:
            # Get event statistics from the last 24 hours
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)
            
            # Get event counts by severity
            severity_query = """
                SELECT 
                    COUNT(CASE WHEN severity >= 4 THEN 1 END) as critical,
                    COUNT(CASE WHEN severity = 3 THEN 1 END) as warning,
                    COUNT(CASE WHEN severity <= 2 THEN 1 END) as info,
                    COUNT(*) as total
                FROM events
                WHERE timestamp BETWEEN ? AND ?
            """
            
            # Get top event sources
            sources_query = """
                SELECT source, COUNT(*) as count
                FROM events
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY source
                ORDER BY count DESC
                LIMIT 5
            """
            
            # Get recent events with all details
            events_query = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M:%S', timestamp) as timestamp,
                    source,
                    event_type,
                    severity,
                    description,
                    ip_address
                FROM events
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
                LIMIT 15
            """
            
            # Execute queries
            with self.event_model.db.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get severity stats
                cursor.execute(severity_query, (start_time, end_time))
                severity_data = cursor.fetchone()
                
                # Get top sources
                cursor.execute(sources_query, (start_time, end_time))
                sources_data = cursor.fetchall()
                
                # Get recent events
                cursor.execute(events_query, (start_time, end_time))
                events_data = cursor.fetchall()
            
            # Update stats cards with real data
            if severity_data:
                critical, warning, info, total = severity_data
                self.events_var.set(f"{total:,}")
                self.alerts_var.set(f"{warning + critical:,}")
                self.threats_var.set(f"{critical:,}")
                
                # Update system health based on critical events
                if critical > 10:
                    self.health_var.set("At Risk")
                    self.health_status.config(background='#ff5252', foreground='white')
                elif critical > 0:
                    self.health_var.set("Warning")
                    self.health_status.config(background='#ffc107', foreground='black')
                else:
                    self.health_var.set("Good")
                    self.health_status.config(background='#4caf50', foreground='white')
            
            # Update events table
            if events_data:
                self._update_events_table(events_data)
            
            # Update charts with real data
            self._update_severity_chart(severity_data)
            self._update_timeline_chart(start_time, end_time)
            self._update_top_sources_chart(sources_data)
            
            # Update last updated time
            self.last_update = datetime.now()
            self.last_updated_var.set(f"Last updated: {self.last_update.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Schedule next update
            self.frame.after(5000, self.update_dashboard)
            
        except Exception as e:
            logger.error(f"Error updating dashboard: {e}", exc_info=True)
            self.status_var.set(f"Error: {str(e)}")
            # Retry after error
            self.frame.after(10000, self.update_dashboard)
    
    def _update_events_table(self, events):
        """Update the events table with the latest events"""
        # Clear existing rows
        for row in self.events_tree.get_children():
            self.events_tree.delete(row)
        
        # Add new rows with proper formatting
        for event in events:
            try:
                # Extract values from the database row
                timestamp = event[0] if len(event) > 0 else 'N/A'
                source = event[1] if len(event) > 1 else 'Unknown'
                event_type = event[2] if len(event) > 2 else 'Unknown'
                severity = event[3] if len(event) > 3 else 0
                description = event[4] if len(event) > 4 else 'No description'
                ip_address = event[5] if len(event) > 5 else 'N/A'
                
                # Truncate long descriptions
                if len(description) > 100:
                    description = description[:97] + '...'
                
                # Add row to treeview
                item_id = self.events_tree.insert('', 'end', values=(
                    timestamp,
                    source,
                    event_type,
                    severity,
                    description,
                    ip_address
                ))
                
                # Color code by severity
                if severity >= 4:  # Critical
                    self.events_tree.item(item_id, tags=('critical',))
                elif severity == 3:  # Warning
                    self.events_tree.item(item_id, tags=('warning',))
                    
            except Exception as e:
                logger.error(f"Error adding event to table: {e}")
                continue
    
    def update_dashboard(self):
        """Update the dashboard with fresh data."""
        if not self.is_visible or self.is_updating:
            return
            
        try:
            self.is_updating = True
            self.last_update = datetime.now()
            
            # Update system metrics
            self._update_system_metrics()
            
            # Check service status every 30 seconds
            current_time = datetime.now()
            if (current_time - self._last_service_check).total_seconds() >= 30:
                self._check_services_status()
                self._last_service_check = current_time
            
            # Update service status display
            self.update_service_status()
            
            # Update charts
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=24)  # Last 24 hours
            
            try:
                self._update_timeline_chart(start_time, end_time)
                self._update_event_types_chart(start_time, end_time)
                self._update_alerts_table()
            except Exception as e:
                logging.error(f"Error updating charts: {e}", exc_info=True)
            
            # Update window title with timestamp
            try:
                window = self.frame.winfo_toplevel()
                if window:
                    window.title(f"SIEM Dashboard - Last updated: {datetime.now().strftime('%H:%M:%S')}")
            except Exception as e:
                logging.warning(f"Could not update window title: {e}")
            
        except Exception as e:
            logging.error(f"Error updating dashboard: {e}", exc_info=True)
        finally:
            self.is_updating = False
            # Schedule the next update if still visible
            if self.is_visible:
                self._schedule_update(5000)  # Update every 5 seconds
            
    def update_service_status(self):
        """Update the status display of all SIEM services."""
        try:
            # Get current service status
            service_statuses = self._check_services_status()
            
            # Update the service status widget if it exists
            if hasattr(self, 'service_status_widget') and service_statuses:
                self.service_status_widget.update_all_services(service_statuses)
            
            # Update the local service status
            self.service_status.update(service_statuses)
            
            return True
            
        except Exception as e:
            logging.error(f"Error updating service status display: {e}", exc_info=True)
            return False
            
    def _schedule_update(self, delay_ms):
        """Schedule the next dashboard update."""
        if self._scheduled_update is not None:
            self.frame.after_cancel(self._scheduled_update)
        self._scheduled_update = self.frame.after(delay_ms, self.update_dashboard)
    
    def cleanup(self):
        """Clean up resources used by the dashboard."""
        self.is_visible = False
        
        # Cancel any pending updates
        if self._scheduled_update is not None:
            self.frame.after_cancel(self._scheduled_update)
            self._scheduled_update = None
        
        # Clean up matplotlib figures
        for fig in self.figures:
            try:
                plt.close(fig)
            except Exception as e:
                logging.warning(f"Error closing figure: {e}")
        
        # Clear references to figures and canvases
        self.figures.clear()
        self.canvases.clear()
        
        # Clear any other resources
        if hasattr(self, 'service_status_widget'):
            if hasattr(self.service_status_widget, 'cleanup'):
                self.service_status_widget.cleanup()
        
        logging.info("Dashboard resources cleaned up")
    
    def _check_services_status(self):
        """Check the status of all services and update the service_status dictionary."""
        try:
            now = datetime.now()
            service_statuses = {}
            
            if self.service_manager:
                # Get status from service manager if available
                for service_name in self.service_list:
                    try:
                        status = self.service_manager.get_service_status(service_name)
                        if status is not None:
                            service_statuses[service_name] = {
                                'status': status.get('status', 'stopped'),
                                'last_check': now
                            }
                    except Exception as e:
                        logging.error(f"Error getting status for {service_name}: {e}")
                        service_statuses[service_name] = {
                            'status': 'error',
                            'last_check': now,
                            'error': str(e)
                        }
            
            # Fallback to simulated status if no service manager or service not found
            for service_name in self.service_list:
                if service_name not in service_statuses:
                    if service_name == 'SIEM Core':
                        status = 'running'
                    elif random.random() < 0.1:  # 10% chance to change status
                        status = random.choice(['running', 'stopped', 'error'])
                    else:
                        status = self.service_status.get(service_name, {}).get('status', 'stopped')
                    
                    service_statuses[service_name] = {
                        'status': status,
                        'last_check': now
                    }
            
            # Update the service status widget if it exists
            if hasattr(self, 'service_status_widget'):
                try:
                    self.service_status_widget.update_all_services(service_statuses)
                except Exception as e:
                    logging.error(f"Error updating service status widget: {e}")
            
            # Update the local service status
            self.service_status = service_statuses
            
            return service_statuses
            
        except Exception as e:
            logging.error(f"Error checking service status: {e}", exc_info=True)
            return {}