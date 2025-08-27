"""
Network Detection and Response (NDR) GUI

Provides a graphical interface for monitoring and responding to network threats.
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import logging
from datetime import datetime
from typing import List, Dict, Any

# Local imports
from ndr.models.flow import NetworkFlow
from ndr.models.alert import NetworkAlert, AlertSeverity
from ndr.collector import NetworkCollector
from ndr.analyzer import TrafficAnalyzer

class NDREvent:
    """Container for NDR events and updates."""
    def __init__(self, event_type: str, data: Any):
        self.event_type = event_type
        self.data = data
        self.timestamp = datetime.now()

class NDRGUI:
    """Main NDR GUI application."""
    def __init__(self, root):
        self.root = root
        self.root.title("Network Detection & Response")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Initialize components
        self.flow_collector = NetworkCollector()
        self.traffic_analyzer = TrafficAnalyzer()
        
        # Event queue for thread-safe UI updates
        self.event_queue = queue.Queue()
        
        # Data storage
        self.flows: List[NetworkFlow] = []
        self.alerts: List[NetworkAlert] = []
        self.flow_stats = {
            'total_flows': 0,
            'total_bytes': 0,
            'alerts_count': 0,
            'top_protocol': 'N/A'
        }
        
        # Setup logging
        self.setup_logging()
        
        # Setup UI
        self.setup_ui()
        
        # Start background tasks
        self.running = True
        self.start_background_tasks()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_logging(self):
        """Configure logging for the NDR GUI."""
        self.logger = logging.getLogger('NDR_GUI')
        self.logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        import os
        os.makedirs('logs', exist_ok=True)
        
        # File handler
        fh = logging.FileHandler('logs/ndr_gui.log')
        fh.setLevel(logging.DEBUG)
        
        # Console handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        
        # Add handlers
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Main container
        main_container = ttk.Frame(self.root, padding="5")
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_flows_tab()
        self.setup_alerts_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab with overview metrics."""
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.dashboard_tab, text="Network Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Stats display
        self.stats_vars = {
            'total_flows': tk.StringVar(value="0"),
            'total_bytes': tk.StringVar(value="0 B"),
            'alerts_count': tk.StringVar(value="0"),
            'top_protocol': tk.StringVar(value="N/A")
        }
        
        # Layout stats
        ttk.Label(stats_frame, text="Total Flows:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.stats_vars['total_flows']).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(stats_frame, text="Total Data:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.stats_vars['total_bytes']).grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(stats_frame, text="Active Alerts:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.stats_vars['alerts_count'], foreground="red").grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(stats_frame, text="Top Protocol:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, textvariable=self.stats_vars['top_protocol']).grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
    
    def setup_flows_tab(self):
        """Setup the network flows tab."""
        self.flows_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.flows_tab, text="Network Flows")
        
        # Search frame
        search_frame = ttk.Frame(self.flows_tab)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.flow_filter_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.flow_filter_var, width=50)
        search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        search_entry.bind("<Return>", lambda e: self.filter_flows())
        
        # Flows treeview
        columns = ("Time", "Source IP", "Source Port", "→", "Destination IP", "Destination Port", "Protocol", "Bytes")
        self.flows_tree = ttk.Treeview(
            self.flows_tab, 
            columns=columns, 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Time": 140, "Source IP": 120, "Source Port": 80, "→": 20, 
            "Destination IP": 120, "Destination Port": 80, "Protocol": 80,
            "Bytes": 100
        }
        
        for col in columns:
            self.flows_tree.heading(col, text=col)
            self.flows_tree.column(col, width=col_widths.get(col, 100), anchor=tk.CENTER)
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.flows_tab, orient="vertical", command=self.flows_tree.yview)
        hsb = ttk.Scrollbar(self.flows_tab, orient="horizontal", command=self.flows_tree.xview)
        self.flows_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.flows_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_alerts_tab(self):
        """Setup the alerts tab."""
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        
        # Alerts treeview
        columns = ("Time", "Severity", "Source IP", "Destination IP", "Protocol", "Description")
        self.alerts_tree = ttk.Treeview(
            self.alerts_tab, 
            columns=columns, 
            show="headings",
            selectmode="extended"
        )
        
        # Configure columns
        col_widths = {
            "Time": 140, "Severity": 80, "Source IP": 120, 
            "Destination IP": 120, "Protocol": 80, "Description": 250
        }
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbars
        vsb = ttk.Scrollbar(self.alerts_tab, orient="vertical", command=self.alerts_tree.yview)
        hsb = ttk.Scrollbar(self.alerts_tab, orient="horizontal", command=self.alerts_tree.xview)
        self.alerts_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
    
    def start_background_tasks(self):
        """Start background tasks for data collection and analysis."""
        # Start flow collection
        self.flow_thread = threading.Thread(target=self.collect_flows, daemon=True)
        self.flow_thread.start()
        
        # Start analysis thread
        self.analysis_thread = threading.Thread(target=self.analyze_flows, daemon=True)
        self.analysis_thread.start()
        
        # Start UI update loop
        self.update_ui()
    
    def collect_flows(self):
        """Collect network flows in a background thread."""
        try:
            # Start the collector
            self.flow_collector.start()
            
            while self.running:
                # Get recent flows from the collector
                flows = self.flow_collector.get_recent_flows()
                for flow in flows:
                    if not self.running:
                        break
                    self.event_queue.put(NDREvent("new_flow", flow))
                # Sleep briefly to prevent high CPU usage
                import time
                time.sleep(1)
        except Exception as e:
            self.logger.error(f"Error in flow collection: {e}")
            self.event_queue.put(NDREvent("error", f"Flow collection error: {e}"))
    
    def analyze_flows(self):
        """Analyze network flows for threats in a background thread."""
        try:
            while self.running:
                # Get recent flows and analyze them
                flows = self.flow_collector.get_recent_flows()
                alerts = self.traffic_analyzer.analyze_flows(flows)
                for alert in alerts:
                    if not self.running:
                        break
                    self.event_queue.put(NDREvent("new_alert", alert))
                # Sleep briefly to prevent high CPU usage
                import time
                time.sleep(1)
        except Exception as e:
            self.logger.error(f"Error in flow analysis: {e}")
            self.event_queue.put(NDREvent("error", f"Analysis error: {e}"))
    
    def update_ui(self):
        """Process events from the queue and update the UI."""
        try:
            while True:
                try:
                    event = self.event_queue.get_nowait()
                    self.process_event(event)
                except queue.Empty:
                    break
            
            # Update stats
            self.update_stats()
            
            # Schedule next update
            if self.running:
                self.root.after(1000, self.update_ui)
                
        except Exception as e:
            self.logger.error(f"Error in UI update: {e}")
            if self.running:
                self.root.after(1000, self.update_ui)
    
    def process_event(self, event: NDREvent):
        """Process a single event from the queue."""
        try:
            if event.event_type == "new_flow":
                self.handle_new_flow(event.data)
            elif event.event_type == "new_alert":
                self.handle_new_alert(event.data)
            elif event.event_type == "error":
                self.handle_error(event.data)
        except Exception as e:
            self.logger.error(f"Error processing event: {e}")
    
    def handle_new_flow(self, flow: dict):
        """Handle a new network flow."""
        self.flows.append(flow)
        self.flow_stats['total_flows'] += 1
        self.flow_stats['total_bytes'] += flow.get('bytes', 0)
        
        # Update flows tree
        self.update_flows_tree()
    
    def handle_new_alert(self, alert: dict):
        """Handle a new alert."""
        self.alerts.append(alert)
        self.flow_stats['alerts_count'] += 1
        
        # Update alerts tree
        self.update_alerts_tree()
        
        # Show notification for high severity alerts
        if alert.get('severity') in ['HIGH', 'CRITICAL']:
            self.show_alert_notification(alert)
    
    def handle_error(self, error_msg: str):
        """Handle an error message."""
        self.logger.error(error_msg)
        self.update_status(f"Error: {error_msg}")
    
    def update_stats(self):
        """Update the statistics display."""
        self.stats_vars['total_flows'].set(f"{self.flow_stats['total_flows']:,}")
        self.stats_vars['total_bytes'].set(f"{self.flow_stats['total_bytes']:,} B")
        self.stats_vars['alerts_count'].set(f"{self.flow_stats['alerts_count']:,}")
        
        # Update top protocol
        if self.flows:
            protocols = {}
            for flow in self.flows[-100:]:  # Last 100 flows
                proto = flow.get('protocol', 'unknown')
                protocols[proto] = protocols.get(proto, 0) + 1
            
            if protocols:
                top_proto = max(protocols.items(), key=lambda x: x[1])[0]
                self.stats_vars['top_protocol'].set(top_proto)
    
    def update_flows_tree(self):
        """Update the flows treeview with current flow data."""
        # Clear existing items
        for item in self.flows_tree.get_children():
            self.flows_tree.delete(item)
        
        # Add flows (show most recent first)
        for flow in reversed(self.flows[-1000:]):  # Show last 1000 flows
            timestamp = flow.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except (ValueError, TypeError):
                    timestamp = datetime.now()
            
            self.flows_tree.insert("", "end", values=(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                flow.get('src_ip', ''),
                flow.get('src_port', ''),
                "→",
                flow.get('dst_ip', ''),
                flow.get('dst_port', ''),
                flow.get('protocol', 'unknown'),
                f"{flow.get('bytes', 0):,} B"
            ))
    
    def update_alerts_tree(self):
        """Update the alerts treeview with current alert data."""
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Add alerts (show most recent first)
        for alert in reversed(self.alerts[-1000:]):  # Show last 1000 alerts
            timestamp = alert.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except (ValueError, TypeError):
                    timestamp = datetime.now()
            
            severity = alert.get('severity', 'INFO')
            description = alert.get('description', '')
            
            self.alerts_tree.insert("", "end", values=(
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                severity,
                alert.get('source_ip', ''),
                alert.get('destination_ip', ''),
                alert.get('protocol', ''),
                (description[:97] + '...') if len(description) > 100 else description
            ), tags=(severity.lower(),))
        
        # Configure tag colors
        self.alerts_tree.tag_configure('critical', background='#ffcccc')
        self.alerts_tree.tag_configure('high', background='#ffe6cc')
        self.alerts_tree.tag_configure('medium', background='#ffffcc')
        self.alerts_tree.tag_configure('low', background='#e6f3ff')
        self.alerts_tree.tag_configure('info', background='#f0f0f0')
    
    def show_alert_notification(self, alert: dict):
        """Show a notification for a new alert."""
        notification = tk.Toplevel(self.root)
        notification.title(f"{alert.get('severity', 'ALERT')}: {alert.get('title', 'New Alert')}")
        notification.geometry("500x200")
        notification.transient(self.root)
        notification.grab_set()
        
        # Add content
        ttk.Label(notification, text=alert.get('title', 'New Alert'), font=('Arial', 12, 'bold')).pack(pady=5)
        ttk.Label(notification, text=f"Severity: {alert.get('severity', 'UNKNOWN')}", 
                 foreground="red" if alert.get('severity') in ['HIGH', 'CRITICAL'] else "black").pack()
        ttk.Label(notification, text=f"Source: {alert.get('source_ip', 'N/A')}").pack()
        ttk.Label(notification, text=f"Destination: {alert.get('destination_ip', 'N/A')}").pack()
        ttk.Label(notification, text=alert.get('description', 'No description available'), 
                 wraplength=480).pack(expand=True, fill='both', padx=10, pady=5)
        
        # Add close button
        ttk.Button(notification, text="Dismiss", command=notification.destroy).pack(pady=10)
    
    def update_status(self, message: str):
        """Update the status bar with a message."""
        self.status_var.set(message)
        self.logger.info(f"Status: {message}")
    
    def filter_flows(self):
        """Filter flows based on search criteria."""
        filter_text = self.flow_filter_var.get().lower()
        if not filter_text:
            self.update_flows_tree()
            return
        
        # Filter flows
        filtered_flows = [
            flow for flow in self.flows[-1000:]
            if (filter_text in flow.src_ip.lower() or 
                filter_text in flow.dst_ip.lower() or
                (flow.src_port and filter_text in str(flow.src_port)) or
                (flow.dst_port and filter_text in str(flow.dst_port)) or
                (hasattr(flow.protocol, 'name') and filter_text in flow.protocol.name.lower()) or
                (isinstance(flow.protocol, str) and filter_text in flow.protocol.lower()))
        ]
        
        # Update tree with filtered results
        for item in self.flows_tree.get_children():
            self.flows_tree.delete(item)
        
        for flow in reversed(filtered_flows):
            self.flows_tree.insert("", "end", values=(
                flow.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                flow.src_ip,
                flow.src_port if flow.src_port else "",
                "→",
                flow.dst_ip,
                flow.dst_port if flow.dst_port else "",
                flow.protocol.name if hasattr(flow.protocol, 'name') else str(flow.protocol),
                f"{flow.bytes_sent + flow.bytes_received:,} B"
            ))
    
    def on_closing(self):
        """Handle window close event."""
        self.running = False
        self.root.destroy()

def main():
    """Main entry point for the NDR GUI application."""
    root = tk.Tk()
    app = NDRGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
