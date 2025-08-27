"""
SIEM GUI Module

A self-contained graphical interface for the Security Information and Event Management system.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
from datetime import datetime
import json
import os
import sys
from typing import Dict, Any, List, Optional
import threading
import queue

# Set up basic logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_gui.log')
    ]
)
logger = logging.getLogger('siem.gui')

# Simple SIEM core implementation
class SIEMCore:
    """Simplified SIEM core for the GUI."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize the SIEM core with optional configuration."""
        self.config = config or {}
        self.running = False
        self.events = []
        self.alerts = []
        
    def get_next_event(self) -> Optional[Dict[str, Any]]:
        """Get the next event (simulated for demo)."""
        if not self.running:
            return None
            
        # Simulate receiving an event
        event = {
            'timestamp': datetime.now().isoformat(),
            'source': 'simulator',
            'type': 'network',
            'details': 'Sample network event',
            'severity': 'info'
        }
        self.events.append(event)
        return event
        
    def start(self):
        """Start the SIEM core."""
        self.running = True
        logger.info("SIEM core started")
        
    def stop(self):
        """Stop the SIEM core."""
        self.running = False
        logger.info("SIEM core stopped")

# Simple Detection Engine
class DetectionEngine:
    """Simplified detection engine for the GUI."""
    
    def analyze(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze an event and return any generated alerts."""
        alerts = []
        
        # Simple detection logic (example)
        if 'error' in str(event.get('details', '')).lower():
            alert = {
                'timestamp': datetime.now().isoformat(),
                'source': 'detection_engine',
                'severity': 'high',
                'message': f'Error detected: {event.get("details", "")}'
            }
            alerts.append(alert)
            
        return alerts

class SIEMApp:
    """Main SIEM GUI application."""
    
    def __init__(self, root):
        """Initialize the SIEM GUI."""
        self.root = root
        self.root.title("Security Information and Event Management")
        self.root.geometry("1400x900")
        self.root.minsize(1200, 700)
        
        # Initialize SIEM components
        self.siem_core = SIEMCore()
        self.detection_engine = DetectionEngine()
        self.historical_analyzer = HistoricalAnalyzer()
        
        # Data storage
        self.alerts = []
        self.events = []
        self.monitoring = False
        
        # Setup logging
        self.setup_logging()
        
        # Setup UI
        self.setup_ui()
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_logging(self):
        """Configure logging for the SIEM GUI."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='siem_gui.log'
        )
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_alerts_tab()
        self.setup_events_tab()
        self.setup_detection_tab()
        self.setup_logs_tab()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(
            self.main_frame, 
            textvariable=self.status_var,
            relief=tk.SUNKEN, 
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.update_status("Ready")
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab."""
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Dashboard layout
        top_frame = ttk.Frame(self.dashboard_tab)
        top_frame.pack(fill=tk.X, pady=5)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(top_frame, text="Security Metrics", padding=10)
        stats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Stats widgets
        ttk.Label(stats_frame, text="Alerts (24h):").pack(anchor=tk.W)
        self.alert_count = ttk.Label(stats_frame, text="0", font=('Arial', 16, 'bold'))
        self.alert_count.pack(anchor=tk.W)
        
        ttk.Label(stats_frame, text="Events (24h):").pack(anchor=tk.W)
        self.event_count = ttk.Label(stats_frame, text="0", font=('Arial', 16, 'bold'))
        self.event_count.pack(anchor=tk.W)
        
        # Controls frame
        ctrl_frame = ttk.LabelFrame(top_frame, text="Controls", padding=10)
        ctrl_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Control buttons
        self.monitor_btn = ttk.Button(
            ctrl_frame, 
            text="Start Monitoring", 
            command=self.toggle_monitoring
        )
        self.monitor_btn.pack(fill=tk.X, pady=2)
        
        ttk.Button(
            ctrl_frame, 
            text="Export Alerts", 
            command=self.export_alerts
        ).pack(fill=tk.X, pady=2)
        
        # Alerts preview
        alerts_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alerts table
        columns = ("timestamp", "severity", "source", "message")
        self.alerts_table = ttk.Treeview(
            alerts_frame, 
            columns=columns, 
            show="headings",
            selectmode="browse"
        )
        
        # Configure columns
        self.alerts_table.heading("timestamp", text="Timestamp")
        self.alerts_table.heading("severity", text="Severity")
        self.alerts_table.heading("source", text="Source")
        self.alerts_table.heading("message", text="Message")
        
        # Set column widths
        self.alerts_table.column("timestamp", width=150)
        self.alerts_table.column("severity", width=80)
        self.alerts_table.column("source", width=120)
        self.alerts_table.column("message", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_table.yview)
        self.alerts_table.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_table.pack(fill=tk.BOTH, expand=True)
        
        # Double-click event for alert details
        self.alerts_table.bind("<Double-1>", self.show_alert_details)
    
    def setup_alerts_tab(self):
        """Setup the alerts management tab."""
        self.alerts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="Alerts")
        
        # Add alerts management UI here
        ttk.Label(self.alerts_tab, text="Alerts Management").pack(pady=20)
    
    def setup_events_tab(self):
        """Setup the events viewer tab."""
        self.events_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.events_tab, text="Events")
        
        # Add events viewer UI here
        ttk.Label(self.events_tab, text="Security Events").pack(pady=20)
    
    def setup_detection_tab(self):
        """Setup the detection rules tab."""
        self.detection_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detection_tab, text="Detection Rules")
        
        # Add detection rules UI here
        ttk.Label(self.detection_tab, text="Detection Rules Management").pack(pady=20)
    
    def setup_logs_tab(self):
        """Setup the logs viewer tab."""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Logs text widget with scrollbar
        log_frame = ttk.Frame(self.logs_tab)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = tk.Text(
            log_frame, 
            wrap=tk.WORD, 
            bg='black', 
            fg='white',
            font=('Consolas', 10)
        )
        
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout to log window
        import sys
        sys.stdout = TextRedirector(self.log_text, "stdout")
        sys.stderr = TextRedirector(self.log_text, "stderr")
    
    def toggle_monitoring(self):
        """Toggle monitoring on/off."""
        if not self.monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start monitoring for security events."""
        self.monitoring = True
        self.monitor_btn.config(text="Stop Monitoring")
        self.update_status("Monitoring started...")
        logger.info("SIEM monitoring started")
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.run_monitoring, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring for security events."""
        self.monitoring = False
        self.monitor_btn.config(text="Start Monitoring")
        self.update_status("Monitoring stopped")
        logger.info("SIEM monitoring stopped")
    
    def run_monitoring(self):
        """Run the monitoring loop in a separate thread."""
        try:
            # TODO: Implement actual monitoring logic
            while self.monitoring:
                # Simulate receiving events
                event = self.siem_core.get_next_event()
                if event:
                    self.process_event(event)
                
                # Small delay to prevent high CPU usage
                import time
                time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Error in monitoring thread: {e}")
            self.update_status(f"Error: {str(e)}")
    
    def process_event(self, event):
        """Process a security event."""
        try:
            # Add to events list
            self.events.append(event)
            
            # Run detection
            alerts = self.detection_engine.analyze(event)
            
            # Process any generated alerts
            for alert in alerts:
                self.process_alert(alert)
                
            # Update UI
            self.update_event_count()
            
        except Exception as e:
            logger.error(f"Error processing event: {e}")
    
    def process_alert(self, alert):
        """Process a security alert."""
        try:
            # Add to alerts list
            self.alerts.append(alert)
            
            # Update UI
            self.update_alerts_table(alert)
            self.update_alert_count()
            
            # Log the alert
            logger.warning(f"ALERT: {alert.get('message', 'No message')}")
            
            # Show notification for high severity alerts
            if alert.get('severity', 'low').lower() in ['high', 'critical']:
                self.show_alert_notification(alert)
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def update_alerts_table(self, alert):
        """Update the alerts table with a new alert."""
        # This method runs in a background thread, so we need to use after()
        def _update():
            # Limit number of displayed alerts
            if self.alerts_table.get_children() > 1000:
                self.alerts_table.delete(*self.alerts_table.get_children()[-100:])
            
            # Add new alert to the top
            self.alerts_table.insert(
                "", 0, 
                values=(
                    alert.get('timestamp', ''),
                    alert.get('severity', 'info').upper(),
                    alert.get('source', 'N/A'),
                    alert.get('message', 'No message')
                ),
                tags=(alert.get('severity', 'info'),)
            )
            
            # Configure tag colors
            self.alerts_table.tag_configure('critical', background='#ff6b6b', foreground='white')
            self.alerts_table.tag_configure('high', background='#ffa07a', foreground='black')
            self.alerts_table.tag_configure('medium', background='#ffd700', foreground='black')
            self.alerts_table.tag_configure('low', background='#98fb98', foreground='black')
            self.alerts_table.tag_configure('info', background='#e6e6fa', foreground='black')
        
        # Schedule the update on the main thread
        self.root.after(0, _update)
    
    def show_alert_details(self, event):
        """Show details for the selected alert."""
        selected = self.alerts_table.selection()
        if not selected:
            return
            
        # Get the alert details
        item = self.alerts_table.item(selected[0])
        alert_details = dict(zip(
            [col for col in self.alerts_table['columns']],
            item['values']
        ))
        
        # Create a dialog to show details
        details_win = tk.Toplevel(self.root)
        details_win.title("Alert Details")
        details_win.geometry("800x600")
        
        # Add a text widget to show the full alert details
        text = tk.Text(details_win, wrap=tk.WORD, font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format the alert details as JSON
        try:
            import json
            text.insert(tk.END, json.dumps(alert_details, indent=2))
        except:
            text.insert(tk.END, str(alert_details))
        
        text.config(state=tk.DISABLED)
        
        # Add a close button
        btn_frame = ttk.Frame(details_win)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="Close", 
            command=details_win.destroy
        ).pack(side=tk.RIGHT)
    
    def show_alert_notification(self, alert):
        """Show a notification for a high-priority alert."""
        def _show():
            messagebox.showwarning(
                f"{alert.get('severity', 'Alert').upper()} Alert",
                alert.get('message', 'A security alert has been triggered.')
            )
        self.root.after(0, _show)
    
    def export_alerts(self):
        """Export alerts to a file."""
        if not self.alerts:
            messagebox.showinfo("No Alerts", "There are no alerts to export.")
            return
        
        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Alerts As"
        )
        
        if not filename:
            return  # User cancelled
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            
            self.update_status(f"Alerts exported to {filename}")
            logger.info(f"Exported {len(self.alerts)} alerts to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export alerts: {e}")
            logger.error(f"Export failed: {e}")
    
    def update_status(self, message: str):
        """Update the status bar."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_var.set(f"{timestamp} | {message}")
    
    def update_alert_count(self):
        """Update the alert count display."""
        def _update():
            self.alert_count.config(text=str(len(self.alerts)))
        self.root.after(0, _update)
    
    def update_event_count(self):
        """Update the event count display."""
        def _update():
            self.event_count.config(text=str(len(self.events)))
        self.root.after(0, _update)
    
    def on_closing(self):
        """Handle window close event."""
        # Stop any running monitoring
        if hasattr(self, 'monitoring') and self.monitoring:
            self.stop_monitoring()
        
        # Close the application
        self.root.quit()


class TextRedirector:
    """Redirects stdout/stderr to a Tkinter Text widget."""
    def __init__(self, widget, tag="stdout"):
        self.widget = widget
        self.tag = tag
    
    def write(self, str):
        self.widget.configure(state=tk.NORMAL)
        self.widget.insert(tk.END, str, (self.tag,))
        self.widget.see(tk.END)
        self.widget.configure(state=tk.DISABLED)
    
    def flush(self):
        pass


def main():
    """Main entry point for the SIEM GUI application."""
    try:
        # Create the main window
        root = tk.Tk()
        
        # Set the application icon if available
        try:
            # Replace with your icon file if available
            # root.iconbitmap("siem_icon.ico")
            pass
        except:
            pass
        
        # Create and run the application
        app = SIEMApp(root)
        root.mainloop()
        
        return 0
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        messagebox.showerror("Fatal Error", f"The application encountered a fatal error:\n{str(e)}")
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
