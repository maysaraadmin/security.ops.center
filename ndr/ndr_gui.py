
"""
Network Detection and Response (NDR) GUI

Provides a graphical interface for monitoring and responding to network threats.
"""
import asyncio
import logging
import os
import queue
import sys
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                            QLabel, QLineEdit, QTreeWidget, QTreeWidgetItem, QHeaderView, QPushButton,
                            QStatusBar, QMessageBox, QSplitter, QGroupBox, QFormLayout, QComboBox, QMenu)
from PyQt5.QtCore import Qt, QTimer, QSize, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QColor, QFont, QPalette

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import flow collector and analyzer
from ndr.collectors.netflow_collector import NetFlowCollector
from ndr.analyzers.traffic_analyzer import TrafficAnalyzer

# Local imports
from ndr.models.flow import NetworkFlow
from ndr.models.alert import NetworkAlert, AlertSeverity

class WorkerSignals(QObject):
    """Defines the signals available from a running worker thread."""
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)


class FlowCollectorWorker(QThread):
    """Worker thread for collecting network flows."""
    flow_collected = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    
    def __init__(self, flow_collector):
        super().__init__()
        self.flow_collector = flow_collector
        self.running = False
    
    def start(self):
        """Start the worker thread."""
        self.running = True
        self.flow_collector.start()
    
    def stop(self):
        """Stop the worker thread."""
        self.running = False
        if hasattr(self.flow_collector, 'stop'):
            if asyncio.iscoroutinefunction(self.flow_collector.stop):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(self.flow_collector.stop())
                loop.close()
            else:
                self.flow_collector.stop()
    
    def run(self):
        """Main worker loop."""
        try:
            while self.running:
                try:
                    # Get new flows from collector
                    flows = self.flow_collector.get_recent_flows()
                    for flow in flows:
                        if not self.running:
                            break
                        self.flow_collected.emit(flow)
                    
                    # Small delay to prevent high CPU usage
                    QApplication.processEvents()
                    QThread.msleep(100)
                    
                except Exception as e:
                    self.error_occurred.emit(f"Error in flow collection: {e}")
                    break
        except Exception as e:
            self.error_occurred.emit(f"Fatal error in flow collector: {e}")


class TrafficAnalyzerWorker(QThread):
    """Worker thread for analyzing network traffic."""
    alert_detected = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, flow_collector, traffic_analyzer):
        super().__init__()
        self.flow_collector = flow_collector
        self.traffic_analyzer = traffic_analyzer
        self.running = False
    
    def start(self):
        """Start the worker thread."""
        self.running = True
    
    def stop(self):
        """Stop the worker thread."""
        self.running = False
    
    def run(self):
        """Main worker loop."""
        try:
            while self.running:
                try:
                    # Get recent flows and analyze them
                    flows = self.flow_collector.get_recent_flows()
                    alerts = self.traffic_analyzer.analyze_flows(flows)
                    
                    # Emit alerts
                    for alert in alerts:
                        if not self.running:
                            break
                        self.alert_detected.emit(alert)
                    
                    # Small delay to prevent high CPU usage
                    QApplication.processEvents()
                    QThread.msleep(1000)  # Analyze every second
                    
                except Exception as e:
                    self.error_occurred.emit(f"Error in traffic analysis: {e}")
                    break
        except Exception as e:
            self.error_occurred.emit(f"Fatal error in traffic analyzer: {e}")


class NDRGUI(QMainWindow):
    """Main NDR GUI application using PyQt5."""
    
    def __init__(self):
        super().__init__()
        
        # Initialize components
        self.flow_collector = None
        self.traffic_analyzer = None
        self.flow_worker = None
        self.analysis_worker = None
        self.flow_thread = None
        self.analysis_thread = None
        
        try:
            # Initialize with default configuration
            self.flow_collector = NetFlowCollector()
            self.traffic_analyzer = TrafficAnalyzer()
        except Exception as e:
            print(f"Error initializing components: {e}", file=sys.stderr)
            self.flow_collector = None
            self.traffic_analyzer = None
        
        # Event queue for thread-safe UI updates
        self.event_queue = queue.Queue()
        
        # Data storage
        self.flows: List[dict] = []
        self.alerts: List[dict] = []
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
        
        # Set window properties
        self.setWindowTitle("Network Detection & Response")
        self.setMinimumSize(1000, 600)
        self.resize(1200, 800)
        
        # Center the window
        self.center_window()
        
        # Setup timer for UI updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)  # Update UI every second
    
    def center_window(self):
        """Center the window on the screen."""
        frame_geometry = self.frameGeometry()
        center_point = QApplication.desktop().availableGeometry().center()
        frame_geometry.moveCenter(center_point)
        self.move(frame_geometry.topLeft())
    
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
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.setup_dashboard_tab()
        self.setup_flows_tab()
        self.setup_alerts_tab()
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.update_status("Ready")
        
        # Set style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QTabWidget::pane {
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                margin: 0px;
                padding: 0px;
            }
            QTabBar::tab {
                background: #e0e0e0;
                border: 1px solid #c4c4c4;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 100px;
                padding: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #f0f0f0;
                border-bottom: 1px solid #f0f0f0;
                margin-bottom: -1px;
            }
            QTreeWidget {
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                background: white;
                alternate-background-color: #f8f8f8;
            }
            QTreeWidget::item:selected {
                background: #4a90e2;
                color: white;
            }
            QGroupBox {
                border: 1px solid #c4c4c4;
                border-radius: 4px;
                margin-top: 1em;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
        """)
    
    def setup_dashboard_tab(self):
        """Setup the dashboard tab with overview metrics."""
        self.dashboard_tab = QWidget()
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
        
        # Main layout
        layout = QVBoxLayout(self.dashboard_tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        
        # Stats group box
        stats_group = QGroupBox("Network Statistics")
        stats_layout = QFormLayout()
        stats_group.setLayout(stats_layout)
        
        # Stats display
        self.stats_vars = {
            'total_flows': QLabel("0"),
            'total_bytes': QLabel("0 B"),
            'alerts_count': QLabel("0"),
            'top_protocol': QLabel("N/A")
        }
        
        # Set alert count to red
        self.stats_vars['alerts_count'].setStyleSheet("color: red;")
        
        # Add stats to layout
        stats_layout.addRow("Total Flows:", self.stats_vars['total_flows'])
        stats_layout.addRow("Total Data:", self.stats_vars['total_bytes'])
        stats_layout.addRow("Active Alerts:", self.stats_vars['alerts_count'])
        stats_layout.addRow("Top Protocol:", self.stats_vars['top_protocol'])
        
        # Add stats group to main layout
        layout.addWidget(stats_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
    
    def setup_flows_tab(self):
        """Setup the network flows tab."""
        self.flows_tab = QWidget()
        self.tab_widget.addTab(self.flows_tab, "Network Flows")
        
        # Main layout
        layout = QVBoxLayout(self.flows_tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Search frame
        search_frame = QHBoxLayout()
        layout.addLayout(search_frame)
        
        search_label = QLabel("Filter:")
        search_frame.addWidget(search_label)
        
        self.flow_filter_edit = QLineEdit()
        self.flow_filter_edit.setPlaceholderText("Filter flows...")
        self.flow_filter_edit.returnPressed.connect(self.filter_flows)
        search_frame.addWidget(self.flow_filter_edit)
        
        # Flows treeview
        self.flows_tree = QTreeWidget()
        self.flows_tree.setAlternatingRowColors(True)
        self.flows_tree.setSelectionBehavior(QTreeWidget.SelectRows)
        self.flows_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.flows_tree.setSortingEnabled(True)
        self.flows_tree.setAnimated(True)
        
        # Set up columns
        columns = ["Time", "Source IP", "Source Port", "→", "Destination IP", "Destination Port", "Protocol", "Bytes"]
        self.flows_tree.setHeaderLabels(columns)
        self.flows_tree.setColumnCount(len(columns))
        
        # Set column widths
        col_widths = {
            0: 140,   # Time
            1: 120,   # Source IP
            2: 80,    # Source Port
            3: 20,    # Arrow
            4: 120,   # Destination IP
            5: 80,    # Destination Port
            6: 80,    # Protocol
            7: 100    # Bytes
        }
        
        for col, width in col_widths.items():
            self.flows_tree.setColumnWidth(col, width)
        
        # Add to layout
        layout.addWidget(self.flows_tree)
    
    def setup_alerts_tab(self):
        """Setup the alerts tab."""
        self.alerts_tab = QWidget()
        self.tab_widget.addTab(self.alerts_tab, "Alerts")
        
        # Main layout
        layout = QVBoxLayout(self.alerts_tab)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Alerts treeview
        self.alerts_tree = QTreeWidget()
        self.alerts_tree.setAlternatingRowColors(True)
        self.alerts_tree.setSelectionBehavior(QTreeWidget.SelectRows)
        self.alerts_tree.setSelectionMode(QTreeWidget.ExtendedSelection)
        self.alerts_tree.setSortingEnabled(True)
        self.alerts_tree.setAnimated(True)
        
        # Set up columns
        columns = ["Time", "Severity", "Source IP", "Destination IP", "Protocol", "Description"]
        self.alerts_tree.setHeaderLabels(columns)
        self.alerts_tree.setColumnCount(len(columns))
        
        # Set column widths
        col_widths = {
            0: 140,   # Time
            1: 80,    # Severity
            2: 120,   # Source IP
            3: 120,   # Destination IP
            4: 80,    # Protocol
            5: 250    # Description
        }
        
        for col, width in col_widths.items():
            self.alerts_tree.setColumnWidth(col, width)
        
        # Add to layout
        layout.addWidget(self.alerts_tree)
        
        # Context menu for alerts
        self.alerts_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.alerts_tree.customContextMenuRequested.connect(self.show_alert_context_menu)
    
    def start_background_tasks(self):
        """Start background tasks for data collection and analysis."""
        try:
            if not self.flow_collector or not self.traffic_analyzer:
                print("Error: Flow collector or traffic analyzer not initialized", file=sys.stderr)
                return
                
            print("Starting background tasks...")
            
            # Start flow collection worker
            self.flow_worker = FlowCollectorWorker(self.flow_collector)
            self.flow_worker.flow_collected.connect(self.handle_new_flow)
            self.flow_worker.error_occurred.connect(self.handle_error)
            
            # Start traffic analysis worker
            self.analysis_worker = TrafficAnalyzerWorker(self.flow_collector, self.traffic_analyzer)
            self.analysis_worker.alert_detected.connect(self.handle_new_alert)
            self.analysis_worker.error_occurred.connect(self.handle_error)
            
            # Start the worker threads
            self.flow_thread = QThread()
            self.analysis_thread = QThread()
            
            self.flow_worker.moveToThread(self.flow_thread)
            self.analysis_worker.moveToThread(self.analysis_thread)
            
            self.flow_thread.started.connect(self.flow_worker.run)
            self.analysis_thread.started.connect(self.analysis_worker.run)
            
            # Start the threads
            self.flow_thread.start()
            self.analysis_thread.start()
            
            # Start the update timer
            if hasattr(self, 'update_timer'):
                self.update_timer.start(1000)  # Update every second
            else:
                print("Warning: Update timer not initialized")
            
            print("Background tasks started successfully")
            
        except Exception as e:
            error_msg = f"Failed to start background tasks: {str(e)}"
            print(error_msg, file=sys.stderr)
            self.handle_error(error_msg)
    
    def update_ui(self):
        """Update the UI with the latest data."""
        try:
            # Update stats
            self.update_stats()
            
            # Update flows tree
            self.update_flows_tree()
            
            # Update alerts tree
            self.update_alerts_tree()
            
        except Exception as e:
            self.logger.error(f"Error in UI update: {e}")
    
    def handle_new_flow(self, flow: dict):
        """Handle a new network flow."""
        try:
            self.flows.append(flow)
            self.flow_stats['total_flows'] += 1
            self.flow_stats['total_bytes'] += flow.get('bytes', 0)
            
            # Keep only the most recent flows (for performance)
            if len(self.flows) > 1000:
                self.flows = self.flows[-1000:]
                
            # Update the UI
            self.update_flows_tree()
            
        except Exception as e:
            self.logger.error(f"Error handling new flow: {e}")
            self.handle_error(f"Failed to process flow: {e}")
    
    def handle_new_alert(self, alert: dict):
        """Handle a new alert."""
        try:
            self.alerts.append(alert)
            self.flow_stats['alerts_count'] += 1
            
            # Update the UI
            self.update_alerts_tree()
            
            # Show notification for high severity alerts
            if alert.get('severity') in ['HIGH', 'CRITICAL']:
                self.show_alert_notification(alert)
                
        except Exception as e:
            self.logger.error(f"Error handling new alert: {e}")
            self.handle_error(f"Failed to process alert: {e}")
    
    def handle_error(self, error_msg: str):
        """Handle an error message."""
        try:
            self.logger.error(error_msg)
            self.update_status(f"Error: {error_msg}")
            
            # Show error message to user
            QMessageBox.critical(self, "Error", error_msg)
            
        except Exception as e:
            # If there's an error in the error handler, just log it
            import traceback
            self.logger.error(f"Error in error handler: {e}\n{traceback.format_exc()}")


    def update_stats(self):
        """Update the statistics display."""
        self.stats_vars['total_flows'].setText(f"{self.flow_stats['total_flows']:,}")
        self.stats_vars['total_bytes'].setText(f"{self.flow_stats['total_bytes']:,} B")
        self.stats_vars['alerts_count'].setText(f"{self.flow_stats['alerts_count']:,}")
        
        # Update top protocol
        if self.flows:
            protocols = {}
            for flow in self.flows[-100:]:  # Last 100 flows
                proto = flow.get('protocol', 'unknown')
                protocols[proto] = protocols.get(proto, 0) + 1
            
            if protocols:
                top_proto = max(protocols.items(), key=lambda x: x[1])[0]
                self.stats_vars['top_protocol'].setText(top_proto)

    def update_flows_tree(self):
        """Update the flows treeview with current flow data."""
        # Block signals to prevent UI flickering
        self.flows_tree.blockSignals(True)
        self.flows_tree.setSortingEnabled(False)
        
        # Clear existing items
        self.flows_tree.clear()
        
        # Add flows (show most recent first)
        for flow in reversed(self.flows[-1000:]):  # Show last 1000 flows
            timestamp = flow.get('timestamp', datetime.now())
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp)
                except (ValueError, TypeError):
                    timestamp = datetime.now()
            
            item = QTreeWidgetItem([
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                flow.get('src_ip', ''),
                str(flow.get('src_port', '')),
                "→",
                flow.get('dst_ip', ''),
                str(flow.get('dst_port', '')),
                flow.get('protocol', 'unknown'),
                f"{flow.get('bytes', 0):,} B"
            ])
            
            # Set text alignment for numeric columns
            for i in [2, 5, 7]:  # Source Port, Destination Port, Bytes columns
                item.setTextAlignment(i, Qt.AlignRight | Qt.AlignVCenter)
            
            self.flows_tree.addTopLevelItem(item)
        
        # Re-enable sorting and signals
        self.flows_tree.setSortingEnabled(True)
        self.flows_tree.blockSignals(False)

    def update_alerts_tree(self):
        """Update the alerts treeview with current alert data."""
        # Block signals to prevent UI flickering
        self.alerts_tree.blockSignals(True)
        self.alerts_tree.setSortingEnabled(False)
        
        # Clear existing items
        self.alerts_tree.clear()
        
        # Define severity colors
        severity_colors = {
            'CRITICAL': QColor(255, 200, 200),  # Light red
            'HIGH': QColor(255, 220, 200),      # Light orange
            'MEDIUM': QColor(255, 240, 200),    # Light yellow
            'LOW': QColor(220, 230, 255),       # Light blue
            'INFO': QColor(230, 230, 230)       # Light gray
        }
        
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
            
            # Create the item
            item = QTreeWidgetItem([
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                severity,
                alert.get('source_ip', ''),
                alert.get('destination_ip', ''),
                alert.get('protocol', ''),
                (description[:97] + '...') if len(description) > 100 else description
            ])
            
            # Set background color based on severity
            bg_color = severity_colors.get(severity.upper(), QColor(255, 255, 255))
            for i in range(self.alerts_tree.columnCount()):
                item.setBackground(i, bg_color)
            
            # Make high severity items bold
            if severity in ['HIGH', 'CRITICAL']:
                font = item.font(0)
                font.setBold(True)
                for i in range(self.alerts_tree.columnCount()):
                    item.setFont(i, font)
            
            self.alerts_tree.addTopLevelItem(item)
        
        # Re-enable sorting and signals
        self.alerts_tree.setSortingEnabled(True)
        self.alerts_tree.blockSignals(False)

    def show_alert_notification(self, alert):
        """Show a notification for a new alert."""
        title = f"{alert.get('severity', 'ALERT')}: {alert.get('rule_name', 'New Alert')}"
        message = f"{alert.get('description', 'No description')}\n"
        message += f"Source: {alert.get('source_ip', 'Unknown')}\n"
        message += f"Destination: {alert.get('destination_ip', 'Unknown')}\n"
        message += f"Protocol: {alert.get('protocol', 'N/A')}"
        
        # Show a message box for critical alerts
        if alert.get('severity') in ['CRITICAL']:
            QMessageBox.warning(self, title, message)
        else:
            # For non-critical alerts, just log and update status
            self.logger.info(f"Alert: {title} - {message}")
            self.update_status(f"New {alert.get('severity', 'alert')} detected")

    def update_status(self, message, timeout=5000):
        """Update the status bar with a message."""
        self.status_bar.showMessage(message, timeout)
    
    def show_alert_context_menu(self, position):
        """Show context menu for alert items."""
        item = self.alerts_tree.itemAt(position)
        if not item:
            return
        
        # Create and show context menu
        menu = QMenu()
        view_details_action = menu.addAction("View Details")
        mark_resolved_action = menu.addAction("Mark as Resolved")
        export_action = menu.addAction("Export Alert")
        
        action = menu.exec_(self.alerts_tree.viewport().mapToGlobal(position))
        
        if action == view_details_action:
            self.view_alert_details(item)
        elif action == mark_resolved_action:
            self.mark_alert_resolved(item)
        elif action == export_action:
            self.export_alert(item)

    def view_alert_details(self, item):
        """Show detailed information about the selected alert."""
        # Get the alert data from the item
        alert_data = {
            'time': item.text(0),
            'severity': item.text(1),
            'source_ip': item.text(2),
            'destination_ip': item.text(3),
            'protocol': item.text(4),
            'description': item.text(5)
        }
        
        # Create a detailed message
        details = f"""
        <b>Time:</b> {alert_data['time']}<br>
        <b>Severity:</b> {alert_data['severity']}<br>
        <b>Source IP:</b> {alert_data['source_ip']}<br>
        <b>Destination IP:</b> {alert_data['destination_ip']}<br>
        <b>Protocol:</b> {alert_data['protocol']}<br>
        <b>Description:</b><br>{alert_data['description']}
        """
        
        # Show the details in a message box
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Alert Details")
        msg_box.setTextFormat(Qt.RichText)
        msg_box.setText(details)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()

    def mark_alert_resolved(self, item):
        """Mark the selected alert as resolved."""
        # In a real application, you would update the alert status in your data model
        # For now, we'll just remove it from the view
        index = self.alerts_tree.indexOfTopLevelItem(item)
        if index >= 0:
            self.alerts_tree.takeTopLevelItem(index)
            self.update_status("Alert marked as resolved")

    def export_alert(self, item):
        """Export the selected alert to a file."""
        # In a real application, you would implement actual file export logic
        # For now, we'll just show a message
        QMessageBox.information(
            self, 
            "Export Alert", 
            f"Exporting alert: {item.text(5)[:50]}..."
        )

    def filter_flows(self):
        """Filter flows based on the search term."""
        search_term = self.flow_filter_edit.text().lower()
        if not search_term:
            # If search is empty, show all flows
            for i in range(self.flows_tree.topLevelItemCount()):
                self.flows_tree.topLevelItem(i).setHidden(False)
            return
        
        # Hide items that don't match the search term
        for i in range(self.flows_tree.topLevelItemCount()):
            item = self.flows_tree.topLevelItem(i)
            match_found = False
            
            # Check each column for a match
            for col in range(self.flows_tree.columnCount()):
                if search_term in item.text(col).lower():
                    match_found = True
                    break
            
            item.setHidden(not match_found)
    
    async def _stop_collector(self):
        """Stop the flow collector asynchronously."""
        if self.flow_collector and hasattr(self.flow_collector, 'stop'):
            if asyncio.iscoroutinefunction(self.flow_collector.stop):
                try:
                    await self.flow_collector.stop()
                except Exception as e:
                    print(f"Error stopping flow collector: {e}", file=sys.stderr)
            else:
                try:
                    self.flow_collector.stop()
                except Exception as e:
                    print(f"Error stopping flow collector: {e}", file=sys.stderr)

    def closeEvent(self, event):
        """Handle window close event."""
        try:
            # Stop background tasks
            self.running = False
            
            # Stop the update timer first
            if hasattr(self, 'update_timer') and self.update_timer.isActive():
                self.update_timer.stop()
            
            # Create and start event loop for async cleanup
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Stop worker threads with proper cleanup
                if hasattr(self, 'flow_worker') and self.flow_worker:
                    self.flow_worker.stop()
                
                if hasattr(self, 'analysis_worker') and self.analysis_worker:
                    self.analysis_worker.stop()
                
                # Stop the flow collector
                if hasattr(self, 'flow_collector') and self.flow_collector:
                    try:
                        loop.run_until_complete(self._stop_collector())
                    except Exception as e:
                        print(f"Error stopping flow collector: {e}", file=sys.stderr)
                
                # Stop the threads
                if hasattr(self, 'flow_thread') and self.flow_thread.isRunning():
                    self.flow_thread.quit()
                    if not self.flow_thread.wait(2000):
                        self.flow_thread.terminate()
                
                if hasattr(self, 'analysis_thread') and self.analysis_thread.isRunning():
                    self.analysis_thread.quit()
                    if not self.analysis_thread.wait(2000):
                        self.analysis_thread.terminate()
                
                event.accept()
                
            except Exception as e:
                print(f"Error during cleanup: {e}", file=sys.stderr)
                event.accept()  # Still accept the close event
                
            finally:
                try:
                    if loop.is_running():
                        loop.stop()
                    loop.close()
                except Exception as e:
                    print(f"Error closing event loop: {e}", file=sys.stderr)
                    
        except Exception as e:
            print(f"Fatal error during shutdown: {e}", file=sys.stderr)
            event.accept()  # Ensure the application can still close


def main():
    """Main entry point for the NDR GUI application."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Set application information
    app.setApplicationName("Network Detection & Response")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Security Ops Center")
    
    # Create and show the main window
    try:
        window = NDRGUI()
        window.show()
        
        # Start the event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        # Log any unhandled exceptions
        import traceback
        error_msg = f"Unhandled exception: {e}\n{traceback.format_exc()}"
        print(error_msg, file=sys.stderr)
        
        # Show error message to user
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setText("An error occurred")
        msg.setInformativeText("The application encountered an unexpected error and needs to close.")
        msg.setWindowTitle("Error")
        msg.setDetailedText(error_msg)
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        
        sys.exit(1)

if __name__ == "__main__":
    main()
