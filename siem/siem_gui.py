"""
SIEM GUI - Security Information and Event Management (PyQt5 Version)

A modern, modular GUI for the SIEM system with enhanced features and improved user experience.
"""

# Suppress PyQt deprecation warnings
import warnings
from PyQt5.QtCore import pyqtRemoveInputHook
warnings.filterwarnings("ignore", category=DeprecationWarning, module='PyQt5')
# Suppress SIP deprecation warnings
import sip
try:
    sip.setapi('QVariant', 2)
    sip.setapi('QString', 2)
except (AttributeError, ValueError):
    # API was already set to v2
    pass

import json
import logging
import os
import random
import sys
import subprocess
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone, UTC
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable, TypeVar, Generic, Type, cast
from dataclasses import dataclass, field, asdict

# Database
from .database import get_database

# Local database module
from .database import get_database

from PyQt5.QtCore import (
    Qt, QTimer, QSize, QDateTime, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, QVariant, pyqtSignal, QObject
)
from PyQt5.QtGui import (
    QIcon, QPalette, QColor, QBrush, QFont, QFontMetrics,
    QStandardItemModel, QStandardItem, QTextCharFormat, QSyntaxHighlighter,
    QTextCursor, QTextDocument, QTextFormat, QPainter, QPen, QLinearGradient
)
from PyQt5.QtWidgets import (
    QMessageBox, QDialog, QDialogButtonBox, QVBoxLayout, QLabel,
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QGridLayout,
    QTabWidget, QLineEdit, QComboBox, QMessageBox, QMenu, QAction,
    QDialog, QDialogButtonBox, QFormLayout, QTextEdit, QFrame,
    QGroupBox, QTextBrowser, QStatusBar, QToolBar, QToolButton,
    QFileDialog, QInputDialog, QProgressBar, QDateEdit, QDateTimeEdit,
    QSpinBox, QDoubleSpinBox, QCheckBox, QRadioButton, QButtonGroup,
    QSplitter, QScrollArea, QStackedWidget, QDockWidget, QListWidget,
    QListWidgetItem, QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator,
    QAbstractItemView, QStyleFactory, QStyle, QSystemTrayIcon, QMenuBar,
    QTableView, QCompleter, QActionGroup, QStyledItemDelegate, QSizePolicy,
    QSplitterHandle, QTabBar, QDockWidget, QMdiArea, QMdiSubWindow, QGraphicsView,
    QGraphicsScene, QGraphicsWidget, QGraphicsGridLayout, QGraphicsLinearLayout,
    QGraphicsProxyWidget, QGraphicsDropShadowEffect, QScrollBar, QSlider, QDial,
    QProgressDialog, QWizard, QWizardPage, QCalendarWidget, QColorDialog,
    QFontDialog, QFileSystemModel, QTreeView, QColumnView, QHeaderView,
    QItemDelegate, QDataWidgetMapper, QListView, QUndoView, QTableWidget,
    QTableWidgetItem, QTableWidgetSelectionRange, QTableView, QAbstractItemView,
    QStyledItemDelegate, QStyleOptionViewItem, QStyleOptionButton, QStyleOption,
    QDesktopWidget, QDockWidget, QMdiArea, QMdiSubWindow, QGraphicsView,
    QGraphicsScene, QGraphicsWidget, QGraphicsGridLayout, QGraphicsLinearLayout,
    QGraphicsProxyWidget, QGraphicsDropShadowEffect, QScrollBar, QSlider, QDial,
    QProgressDialog, QWizard, QWizardPage, QCalendarWidget, QColorDialog,
    QFontDialog, QFileSystemModel, QTreeView, QColumnView, QHeaderView,
    QItemDelegate, QDataWidgetMapper, QListView, QUndoView, QTableWidget,
    QTableWidgetItem, QTableWidgetSelectionRange, QTableView, QAbstractItemView,
    QStyledItemDelegate, QStyleOptionViewItem, QStyleOptionButton, QStyleOption,
    QDesktopWidget
)

# Import models
from .models import Event, Alert, EventSeverity, AlertStatus, EventManager

from PyQt5.QtCore import (
    Qt, QTimer, QDateTime, QDate, QTime, QSize, QPoint, QRect,
    QUrl, QEvent, QObject, QThread, pyqtSignal, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, QRegExp, QItemSelectionModel,
    QItemSelection, QMimeData, QSettings, QProcess, QProcessEnvironment,
    QFile, QTextStream, QIODevice, QTextCodec, QByteArray, QDataStream,
    QBuffer, QFileInfo, QDir, QStandardPaths, QLibraryInfo, QLocale,
    QTranslator, QCoreApplication, QMetaObject, QMetaType, QVariant,
    QThreadPool, QRunnable, QMutex, QMutexLocker, QWaitCondition,
    QSemaphore, QReadWriteLock, QReadLocker, QWriteLocker, QTimerEvent,
    QChildEvent, QDynamicPropertyChangeEvent
)

from PyQt5.QtGui import (
    QIcon, QPixmap, QImage, QPainter, QPen, QBrush, QColor, QFont,
    QFontMetrics, QFontDatabase, QTextCharFormat, QTextCursor,
    QTextDocument, QTextFormat, QTextLength, QTextOption, QSyntaxHighlighter,
    QStandardItemModel, QStandardItem, QIntValidator, QDoubleValidator,
    QRegExpValidator, QValidator, QKeySequence, QKeyEvent, QMouseEvent,
    QWheelEvent, QResizeEvent, QMoveEvent, QCloseEvent, QFocusEvent,
    QContextMenuEvent, QDropEvent, QDragEnterEvent, QDragMoveEvent,
    QDragLeaveEvent, QHelpEvent, QStatusTipEvent, QWhatsThisClickedEvent,
    QActionEvent, QIconEngine, QMovie, QClipboard,
    QDesktopServices, QGuiApplication, QRegion, QTransform,
    QMatrix4x4, QVector2D, QVector3D, QVector4D, QQuaternion, QPalette,
    QLinearGradient, QRadialGradient, QConicalGradient, QGradient,
    QBitmap, QCursor, QTextDocumentFragment, QTextTable,
    QTextTableFormat, QTextBlockFormat, QTextFrameFormat,
    QTextImageFormat, QTextListFormat, QTextTableCellFormat,
    QTextDocumentWriter, QTextInlineObject, QTextLayout, QTextLine,
    QTextTableCell
)

# Chart imports
from PyQt5.QtChart import QChart, QChartView, QPieSeries, QPieSlice, QBarSeries, QBarSet, QBarCategoryAxis, QValueAxis, QLineSeries

# Enums
class EventSeverity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AlertStatus(Enum):
    NEW = "New"
    IN_PROGRESS = "In Progress"
    RESOLVED = "Resolved"
    DISMISSED = "Dismissed"
    ESCALATED = "Escalated"
    SUPPRESSED = "Suppressed"

# Data Models
@dataclass
class SIEMEvent:
    """Represents a security event in the SIEM system."""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: EventSeverity
    description: str
    raw_data: Dict[str, Any]
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'severity': self.severity.value,
            'description': self.description,
            'tags': self.tags,
            'raw_data': self.raw_data
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SIEMEvent':
        """Create an event from a dictionary."""
        return cls(
            event_id=data.get('event_id', str(uuid.uuid4())),
            timestamp=datetime.fromisoformat(data['timestamp']),
            source=data['source'],
            event_type=data['event_type'],
            severity=EventSeverity(data['severity']),
            description=data['description'],
            raw_data=data.get('raw_data', {}),
            tags=data.get('tags', [])
        )

    @classmethod
    def add_event(cls, event_data: Dict[str, Any], db) -> None:
        """Add a new event to the system and database."""
        try:
            # Create event data for database
            event_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            
            db_event = {
                'event_id': event_id,
                'timestamp': timestamp,
                'source': event_data.get('source', 'unknown'),
                'event_type': event_data.get('event_type', 'unknown'),
                'severity': event_data.get('severity', EventSeverity.INFO).value,
                'description': event_data.get('description', ''),
                'raw_data': json.dumps(event_data.get('raw_data', {})),
                'tags': json.dumps(event_data.get('tags', []))
            }
            
            # Create event object
            event = cls(
                event_id=event_id,
                timestamp=datetime.fromisoformat(timestamp),
                source=db_event['source'],
                event_type=db_event['event_type'],
                severity=EventSeverity(db_event['severity']),
                description=db_event['description'],
                raw_data=json.loads(db_event['raw_data'])
            )
            
            # Add to database
            db.add_event(db_event)
            
            # Add to in-memory lists
            # self.events.append(event)
            # self.event_manager.add_event(event)
            
            # Update UI
            # self.update_events_table()
            
            # Check if this event should trigger any alerts
            # self._check_for_alerts(event)
            
        except Exception as e:
            logging.error(f"Error adding event: {e}")

@dataclass
class Alert:
    """Represents a security alert in the SIEM system."""
    alert_id: str
    timestamp: datetime
    source: str
    title: str
    description: str
    severity: EventSeverity
    status: AlertStatus
    event_ids: List[str]
    assigned_to: str = ""
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'event_ids': self.event_ids,
            'assigned_to': self.assigned_to,
            'notes': self.notes
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Alert':
        """Create an alert from a dictionary."""
        return cls(
            alert_id=data.get('alert_id', str(uuid.uuid4())),
            timestamp=datetime.fromisoformat(data['timestamp']),
            source=data['source'],
            title=data['title'],
            description=data['description'],
            severity=EventSeverity(data['severity']),
            status=AlertStatus(data['status']),
            event_ids=data.get('event_ids', []),
            assigned_to=data.get('assigned_to', ''),
            notes=data.get('notes', '')
        )

    @classmethod
    def add_alert(cls, alert_data: Dict[str, Any], db) -> None:
        """Add a new alert to the system and database."""
        try:
            # Create alert data for database
            alert_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()
            
            db_alert = {
                'alert_id': alert_id,
                'timestamp': timestamp,
                'source': alert_data.get('source', 'system'),
                'title': alert_data.get('title', 'New Alert'),
                'description': alert_data.get('description', ''),
                'severity': alert_data.get('severity', EventSeverity.MEDIUM).value,
                'status': AlertStatus.NEW.value,
                'event_ids': json.dumps(alert_data.get('event_ids', [])),
                'assigned_to': '',
                'notes': ''
            }
            
            # Create alert object
            alert = cls(
                alert_id=alert_id,
                timestamp=datetime.fromisoformat(timestamp),
                source=db_alert['source'],
                title=db_alert['title'],
                description=db_alert['description'],
                severity=EventSeverity(db_alert['severity']),
                status=AlertStatus(db_alert['status']),
                event_ids=json.loads(db_alert['event_ids'])
            )
            
            # Add to database
            db.add_alert(db_alert)
            
            # Add to in-memory lists
            # self.alerts.append(alert)
            # self.event_manager.add_alert(alert)
            
            # Update UI
            # self.update_alerts_table()
            
            # Show notification
            # self.show_alert_notification(alert)
            
        except Exception as e:
            logging.error(f"Error adding alert: {e}")

@dataclass
class DetectionRule:
    """Represents a detection rule for identifying security events."""
    rule_id: str
    name: str
    description: str
    query: str
    tags: List[str]
    severity: EventSeverity = EventSeverity.MEDIUM
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary for serialization."""
        return {
            'rule_id': self.rule_id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity.value,
            'query': self.query,
            'tags': self.tags,
            'enabled': self.enabled,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DetectionRule':
        """Create a rule from a dictionary."""
        return cls(
            rule_id=data.get('rule_id', str(uuid.uuid4())),
            name=data['name'],
            description=data['description'],
            severity=EventSeverity(data['severity']),
            query=data['query'],
            tags=data.get('tags', []),
            enabled=data.get('enabled', True),
            created_at=datetime.fromisoformat(data.get('created_at', datetime.now(timezone.utc).isoformat())),
            updated_at=datetime.fromisoformat(data.get('updated_at', datetime.now(timezone.utc).isoformat()))
        )

# Constants
MAX_EVENTS = 10000  # Maximum number of events to keep in memory
ALERT_RETENTION_DAYS = 30  # Days to retain alerts
EVENT_RETENTION_DAYS = 90  # Days to retain events

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('siem_gui.log')
    ]
)
logger = logging.getLogger('siem.gui')

# Default configuration
DEFAULT_CONFIG = {
    'ui': {
        'theme': 'dark',
        'font_size': 10,
        'refresh_interval': 5000,
        'window_size': (1600, 1000)
    },
    'paths': {
        'rules': 'rules',
        'reports': 'reports',
        'exports': 'exports',
        'logs': 'logs'
    }
}

class EventManager(QObject):
    """Manages SIEM events and alerts with thread-safe operations."""
    event_added = pyqtSignal(object)  # Signal when a new event is added
    alert_triggered = pyqtSignal(object)  # Signal when a new alert is triggered
    
    def __init__(self, max_events=MAX_EVENTS):
        super().__init__()
        self.max_events = max_events
        self.events = []
        self.alerts = []
        self.rules = []

class SIEMMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Security Information and Event Management")
        self.setGeometry(100, 100, 1200, 800)  # Default size if not in config
        
        # Initialize database
        self.db = get_database()
        
        # Initialize core components
        self.config = self.load_config()
        self.event_manager = EventManager()
        
        # Initialize data structures
        self.events = []
        self.alerts = []
        
        # Initialize UI components
        self.setup_ui()
        
        # Load initial data
        self.load_initial_data()
        
        # Setup connections and timers
        self.setup_connections()
        self.apply_theme(self.config.get('ui', {}).get('theme', 'light'))
        self.setup_timers()
        
        # Show status message
        self.status_bar.showMessage("Ready")
    
    def load_config(self) -> dict:
        """Load application configuration."""
        config = DEFAULT_CONFIG.copy()
        config_path = Path('siem_config.json')
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config.update(json.load(f))
            else:
                # Create default config file if it doesn't exist
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=4)
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            
        return config
        
    def save_config(self) -> None:
        """Save application configuration."""
        try:
            with open('siem_config.json', 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")
            
    def update_dashboard(self):
        """Update the dashboard with current statistics."""
        try:
            # Get stats from database
            event_count = len(self.events) if hasattr(self, 'events') else 0
            alert_count = len(self.alerts) if hasattr(self, 'alerts') else 0
            
            # Update dashboard widgets if they exist
            if hasattr(self, 'event_count_label'):
                self.event_count_label.setText(f"{event_count}")
            if hasattr(self, 'alert_count_label'):
                self.alert_count_label.setText(f"{alert_count}")
                
        except Exception as e:
            logging.error(f"Error updating dashboard: {e}")
            
    def setup_timers(self):
        """Set up timers for periodic updates."""
        # Only set up timers if the UI elements exist
        if hasattr(self, 'dashboard_tab'):
            self.dashboard_timer = QTimer()
            self.dashboard_timer.timeout.connect(self.update_dashboard)
            self.dashboard_timer.start(10000)  # Update every 10 seconds
        
        if hasattr(self, 'events_table'):
            self.events_timer = QTimer()
            self.events_timer.timeout.connect(lambda: self.update_events_table(100))
            self.events_timer.start(5000)  # Update every 5 seconds
        
        if hasattr(self, 'alerts_table'):
            self.alerts_timer = QTimer()
            self.alerts_timer.timeout.connect(lambda: self.update_alerts_table(100))
            self.alerts_timer.start(5000)  # Update every 5 seconds
        
    def setup_connections(self):
        """Set up signal-slot connections."""
        # Connect event manager signals
        self.event_manager.event_added.connect(self.handle_new_event)
        self.event_manager.alert_triggered.connect(self.handle_new_alert)
        
    def handle_new_event(self, event):
        """Handle new event from the event manager."""
        # Update event count
        if hasattr(self, 'events_received'):
            self.agentless_stats['events_received'] += 1
            self.events_received.setText(f"Events Received: {self.agentless_stats['events_received']}")
    
    def handle_new_alert(self, alert):
        """Handle new alert from the event manager."""
        # Update alerts table if needed
        if hasattr(self, 'alerts_table'):
            self.update_alerts_table()
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # Create tab widget (using tab_widget instead of tabs for consistency)
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tab widgets
        self.dashboard_tab = QWidget()
        self.events_tab = QWidget()
        self.alerts_tab = QWidget()
        self.agentless_tab = QWidget()
        
        # Add tabs to the tab widget
        self.tab_widget.addTab(self.dashboard_tab, "Dashboard")
        self.tab_widget.addTab(self.events_tab, "Events")
        self.tab_widget.addTab(self.alerts_tab, "Alerts")
        self.tab_widget.addTab(self.agentless_tab, "Agentless Collection")
        
        # Set up status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Set up tab contents
        self.setup_dashboard_tab()
        self.setup_events_tab()
        self.setup_alerts_tab()
        self.setup_agentless_tab()
        
        # Set initial status message
        self.status_bar.showMessage("Ready")
        
    def setup_dashboard_tab(self):
        """Set up the dashboard tab with metrics and charts."""
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Add metrics section
        metrics_group = QGroupBox("Metrics")
        metrics_layout = QHBoxLayout()
        
        # Event metrics
        self.events_count_label = QLabel("Total Events: 0")
        self.alerts_count_label = QLabel("Active Alerts: 0")
        
        # Style the labels
        for label in [self.events_count_label, self.alerts_count_label]:
            label.setStyleSheet("font-size: 14px; font-weight: bold;")
            metrics_layout.addWidget(label)
            
        metrics_group.setLayout(metrics_layout)
        layout.addWidget(metrics_group)
        
        # Add charts area
        chart_group = QGroupBox("Event Statistics")
        chart_layout = QVBoxLayout()
        
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        chart_layout.addWidget(self.chart_view)
        
        chart_group.setLayout(chart_layout)
        layout.addWidget(chart_group)
        
        # Add stretch to push content to the top
        layout.addStretch()
        
    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh of the events table."""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
            
        if state == Qt.Checked:
            if not hasattr(self, 'refresh_timer'):
                self.refresh_timer = QTimer()
                self.refresh_timer.timeout.connect(self.update_events_table)
            self.refresh_timer.start(5000)  # 5 seconds
            
    def apply_filters(self):
        """Apply filters to the events table."""
        try:
            if not hasattr(self, 'events_table'):
                return
                
            filter_text = self.filter_text.text().lower()
            severity_filter = self.severity_filter.currentText().lower()
            
            for row in range(self.events_table.rowCount()):
                show_row = True
                
                # Apply severity filter
                if severity_filter and severity_filter != "all severities":
                    severity_item = self.events_table.item(row, 3)  # Severity is in column 3
                    if severity_item and severity_filter not in severity_item.text().lower():
                        show_row = False
                
                # Apply text filter
                if show_row and filter_text:
                    row_matches = False
                    for col in range(self.events_table.columnCount()):
                        item = self.events_table.item(row, col)
                        if item and filter_text in item.text().lower():
                            row_matches = True
                            break
                    show_row = row_matches
                
                self.events_table.setRowHidden(row, not show_row)
                
        except Exception as e:
            logging.error(f"Error applying filters: {e}")
            self.statusBar().showMessage(f"Error applying filters: {str(e)}", 5000)
            
    def show_event_context_menu(self, position):
        """Show context menu for event table items."""
        try:
            if not hasattr(self, 'events_table'):
                return
                
            selected_rows = self.events_table.selectionModel().selectedRows()
            if not selected_rows:
                return
                
            menu = QMenu()
            
            # Add View Details action
            view_action = menu.addAction("View Details")
            
            # Add actions based on selection
            if len(selected_rows) == 1:
                menu.addSeparator()
                copy_action = menu.addAction("Copy Event ID")
                
            # Add bulk actions for multiple selections
            if len(selected_rows) > 1:
                menu.addSeparator()
                bulk_ack_action = menu.addAction(f"Acknowledge {len(selected_rows)} Events")
                
            # Show the menu and get the selected action
            action = menu.exec_(self.events_table.viewport().mapToGlobal(position))
            
            if action == view_action:
                self.view_event_details(selected_rows[0].row())
            elif 'copy_action' in locals() and action == copy_action:
                self.copy_event_id(selected_rows[0].row())
            elif 'bulk_ack_action' in locals() and action == bulk_ack_action:
                self.acknowledge_events([row.row() for row in selected_rows])
                
        except Exception as e:
            logging.error(f"Error showing context menu: {e}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
            
    def view_event_details(self, row):
        """Show detailed view of the selected event."""
        try:
            event_id = self.events_table.item(row, 0).text()  # Assuming ID is in first column
            # TODO: Implement event details view
            self.statusBar().showMessage(f"Viewing details for event {event_id}", 3000)
            
        except Exception as e:
            logging.error(f"Error viewing event details: {e}")
            self.statusBar().showMessage(f"Error viewing event: {str(e)}", 5000)
            
    def copy_event_id(self, row):
        """Copy event ID to clipboard."""
        try:
            event_id = self.events_table.item(row, 0).text()
            QApplication.clipboard().setText(event_id)
            self.statusBar().showMessage("Event ID copied to clipboard", 2000)
            
        except Exception as e:
            logging.error(f"Error copying event ID: {e}")
            self.statusBar().showMessage(f"Error copying ID: {str(e)}", 5000)
            
    def acknowledge_events(self, rows):
        """Acknowledge multiple events."""
        try:
            event_ids = [self.events_table.item(row, 0).text() for row in rows]
            # TODO: Implement event acknowledgment logic
            self.statusBar().showMessage(f"Acknowledged {len(event_ids)} events", 3000)
            
        except Exception as e:
            logging.error(f"Error acknowledging events: {e}")
            self.statusBar().showMessage(f"Error acknowledging events: {str(e)}", 5000)
            
    def setup_events_tab(self):
        """Set up the events tab with a table view and controls."""
        self.events_tab = QWidget()
        self.tab_widget.addTab(self.events_tab, "Events")
        
        # Main layout
        main_layout = QVBoxLayout(self.events_tab)
        
        # Controls layout
        controls_layout = QHBoxLayout()
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(lambda: self.update_events_table())
        controls_layout.addWidget(self.refresh_btn)
        
        # Auto-refresh toggle
        self.auto_refresh = QCheckBox("Auto-refresh (5s)")
        self.auto_refresh.setChecked(True)
        self.auto_refresh.stateChanged.connect(self.toggle_auto_refresh)
        controls_layout.addWidget(self.auto_refresh)
        
        # Filter controls
        controls_layout.addWidget(QLabel("Filter:"))
        self.filter_text = QLineEdit()
        self.filter_text.setPlaceholderText("Search events...")
        self.filter_text.textChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.filter_text)
        
        # Severity filter
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All Severities", "")
        self.severity_filter.addItem("Critical", "critical")
        self.severity_filter.addItem("High", "high")
        self.severity_filter.addItem("Medium", "medium")
        self.severity_filter.addItem("Low", "low")
        self.severity_filter.addItem("Info", "info")
        self.severity_filter.currentIndexChanged.connect(self.apply_filters)
        controls_layout.addWidget(self.severity_filter)
        
        # Add controls to main layout
        main_layout.addLayout(controls_layout)
        
        # Create table with better defaults
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(6)
        self.events_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Type", "Severity", "Description", "Details"])
        
        # Configure table
        header = self.events_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Timestamp
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Source
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Severity
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Description (takes remaining space)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Details button
        
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.events_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.events_table.setSortingEnabled(True)
        
        # Enable context menu
        self.events_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.events_table.customContextMenuRequested.connect(self.show_event_context_menu)
        
        # Add table to layout with stretch
        main_layout.addWidget(self.events_table)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.status_bar.showMessage("Ready")
        main_layout.addWidget(self.status_bar)
        
        # Set initial sort order (most recent first)
        self.events_table.sortByColumn(0, Qt.DescendingOrder)
        
    def setup_alerts_tab(self):
        """Set up the alerts tab with a table view."""
        layout = QVBoxLayout(self.alerts_tab)
        
        # Add alerts table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Severity", "Status", "Title", "Description"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.alerts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.alerts_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Initialize stats
        self.agentless_stats = {
            'events_received': 0,
            'bytes_received': 0,
            'start_time': datetime.now(),
            'connected_devices': {}
        }
        
        # Start monitoring the process
        self.agentless_timer = QTimer(self)
        self.agentless_timer.timeout.connect(self.check_agentless_status)
        self.agentless_timer.start(1000)  # Check every second
        
        # Start updating the UI every 5 seconds
        self.agentless_ui_timer = QTimer(self)
        self.agentless_ui_timer.timeout.connect(self.update_agentless_ui)
        self.agentless_ui_timer.start(5000)  # Update every 5 seconds
        
        # Initial UI update
        self.update_agentless_ui()
        
        layout.addWidget(self.alerts_table)
        
    def start_agentless_collection(self):
        """Start the agentless collector."""
        try:
            # Start the agentless collector process
            self.agentless_process = subprocess.Popen(
                [sys.executable, '-m', 'siem.collectors.agentless'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Update UI
            self.agentless_status.setText("Status: Running")
            self.agentless_status.setStyleSheet("color: green;")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            
            # Start monitoring the process
            self.agentless_timer = QTimer(self)
            self.agentless_timer.timeout.connect(self.check_agentless_status)
            self.agentless_timer.start(1000)  # Check every second
            
            # Initialize stats
            self.agentless_stats = {
                'events_received': 0,
                'bytes_received': 0,
                'start_time': datetime.now()
            }
            
        except Exception as e:
            logging.error(f"Error starting agentless collector: {e}", exc_info=True)
            self.agentless_status.setText("Status: Error")
            self.agentless_status.setStyleSheet("color: red;")

    def setup_agentless_tab(self):
        """Set up the agentless collector tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Stats layout
        stats_layout = QHBoxLayout()
        self.events_received = QLabel("Events Received: 0")
        self.bytes_received = QLabel("Data Received: 0 B")
        self.avg_rate = QLabel("Average Rate: 0.00 events/sec")
        
        stats_layout.addWidget(self.events_received)
        stats_layout.addWidget(self.bytes_received)
        stats_layout.addWidget(self.avg_rate)
        stats_layout.addStretch()
        
        # Add stats to main layout
        layout.addLayout(stats_layout)
        
        # Add agentless tab to the main tab widget
        self.tab_widget.addTab(tab, "Agentless Collection")
        
        status_group = QGroupBox("Collector Status")
        main_layout = QVBoxLayout()
        
        # Status and stats layout
        status_layout = QHBoxLayout()
        
        # Left side - Status indicators
        status_left = QVBoxLayout()
        
        # Collector status
        self.agentless_status = QLabel("Status: Stopped")
        self.agentless_status.setStyleSheet("font-weight: bold; color: red;")
        status_left.addWidget(self.agentless_status)
        
        # Collector services status
        self.syslog_status = QLabel("Syslog: Not Running")
        self.snmp_status = QLabel("SNMP Trap: Not Running")
        self.wef_status = QLabel("Windows Event Forwarding: Not Running")
        
        for status in [self.syslog_status, self.snmp_status, self.wef_status]:
            status.setStyleSheet("color: red;")
            status_left.addWidget(status)
        
        status_layout.addLayout(status_left, 1)  # Add stretch factor
        
        # Right side - Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout()
        
        self.events_received = QLabel("Events Received: 0")
        self.bytes_received = QLabel("Data Received: 0 B")
        self.avg_rate = QLabel("Average Rate: 0.00 events/sec")
        self.connected_devices_count = QLabel("Connected Devices: 0")
        
        for stat in [self.events_received, self.bytes_received, 
                    self.avg_rate, self.connected_devices_count]:
            stats_layout.addWidget(stat)
            
        stats_group.setLayout(stats_layout)
        status_layout.addWidget(stats_group, 1)  # Add stretch factor
        
        main_layout.addLayout(status_layout)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.refresh_btn = QPushButton("Refresh")
        self.stop_btn.setEnabled(False)
        
        self.start_btn.clicked.connect(self.start_agentless_collection)
        self.stop_btn.clicked.connect(self.stop_agentless_collection)
        self.refresh_btn.clicked.connect(self.update_agentless_ui)
        
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.refresh_btn)
        
        main_layout.addLayout(btn_layout)
        status_group.setLayout(main_layout)
        layout.addWidget(status_group)
        
        # Connected devices table
        devices_group = QGroupBox("Connected Devices")
        devices_layout = QVBoxLayout()
        
        # Create the devices table
        self.devices_table = QTableWidget()
        self.devices_table.setColumnCount(6)
        self.devices_table.setHorizontalHeaderLabels([
            "IP Address", "Type", "Status", "First Seen", "Last Seen", "Messages"
        ])
        
        # Configure table properties
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setSelectionMode(QTableWidget.SingleSelection)
        self.devices_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.devices_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.devices_table.customContextMenuRequested.connect(self.show_device_context_menu)
        
        # Set column resize modes
        header = self.devices_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # IP
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # First Seen
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Last Seen
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Messages
        
        # Add filter controls
        filter_layout = QHBoxLayout()
        self.device_filter = QLineEdit()
        self.device_filter.setPlaceholderText("Filter devices...")
        self.device_filter.textChanged.connect(self.filter_devices)
        
        self.device_type_filter = QComboBox()
        self.device_type_filter.addItem("All Types")
        self.device_type_filter.addItems(["Syslog", "SNMP", "WEF"])
        self.device_type_filter.currentTextChanged.connect(self.filter_devices)
        
        filter_layout.addWidget(QLabel("Search:"))
        filter_layout.addWidget(self.device_filter, 1)
        filter_layout.addWidget(QLabel("Type:"))
        filter_layout.addWidget(self.device_type_filter)
        
        devices_layout.addLayout(filter_layout)
        devices_layout.addWidget(self.devices_table)
        devices_group.setLayout(devices_layout)
        
        layout.addWidget(devices_group, 1)  # Add stretch factor
        
        # Initialize agentless stats
        self.agentless_stats = {
            'events_received': 0,
            'bytes_received': 0,
            'start_time': None,
            'devices': {}
        }
        
        # Initialize UI elements
        self.events_received = QLabel("Events Received: 0")
        self.bytes_received = QLabel("Data Received: 0 B")
        self.avg_rate = QLabel("Average Rate: 0.00 events/sec")
        
        # Add to stats layout if it exists
        if hasattr(self, 'stats_layout'):
            self.stats_layout.addWidget(self.events_received)
            self.stats_layout.addWidget(self.bytes_received)
            self.stats_layout.addWidget(self.avg_rate)
        
        # Initialize UI update timer
        self.agentless_ui_timer = QTimer()
        self.agentless_ui_timer.timeout.connect(self.update_agentless_ui)
        self.agentless_ui_timer.start(5000)  # Update every 5 seconds
        
        # Configure table properties
        self.devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.devices_table.setSelectionMode(QTableWidget.SingleSelection)
        self.devices_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.devices_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.devices_table.customContextMenuRequested.connect(self.show_device_context_menu)
        
        # Set column resize modes
        header = self.devices_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # IP
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Type
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # First Seen
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Last Seen
        header.setSectionResizeMode(5, QHeaderView.Stretch)  # Messages
        
        devices_layout.addWidget(self.devices_table)
        
        # Add filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter:"))
        
        self.device_filter = QLineEdit()
        self.device_filter.setPlaceholderText("Filter devices...")
        self.device_filter.textChanged.connect(self.filter_devices)
        
        self.device_type_filter = QComboBox()
        self.device_type_filter.addItem("All Types", "")
        self.device_type_filter.addItem("Syslog", "syslog")
        self.device_type_filter.addItem("SNMP", "snmp")
        self.device_type_filter.addItem("WEF", "wef")
        self.device_type_filter.currentIndexChanged.connect(self.filter_devices)
        
        filter_layout.addWidget(self.device_filter)
        filter_layout.addWidget(self.device_type_filter)
        
        devices_layout.addLayout(filter_layout)
        devices_layout.addWidget(self.devices_table)
        devices_group.setLayout(devices_layout)
        layout.addWidget(devices_group, 1)  # Add stretch factor to make it take remaining space
        
    def check_agentless_status(self):
        """Check the status of the agentless collector and update UI accordingly."""
        if not hasattr(self, 'agentless_process'):
            return
            
        # Check if process is still running
        if self.agentless_process.poll() is not None:
            # Process has ended
            self.agentless_status.setText("Status: Stopped")
            self.agentless_status.setStyleSheet("color: red;")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            
            # Stop the timer if it's still running
            if hasattr(self, 'agentless_timer'):
                self.agentless_timer.stop()
    
    def stop_agentless_collection(self):
        """Stop the agentless collector."""
        try:
            if hasattr(self, 'agentless_timer'):
                self.agentless_timer.stop()
                
            # Check if process is still running without blocking
            if self.agentless_process.poll() is None:
                # Process is still running
                current_time = datetime.now()
                
                # Check if we've received any updates recently
                last_update = self.agentless_stats.get('last_update')
                if last_update and (current_time - last_update).total_seconds() > 30:
                    # No updates in 30 seconds, might be stuck
                    logging.warning("Agentless collector running but no updates received in 30 seconds")
                    self.syslog_status.setText("Syslog: No Data (Running)")
                    self.syslog_status.setStyleSheet("font-weight: bold; color: orange;")
                    self.snmp_status.setText("SNMP Trap: No Data (Running)")
                    self.snmp_status.setStyleSheet("font-weight: bold; color: orange;")
                    self.wef_status.setText("Windows Event Forwarding: No Data (Running)")
                    self.wef_status.setStyleSheet("font-weight: bold; color: orange;")
                else:
                    # Update UI for running state with event count
                    event_count = self.agentless_stats.get('events_received', 0)
                    self.syslog_status.setText(f"Syslog: Running ({event_count} events)")
                    self.syslog_status.setStyleSheet("font-weight: bold; color: green;")
                    self.snmp_status.setText(f"SNMP Trap: Running ({event_count} events)")
                    self.snmp_status.setStyleSheet("font-weight: bold; color: green;")
                    self.wef_status.setText(f"Windows Event Forwarding: Running ({event_count} events)")
                    self.wef_status.setStyleSheet("font-weight: bold; color: green;")
                
                # Schedule next status check
                QTimer.singleShot(2000, self.check_agentless_status)
            else:
                # Process has ended
                return_code = self.agentless_process.returncode
                logging.info(f"Agentless collector process ended with return code: {return_code}")
                
                # Read any remaining output
                try:
                    stdout, stderr = self.agentless_process.communicate(timeout=1)
                    if stdout:
                        logging.debug(f"Agentless collector final stdout: {stdout}")
                    if stderr:
                        logging.error(f"Agentless collector final stderr: {stderr}")
                except (subprocess.TimeoutExpired, ValueError):
                    pass
                
                # Clean up
                self.agentless_process = None
                self.start_btn.setEnabled(True)
                self.stop_btn.setEnabled(False)
                
                # Update UI for stopped state
                self.syslog_status.setText("Syslog: Stopped")
                self.syslog_status.setStyleSheet("font-weight: bold; color: red;")
                self.snmp_status.setText("SNMP Trap: Stopped")
                self.snmp_status.setStyleSheet("font-weight: bold; color: red;")
                self.wef_status.setText("Windows Event Forwarding: Stopped")
                self.wef_status.setStyleSheet("font-weight: bold; color: red;")
                
                # Show error message if the process failed
                if return_code != 0:
                    QMessageBox.warning(
                        self,
                        "Agentless Collector Error",
                        f"The agentless collector stopped unexpectedly with return code {return_code}.\n\n"
                        "Check the logs for more information."
                    )
                
        except Exception as e:
            logging.error(f"Error in check_agentless_status: {e}", exc_info=True)
            if hasattr(self, 'agentless_process'):
                self.agentless_process = None
                
            # Reset UI on error
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.syslog_status.setText("Syslog: Error")
            self.syslog_status.setStyleSheet("font-weight: bold; color: red;")
            self.snmp_status.setText("SNMP Trap: Error")
            self.snmp_status.setStyleSheet("font-weight: bold; color: red;")
            self.wef_status.setText("Windows Event Forwarding: Error")
            self.wef_status.setStyleSheet("font-weight: bold; color: red;")
    
    def refresh_agentless_devices(self):
        """Refresh the list of connected devices from the agentless collector."""
        if not hasattr(self, 'agentless_collector') or self.agentless_collector is None:
            return
            
        try:
            # Get connected devices from the agentless collector
            devices = asyncio.run_coroutine_threadsafe(
                self.agentless_collector.get_connected_devices(),
                asyncio.get_event_loop()
            ).result()
            
            # Update the connected devices count
            self.connected_devices_count.setText(f"Connected Devices: {len(devices)}")
            
            # Store the current filter text and type
            filter_text = self.device_filter.text().lower()
            filter_type = self.device_type_filter.currentData()
            
            # Clear the table
            self.devices_table.setRowCount(0)
            
            # Add devices to the table
            for device_id, device in devices.items():
                # Apply filters
                if filter_text and filter_text not in device.get('ip', '').lower():
                    continue
                    
                if filter_type and device.get('type') != filter_type:
                    continue
                
                # Format timestamps
                first_seen = datetime.fromtimestamp(device.get('first_seen', 0))
                last_seen = datetime.fromtimestamp(device.get('last_seen', 0))
                
                # Add a new row
                row = self.devices_table.rowCount()
                self.devices_table.insertRow(row)
                
                # Set the data for each column
                self.devices_table.setItem(row, 0, QTableWidgetItem(device.get('ip', 'Unknown')))
                self.devices_table.setItem(row, 1, QTableWidgetItem(device.get('type', 'Unknown').upper()))
                
                # Status with color coding
                status_item = QTableWidgetItem(device.get('status', 'unknown').capitalize())
                if device.get('status') == 'connected':
                    status_item.setForeground(QColor(0, 128, 0))  # Green for connected
                elif device.get('status') == 'disconnected':
                    status_item.setForeground(QColor(200, 0, 0))  # Red for disconnected
                else:
                    status_item.setForeground(QColor(200, 100, 0))  # Orange for blocked
                self.devices_table.setItem(row, 2, status_item)
                
                # Timestamps
                self.devices_table.setItem(row, 3, QTableWidgetItem(first_seen.strftime('%Y-%m-%d %H:%M:%S')))
                self.devices_table.setItem(row, 4, QTableWidgetItem(last_seen.strftime('%Y-%m-%d %H:%M:%S')))
                self.devices_table.setItem(row, 5, QTableWidgetItem(str(device.get('message_count', 0))))
                
                # Store the device ID as data in the first column
                self.devices_table.item(row, 0).setData(Qt.UserRole, device_id)
                
        except Exception as e:
            logger.error(f"Error refreshing device list: {e}", exc_info=True)
    
    def filter_devices(self):
        """Filter the devices table based on the current filter text and type."""
        self.refresh_agentless_devices()
    
    def show_device_context_menu(self, position):
        """Show the context menu for a device."""
        selected_items = self.devices_table.selectedItems()
        if not selected_items:
            return
            
        # Get the device ID from the first column of the selected row
        row = selected_items[0].row()
        device_id = self.devices_table.item(row, 0).data(Qt.UserRole)
        device_ip = self.devices_table.item(row, 0).text()
        current_status = self.devices_table.item(row, 2).text().lower()
        
        # Create the context menu
        menu = QMenu()
        
        # Add actions
        view_details_action = menu.addAction("View Details")
        copy_ip_action = menu.addAction("Copy IP Address")
        menu.addSeparator()
        
        # Add block/unblock action based on current status
        if current_status != 'blocked':
            block_action = menu.addAction("Block Device")
        else:
            block_action = menu.addAction("Unblock Device")
        
        # Show the menu and get the selected action
        action = menu.exec_(self.devices_table.viewport().mapToGlobal(position))
        
        # Handle the selected action
        if action == view_details_action:
            self.show_device_details(device_id)
        elif action == copy_ip_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(device_ip)
            self.status_bar.showMessage(f"Copied {device_ip} to clipboard", 2000)
        elif action == block_action:
            self.toggle_device_block(device_id, current_status != 'blocked')
    
    def show_device_details(self, device_id):
        """Show detailed information about a device."""
        try:
            if not hasattr(self, 'agentless_collector') or not self.agentless_collector:
                return
                
            # Get device details
            devices = asyncio.run_coroutine_threadsafe(
                self.agentless_collector.get_connected_devices(),
                asyncio.get_event_loop()
            ).result()
            
            device = devices.get(device_id)
            if not device:
                return
                
            # Create a dialog to show device details
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Device Details - {device.get('ip', 'Unknown')}")
            dialog.setMinimumSize(500, 400)
            
            layout = QVBoxLayout()
            
            # Basic info in a form layout
            form_layout = QFormLayout()
            form_layout.addRow("IP Address:", QLabel(device.get('ip', 'Unknown')))
            form_layout.addRow("Type:", QLabel(device.get('type', 'Unknown').upper()))
            form_layout.addRow("Status:", QLabel(device.get('status', 'unknown').capitalize()))
            form_layout.addRow("First Seen:", QLabel(datetime.fromtimestamp(device.get('first_seen', 0)).strftime('%Y-%m-%d %H:%M:%S')))
            form_layout.addRow("Last Seen:", QLabel(datetime.fromtimestamp(device.get('last_seen', 0)).strftime('%Y-%m-%d %H:%M:%S')))
            form_layout.addRow("Message Count:", QLabel(str(device.get('message_count', 0))))
            
            # Add a text area for the last message (if available)
            if 'last_message' in device and device['last_message']:
                last_message = QTextEdit()
                last_message.setPlainText(device['last_message'])
                last_message.setReadOnly(True)
                form_layout.addRow("Last Message:", last_message)
            
            layout.addLayout(form_layout)
            
            # Add close button
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(dialog.reject)
            layout.addWidget(button_box)
            
            dialog.setLayout(layout)
            dialog.exec_()
            
        except Exception as e:
            logger.error(f"Error showing device details: {e}", exc_info=True)
    
    def toggle_device_block(self, device_id, block):
        """Block or unblock a device."""
        try:
            if not hasattr(self, 'agentless_collector') or not self.agentless_collector:
                return
                
            # Get the IP address from the device ID
            ip = device_id.split(':')[0] if ':' in device_id else device_id
            
            # Call the block_device method on the agentless collector
            future = asyncio.run_coroutine_threadsafe(
                self.agentless_collector.block_device(ip, block),
                asyncio.get_event_loop()
            )
            
            # Wait for the operation to complete
            success = future.result()
            
            if success:
                action = "blocked" if block else "unblocked"
                self.status_bar.showMessage(f"Successfully {action} device {ip}", 3000)
                self.refresh_agentless_devices()
            else:
                self.status_bar.showMessage(f"Failed to update device status", 3000)
                
        except Exception as e:
            logger.error(f"Error toggling device block status: {e}", exc_info=True)
            self.status_bar.showMessage(f"Error: {str(e)}", 5000)
    
    def update_agentless_ui(self):
        """Update the agentless collector UI with current stats."""
        try:
            if not hasattr(self, 'events_received') or not hasattr(self, 'bytes_received') or not hasattr(self, 'avg_rate'):
                return
                
            # Update events count
            self.events_received.setText(f"Events Received: {self.agentless_stats.get('events_received', 0)}")
            
            # Format bytes to human-readable format
            bytes_received = self.agentless_stats.get('bytes_received', 0)
            if bytes_received < 1024:
                bytes_str = f"{bytes_received} B"
            elif bytes_received < 1024 * 1024:
                bytes_str = f"{bytes_received/1024:.2f} KB"
            else:
                bytes_str = f"{bytes_received/(1024*1024):.2f} MB"
            
            self.bytes_received.setText(f"Data Received: {bytes_str}")
            
            # Calculate average rate
            if self.agentless_stats.get('start_time'):
                elapsed = (datetime.now() - self.agentless_stats['start_time']).total_seconds()
                if elapsed > 0:
                    rate = self.agentless_stats.get('events_received', 0) / elapsed
                    self.avg_rate.setText(f"Average Rate: {rate:.2f} events/sec")
                    
        except Exception as e:
            logging.error(f"Error in update_agentless_ui: {e}", exc_info=True)
            
            # Calculate and display average rate
            if self.agentless_stats.get('start_time') is not None:
                elapsed = (datetime.now() - self.agentless_stats['start_time']).total_seconds()
                if elapsed > 0:
                    rate = self.agentless_stats['events_received'] / elapsed
                    self.avg_rate.setText(f"Average Rate: {rate:.2f} events/sec")
            
            # Update connected devices if agentless collector is running
            if hasattr(self, 'agentless_collector') and self.agentless_collector is not None:
                try:
                    # Get connected devices from the agentless collector
                    devices = asyncio.run_coroutine_threadsafe(
                        self.agentless_collector.get_connected_devices(),
                        asyncio.get_event_loop()
                    ).result()
                    
                    # Update devices count
                    self.connected_devices_count.setText(f"Connected Devices: {len(devices)}")
                    
                    # Update devices table
                    self.devices_table.setRowCount(len(devices))
                    
                    for row, (device_id, device_info) in enumerate(devices.items()):
                        self.devices_table.setItem(row, 0, QTableWidgetItem(device_info.get('ip', 'N/A')))
                        self.devices_table.setItem(row, 1, QTableWidgetItem(device_info.get('type', 'unknown').upper()))
                        
                        first_seen = device_info.get('first_seen', datetime.now())
                        last_seen = device_info.get('last_seen', datetime.now())
                        
                        self.devices_table.setItem(row, 2, QTableWidgetItem(first_seen.strftime('%Y-%m-%d %H:%M:%S')))
                        self.devices_table.setItem(row, 3, QTableWidgetItem(last_seen.strftime('%Y-%m-%d %H:%M:%S')))
                        self.devices_table.setItem(row, 4, QTableWidgetItem(str(device_info.get('message_count', 0))))
                        
                        # Color code by last seen time (red if not seen in last 5 minutes)
                        if (datetime.now() - last_seen).total_seconds() > 300:  # 5 minutes
                            for col in range(self.devices_table.columnCount()):
                                self.devices_table.item(row, col).setBackground(QColor(255, 200, 200))  # Light red
                
                except Exception as e:
                    logging.error(f"Error updating connected devices: {e}", exc_info=True)
                    self.connected_devices_count.setText("Connected Devices: Error")
            else:
                # Clear the table if agentless collector is not running
                self.devices_table.setRowCount(0)
                self.connected_devices_count.setText("Connected Devices: 0")
                
        except Exception as e:
            logging.error(f"Error in update_agentless_ui: {e}", exc_info=True)
            
    def refresh_data(self):
        """Refresh all data in the UI."""
        current_tab = self.tab_widget.tabText(self.tab_widget.currentIndex())
        if current_tab == "Events":
            self.update_events_table()
        elif current_tab == "Alerts":
            self.update_alerts_table()
            
        # Update metrics
        self.update_metrics()
        
    def update_metrics(self):
        """Update the metrics display."""
        total_events = len(self.events)
        active_alerts = len([a for a in self.alerts if a.status != AlertStatus.RESOLVED])
        self.events_count_label.setText(f"Total Events: {total_events}")
        self.alerts_count_label.setText(f"Active Alerts: {active_alerts}")
        
    def update_events_table(self, limit: int = 100):
        """Update the events table with recent events."""
        try:
            self.events_table.setRowCount(0)
            events_to_show = self.events[-limit:]  # Show most recent events
            
            for event in events_to_show:
                row = self.events_table.rowCount()
                self.events_table.insertRow(row)
                
                # Add items to table
                self.events_table.setItem(row, 0, QTableWidgetItem(str(event.timestamp)))
                self.events_table.setItem(row, 1, QTableWidgetItem(event.source))
                self.events_table.setItem(row, 2, QTableWidgetItem(event.event_type))
                self.events_table.setItem(row, 3, QTableWidgetItem(event.severity.value))
                self.events_table.setItem(row, 4, QTableWidgetItem(event.description))
                
                # Color code by severity
                if event.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]:
                    color = QColor(255, 200, 200)  # Light red
                elif event.severity == EventSeverity.MEDIUM:
                    color = QColor(255, 255, 200)  # Light yellow
                else:
                    color = QColor(200, 255, 200)  # Light green
                    
                for col in range(self.events_table.columnCount()):
                    self.events_table.item(row, col).setBackground(color)
                    
            # Resize columns to content
            self.events_table.resizeColumnsToContents()
            
        except Exception as e:
            logging.error(f"Error updating events table: {e}")
            
    def update_alerts_table(self, limit: int = 100):
        """Update the alerts table with recent alerts."""
        try:
            self.alerts_table.setRowCount(0)
            alerts_to_show = self.alerts[-limit:]  # Show most recent alerts
            
            for alert in alerts_to_show:
                row = self.alerts_table.rowCount()
                self.alerts_table.insertRow(row)
                
                # Add items to table
                self.alerts_table.setItem(row, 0, QTableWidgetItem(str(alert.timestamp)))
                self.alerts_table.setItem(row, 1, QTableWidgetItem(alert.title))
                self.alerts_table.setItem(row, 2, QTableWidgetItem(alert.severity.value))
                self.alerts_table.setItem(row, 3, QTableWidgetItem(alert.status.value))
                self.alerts_table.setItem(row, 4, QTableWidgetItem(alert.source))
                
                # Color code by status
                if alert.status == AlertStatus.NEW:
                    color = QColor(255, 255, 200)  # Light yellow
                elif alert.status == AlertStatus.RESOLVED:
                    color = QColor(200, 255, 200)  # Light green
                else:
                    color = QColor(255, 200, 200)  # Light red
                    
                for col in range(self.alerts_table.columnCount()):
                    self.alerts_table.item(row, col).setBackground(color)
                    
            # Resize columns to content
            self.alerts_table.resizeColumnsToContents()
            
        except Exception as e:
            logging.error(f"Error updating alerts table: {e}")
        
    def apply_theme(self, theme_name):
        """Apply the specified theme to the application."""
        if theme_name == "dark":
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #2b2b2b;
                    color: #ffffff;
                }
                QTableWidget {
                    background-color: #3c3f41;
                    gridline-color: #4e4e4e;
                }
                QHeaderView::section {
                    background-color: #3c3f41;
                    color: #ffffff;
                    padding: 4px;
                    border: 1px solid #6c6c6c;
                }
                QTabBar::tab {
                    background: #3c3f41;
                    color: #ffffff;
                    padding: 8px;
                    border: 1px solid #6c6c6c;
                }
                QTabBar::tab:selected {
                    background: #4e4e4e;
                }
            """)
        else:  # Default light theme
            self.setStyleSheet("")
    
    def load_initial_data(self):
        """Load initial data from the database."""
        try:
            # Load events from database
            db_events = self.db.get_events(limit=1000)
            for event_data in db_events:
                event = SIEMEvent(
                    event_id=event_data['event_id'],
                    timestamp=datetime.fromisoformat(event_data['timestamp']),
                    source=event_data['source'],
                    event_type=event_data['event_type'],
                    severity=EventSeverity(event_data['severity']),
                    description=event_data['description'],
                    raw_data=json.loads(event_data['raw_data'])
                )
                self.events.append(event)
                self.event_manager.add_event(event)
            
            # Load alerts from database
            db_alerts = self.db.get_alerts(limit=1000)
            for alert_data in db_alerts:
                alert = Alert(
                    alert_id=alert_data['alert_id'],
                    timestamp=datetime.fromisoformat(alert_data['timestamp']),
                    source=alert_data['source'],
                    title=alert_data['title'],
                    description=alert_data['description'],
                    severity=EventSeverity(alert_data['severity']),
                    status=AlertStatus(alert_data['status']),
                    event_ids=json.loads(alert_data['event_ids'])
                )
                self.alerts.append(alert)
                
        except Exception as e:
            logging.error(f"Error loading initial data: {e}")
    
    def _generate_sample_data(self):
        """Generate sample events and save to database."""
        try:
            for i in range(10):
                event_data = {
                    'event_id': f'evt_{uuid.uuid4().hex[:8]}',
                    'timestamp': (datetime.now(timezone.utc) - timedelta(minutes=random.randint(0, 60))).isoformat(),
                    'source': random.choice(["firewall", "ids", "windows", "linux"]),
                    'event_type': random.choice(["login", "file_access", "network_alert"]),
                    'severity': random.choice(list(EventSeverity)).value,
                    'description': f"Sample event {i}",
                    'raw_data': json.dumps({"ip": f"192.168.1.{random.randint(1, 254)}"}),
                    'tags': json.dumps(["sample"])
                }
                sample_events.append(event_data)
                
                # Create event object
                SIEMEvent.add_event(event_data, self.db)
                
                # Randomly generate an alert for some events
                if random.random() > 0.7:
                    self._generate_sample_alert(event_data)
                    
        except Exception as e:
            logging.error(f"Error generating sample data: {e}")
    
    def _generate_sample_alert(self, event_data):
        """Generate a sample alert for the given event."""
        try:
            alert_data = {
                'alert_id': f'alert_{uuid.uuid4().hex[:8]}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'source': event_data['source'],
                'title': f"Suspicious {event_data['event_type']} detected",
                'description': f"{event_data['event_type'].capitalize()} from {event_data['source']} requires attention",
                'severity': event_data['severity'],
                'status': AlertStatus.NEW.value,
                'event_ids': json.dumps([event_data['event_id']]),
                'assigned_to': '',
                'notes': ''
            }
            
            # Create alert object
            Alert.add_alert(alert_data, self.db)
            
        except Exception as e:
            logging.error(f"Error generating sample alert: {e}")
            return None

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('siem.db')
        self.cursor = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                source TEXT,
                event_type TEXT,
                severity TEXT,
                description TEXT,
                raw_data TEXT,
                tags TEXT
            )
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                source TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                status TEXT,
                event_ids TEXT,
                assigned_to TEXT,
                notes TEXT
            )
        ''')
        self.conn.commit()

    def add_event(self, event_data: Dict[str, Any]) -> None:
        self.cursor.execute('''
            INSERT INTO events (id, timestamp, source, event_type, severity, description, raw_data, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_data['event_id'],
            event_data['timestamp'],
            event_data['source'],
            event_data['event_type'],
            event_data['severity'],
            event_data['description'],
            event_data['raw_data'],
            event_data['tags']
        ))
        self.conn.commit()

    def add_alert(self, alert_data: Dict[str, Any]) -> None:
        self.cursor.execute('''
            INSERT INTO alerts (id, timestamp, source, title, description, severity, status, event_ids, assigned_to, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data['alert_id'],
            alert_data['timestamp'],
            alert_data['source'],
            alert_data['title'],
            alert_data['description'],
            alert_data['severity'],
            alert_data['status'],
            alert_data['event_ids'],
            alert_data['assigned_to'],
            alert_data['notes']
        ))
        self.conn.commit()

    def get_events(self, limit: int = 100) -> list:
        self.cursor.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def get_alerts(self, limit: int = 100) -> list:
        self.cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
        return self.cursor.fetchall()

    def update_alert_status(self, alert_id: str, status: str, notes: str = None) -> None:
        self.cursor.execute('UPDATE alerts SET status = ?, notes = ? WHERE id = ?', (status, notes, alert_id))
        self.conn.commit()

    def toggle_auto_refresh(self, state):
        """Toggle auto-refresh of the events table."""
        if hasattr(self, 'refresh_timer'):
            self.refresh_timer.stop()
            
        if state == Qt.Checked:
            self.refresh_timer = QTimer()
            self.refresh_timer.timeout.connect(self.update_events_table)
            self.refresh_timer.start(5000)  # 5 seconds
            
    def apply_filters(self):
        """Apply filters to the events table."""
        try:
            filter_text = self.filter_text.text().lower()
            severity_filter = self.severity_filter.currentData()
            
            for row in range(self.events_table.rowCount()):
                show_row = True
                
                # Apply severity filter
                if severity_filter:
                    severity = self.events_table.item(row, 3).text().lower()
                    if severity != severity_filter:
                        show_row = False
                
                # Apply text filter
                if show_row and filter_text:
                    row_matches = False
                    for col in range(self.events_table.columnCount() - 1):  # Skip details column
                        item = self.events_table.item(row, col)
                        if item and filter_text in item.text().lower():
                            row_matches = True
                            break
                    show_row = row_matches
                
                # Show/hide row based on filters
                self.events_table.setRowHidden(row, not show_row)
                
            # Update status bar with visible count
            visible_rows = sum(1 for row in range(self.events_table.rowCount()) 
                             if not self.events_table.isRowHidden(row))
            self.status_bar.showMessage(f"Showing {visible_rows} of {self.events_table.rowCount()} events")
            
        except Exception as e:
            logging.error(f"Error applying filters: {e}")
            self.status_bar.showMessage(f"Error applying filters: {str(e)}")
            
    def show_event_context_menu(self, position):
        """Show context menu for event actions."""
        menu = QMenu()
        
        # Get selected rows
        selected_rows = set(index.row() for index in self.events_table.selectedIndexes())
        
        if selected_rows:
            copy_action = menu.addAction("Copy to Clipboard")
            copy_action.triggered.connect(lambda: self.copy_events_to_clipboard(selected_rows))
            
            # Add separator
            menu.addSeparator()
            
            # Add action to view event details
            if len(selected_rows) == 1:
                view_details = menu.addAction("View Details")
                view_details.triggered.connect(lambda: self.view_event_details(next(iter(selected_rows))))
        
        # Show the menu
        if menu.actions():
            menu.exec_(self.events_table.viewport().mapToGlobal(position))
    
    def copy_events_to_clipboard(self, rows):
        """Copy selected events to clipboard as tab-separated values."""
        try:
            clipboard = QApplication.clipboard()
            text = []
            
            # Get headers
            headers = []
            for col in range(self.events_table.columnCount() - 1):  # Skip details column
                headers.append(self.events_table.horizontalHeaderItem(col).text())
            text.append("\t".join(headers))
            
            # Get selected rows data
            for row in sorted(rows):
                if not self.events_table.isRowHidden(row):
                    row_data = []
                    for col in range(self.events_table.columnCount() - 1):  # Skip details column
                        item = self.events_table.item(row, col)
                        row_data.append(item.text() if item else "")
                    text.append("\t".join(row_data))
            
            # Copy to clipboard
            clipboard.setText("\n".join(text))
            self.status_bar.showMessage(f"Copied {len(rows)} events to clipboard")
            
        except Exception as e:
            logging.error(f"Error copying to clipboard: {e}")
            self.status_bar.showMessage(f"Error: {str(e)}")
    
    def view_event_details(self, row):
        """Show detailed view of a specific event."""
        try:
            # Get event ID if available
            event_id = self.events_table.item(row, 0).data(Qt.UserRole)
            
            # Get all event data from the database
            event_data = self.db.get_event_by_id(event_id) if event_id else {}
            
            # Create dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Event Details")
            dialog.setMinimumSize(600, 400)
            
            layout = QVBoxLayout(dialog)
            
            # Create text edit for displaying event data
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Courier", 10))
            
            # Format event data as JSON
            if event_data:
                text_edit.setPlainText(json.dumps(event_data, indent=2, default=str))
            else:
                # Fallback to table data if no DB access
                event_info = {}
                for col in range(self.events_table.columnCount() - 1):  # Skip details column
                    header = self.events_table.horizontalHeaderItem(col).text()
                    item = self.events_table.item(row, col)
                    event_info[header] = item.text() if item else ""
                text_edit.setPlainText(json.dumps(event_info, indent=2))
            
            # Add close button
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(dialog.reject)
            
            # Add widgets to layout
            layout.addWidget(text_edit)
            layout.addWidget(button_box)
            
            # Show the dialog
            dialog.exec_()
            
        except Exception as e:
            logging.error(f"Error showing event details: {e}")
            QMessageBox.critical(self, "Error", f"Failed to show event details: {str(e)}")
    
    def update_events_table(self, limit: int = 100):
        """Update the events table with recent events from the database."""
        try:
            # Get events from database
            events = self.db.get_events(limit=limit)
            
            # Store current scroll position and selection
            scroll_pos = self.events_table.verticalScrollBar().value()
            selected_rows = set(index.row() for index in self.events_table.selectedIndexes())
            
            # Clear existing rows
            self.events_table.setRowCount(0)
            
            # Add events to table
            for event_data in events:
                row = self.events_table.rowCount()
                self.events_table.insertRow(row)
                
                # Parse timestamp
                timestamp = datetime.fromisoformat(event_data['timestamp'])
                
                # Add items to table
                self.events_table.setItem(row, 0, QTableWidgetItem(timestamp.strftime('%Y-%m-%d %H:%M:%S')))
                self.events_table.setItem(row, 1, QTableWidgetItem(event_data.get('source', 'N/A')))
                self.events_table.setItem(row, 2, QTableWidgetItem(event_data.get('event_type', 'N/A')))
                self.events_table.setItem(row, 3, QTableWidgetItem(event_data.get('severity', 'info').capitalize()))
                self.events_table.setItem(row, 4, QTableWidgetItem(event_data.get('description', 'No description')))
                
                # Add details button
                details_btn = QPushButton("View")
                details_btn.clicked.connect(lambda checked, r=row: self.view_event_details(r))
                self.events_table.setCellWidget(row, 5, details_btn)
                
                # Store event ID in the first column's data
                if 'id' in event_data:
                    self.events_table.item(row, 0).setData(Qt.UserRole, event_data['id'])
                
                # Color code by severity
                severity = event_data.get('severity', 'info').lower()
                self._apply_severity_style(row, severity)
            
            # Apply filters
            self.apply_filters()
            
            # Restore scroll position and selection if possible
            if scroll_pos < self.events_table.verticalScrollBar().maximum():
                self.events_table.verticalScrollBar().setValue(scroll_pos)
                
            # Update status bar
            visible_rows = sum(1 for row in range(self.events_table.rowCount()) 
                             if not self.events_table.isRowHidden(row))
            self.status_bar.showMessage(f"Showing {visible_rows} of {len(events)} events")
            
        except Exception as e:
            logging.error(f"Error updating events table: {e}")
            self.status_bar.showMessage(f"Error: {str(e)}")
    
    def _apply_severity_style(self, row, severity):
        """Apply styling based on event severity."""
        if severity == 'critical':
            bg_color = QColor(255, 200, 200)  # Light red
            text_color = QColor(150, 0, 0)    # Dark red
        elif severity == 'high':
            bg_color = QColor(255, 220, 180)  # Light orange
            text_color = QColor(153, 76, 0)   # Dark orange
        elif severity == 'medium':
            bg_color = QColor(255, 255, 180)  # Light yellow
            text_color = QColor(153, 153, 0)  # Dark yellow
        elif severity == 'low':
            bg_color = QColor(220, 255, 220)  # Light green
            text_color = QColor(0, 100, 0)    # Dark green
        else:  # info or default
            bg_color = QColor(200, 230, 255)  # Light blue
            text_color = QColor(0, 0, 150)    # Dark blue
        
        # Apply colors to all cells in the row
        for col in range(self.events_table.columnCount() - 1):  # Skip details column
            item = self.events_table.item(row, col)
            if item:
                item.setBackground(bg_color)
                item.setForeground(text_color)
                item.setFont(QFont("Segoe UI", 9, QFont.Normal))

    def update_dashboard(self):
        """Update the dashboard with current metrics and charts."""
        try:
            # Get current data
            events = self.event_manager.get_events()
            alerts = self.event_manager.get_alerts()
            
            # Calculate metrics
            total_events = len(events)
            active_alerts = len([a for a in alerts if a.status not in [AlertStatus.RESOLVED, AlertStatus.DISMISSED]])
            high_severity = len([e for e in events if e.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]])
            threats_detected = len([a for a in alerts if a.severity in [EventSeverity.HIGH, EventSeverity.CRITICAL]])
            
            # Update metric widgets
            self.metrics['total_events'].findChild(QLabel).setText(f"{total_events:,}")
            self.metrics['active_alerts'].findChild(QLabel).setText(f"{active_alerts:,}")
            self.metrics['high_severity'].findChild(QLabel).setText(f"{high_severity:,}")
            self.metrics['threats_detected'].findChild(QLabel).setText(f"{threats_detected:,}")
            
            # Update event distribution pie chart
            event_counts = {}
            for sev in EventSeverity:
                event_counts[sev.value] = len([e for e in events if e.severity == sev])
            
            total = sum(event_counts.values()) or 1  # Avoid division by zero
            
            # Update pie chart slices
            series = self.event_dist_series
            for slice in series.slices():
                label = slice.label()
                if label in event_counts:
                    value = event_counts[label]
                    slice.setValue(value)
                    slice.setLabel(f"{label} ({value}, {value/total*100:.1f}%)")
            
            # Update alerts over time line chart
            now = datetime.now()
            hour_counts = [0] * 24
            
            for alert in alerts:
                # Make both datetimes timezone-aware for comparison
                alert_time = alert.timestamp.replace(tzinfo=timezone.utc) if alert.timestamp.tzinfo is None else alert.timestamp
                time_diff = now.astimezone(timezone.utc) - alert_time
                if time_diff.days < 1:  # Last 24 hours
                    hour_ago = int(time_diff.seconds / 3600)
                    if 0 <= hour_ago < 24:
                        hour_counts[23 - hour_ago] += 1
            
            # Update line series
            series = self.alerts_series
            series.clear()
            for i, count in enumerate(hour_counts):
                series.append(i, count)
            
            # Update event types bar chart
            event_types = {}
            for event in events:
                # Make both datetimes timezone-aware for comparison
                event_time = event.timestamp.replace(tzinfo=timezone.utc) if event.timestamp.tzinfo is None else event.timestamp
                time_diff = now.astimezone(timezone.utc) - event_time
                if time_diff.days < 1:  # Last 24 hours
                    event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            
            # Sort by count, descending, and take top 5
            top_event_types = sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]
            
            # Update bar series
            series = self.event_types_series
            series.clear()
            
            if hasattr(series, 'barSets') and series.barSets():
                bar_set = series.barSets()[0]
                bar_set.remove(0, bar_set.count())
            else:
                bar_set = QBarSet("Events")
                series.append(bar_set)
            
            categories = []
            for event_type, count in top_event_types:
                bar_set.append(count)
                categories.append(event_type)
            
            # Update chart axes
            chart = self.charts['event_types']
            axis_x = chart.axisX()
            if axis_x:
                axis_x.setCategories(categories)
            
            # Auto-scale Y axis
            axis_y = chart.axisY()
            if axis_y:
                max_value = max(bar_set.at(i) for i in range(bar_set.count())) if bar_set.count() > 0 else 10
                axis_y.setRange(0, max(10, max_value * 1.1))  # Add 10% padding
            
        except Exception as e:
            logger.error(f"Error updating dashboard: {e}", exc_info=True)
    
    def setup_timers(self):
        """Set up timers for periodic updates."""
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(self.config['ui']['refresh_interval'])
    
    def load_config(self):
        """Load configuration from file or use defaults."""
        # TODO: Implement configuration loading from file
        return DEFAULT_CONFIG
    
    def save_settings(self):
        """Save application settings."""
        try:
            if hasattr(self, 'theme_combo') and self.theme_combo is not None:
                self.config['ui']['theme'] = self.theme_combo.currentText().lower()
            if hasattr(self, 'refresh_spin') and self.refresh_spin is not None:
                self.config['ui']['refresh_interval'] = self.refresh_spin.value() * 1000  # Convert to ms
            return True
        except Exception as e:
            print(f"Error saving settings: {e}")
            return False
        
        # Update timer interval
        self.refresh_timer.setInterval(self.config['ui']['refresh_interval'])
        
        # Apply theme
        self.apply_theme(self.config['ui']['theme'])
        
        QMessageBox.information(self, "Settings", "Settings saved successfully!")
    
    def apply_theme(self, theme):
        """Apply the specified theme to the application."""
        if theme == 'dark':
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #2b2b2b;
                    color: #f0f0f0;
                }
                QTabWidget::pane {
                    border: 1px solid #3e3e3e;
                    border-radius: 3px;
                    padding: 5px;
                }
                QTabBar::tab {
                    background: #3e3e3e;
                    color: #f0f0f0;
                    padding: 8px 12px;
                    border: 1px solid #3e3e3e;
                    border-bottom: none;
                    border-top-left-radius: 3px;
                    border-top-right-radius: 3px;
                }
                QTabBar::tab:selected {
                    background: #2b2b2b;
                    border-color: #3e3e3e;
                }
                QTableWidget {
                    gridline-color: #3e3e3e;
                    background: #2b2b2b;
                    color: #f0f0f0;
                }
                QHeaderView::section {
                    background-color: #3e3e3e;
                    color: #f0f0f0;
                    padding: 5px;
                    border: 1px solid #3e3e3e;
                }
                QPushButton {
                    background-color: #3e3e3e;
                    color: #f0f0f0;
                    border: 1px solid #3e3e3e;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #4e4e4e;
                }
                QPushButton:pressed {
                    background-color: #2e2e2e;
                }
            """)
        else:  # Light theme
            self.setStyleSheet("""
                QMainWindow, QWidget {
                    background-color: #f0f0f0;
                    color: #333333;
                }
                QTabWidget::pane {
                    border: 1px solid #c0c0c0;
                    border-radius: 3px;
                    padding: 5px;
                }
                QTabBar::tab {
                    background: #e0e0e0;
                    color: #333333;
                    padding: 8px 12px;
                    border: 1px solid #c0c0c0;
                    border-bottom: none;
                    border-top-left-radius: 3px;
                    border-top-right-radius: 3px;
                }
                QTabBar::tab:selected {
                    background: #f0f0f0;
                    border-color: #c0c0c0;
                }
                QTableWidget {
                    gridline-color: #c0c0c0;
                    background: #ffffff;
                    color: #333333;
                }
                QHeaderView::section {
                    background-color: #e0e0e0;
                    color: #333333;
                    padding: 5px;
                    border: 1px solid #c0c0c0;
                }
                QPushButton {
                    background-color: #e0e0e0;
                    color: #333333;
                    border: 1px solid #c0c0c0;
                    padding: 5px 10px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #d0d0d0;
                }
                QPushButton:pressed {
                    background-color: #c0c0c0;
                }
            """)
    
    def refresh_data(self):
        """Refresh data in the UI."""
        # TODO: Implement data refresh logic
        pass
    
    def show_about_dialog(self):
        """Show the about dialog."""
        about_text = """
        <h2>Advanced SIEM GUI</h2>
        <p>Version: 1.0.0</p>
        <p>A modern, modular GUI for the SIEM system with enhanced features and improved user experience.</p>
        <p>© 2025 Security Ops Center</p>
        """
        QMessageBox.about(self, "About SIEM GUI", about_text)
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop timers and clean up resources
        self.refresh_timer.stop()
        
        # Save settings
        self.save_settings()
        
        # Accept the close event
        event.accept()

def main():
    """Main entry point for the SIEM GUI application."""
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = SIEMMainWindow()
    window.show()
    
    # Start the application event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
