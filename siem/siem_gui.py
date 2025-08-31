"""
SIEM GUI - Security Information and Event Management (PyQt5 Version)

A modern, modular GUI for the SIEM system with enhanced features and improved user experience.
"""

import json
import logging
import os
import random
import sys
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
    QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
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
        self.setGeometry(100, 100, *DEFAULT_CONFIG['ui']['window_size'])
        
        # Initialize database
        self.db = get_database()
        
        # Initialize core components
        self.config = self.load_config()
        self.event_manager = EventManager()
        
        # Initialize data structures
        self.events = []
        self.alerts = []
        
        # Load initial data
        self.load_initial_data()
        
        # Initialize UI
        self.setup_ui()
        self.setup_connections()
        self.apply_theme(self.config['ui']['theme'])
        self.setup_timers()
    
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
            
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create central widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        
        # Dashboard Tab
        self.dashboard_tab = QWidget()
        self.setup_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        
        # Events Tab
        self.events_tab = QWidget()
        self.setup_events_tab()
        self.tabs.addTab(self.events_tab, "Events")
        
        # Alerts Tab
        self.alerts_tab = QWidget()
        self.setup_alerts_tab()
        self.tabs.addTab(self.alerts_tab, "Alerts")
        
        # Status Bar
        self.statusBar().showMessage("Ready")
        
    def setup_dashboard_tab(self):
        """Set up the dashboard tab with metrics and charts."""
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Add metrics
        metrics_layout = QHBoxLayout()
        self.events_count_label = QLabel("Total Events: 0")
        self.alerts_count_label = QLabel("Active Alerts: 0")
        metrics_layout.addWidget(self.events_count_label)
        metrics_layout.addWidget(self.alerts_count_label)
        layout.addLayout(metrics_layout)
        
        # Add charts area
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(self.chart_view)
        
    def setup_events_tab(self):
        """Set up the events tab with a table view."""
        layout = QVBoxLayout(self.events_tab)
        
        # Create table
        self.events_table = QTableWidget()
        self.events_table.setColumnCount(5)
        self.events_table.setHorizontalHeaderLabels(["Timestamp", "Source", "Type", "Severity", "Description"])
        self.events_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.events_table.verticalHeader().setVisible(False)
        
        layout.addWidget(self.events_table)
        
    def setup_alerts_tab(self):
        """Set up the alerts tab with a table view."""
        layout = QVBoxLayout(self.alerts_tab)
        
        # Create table
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(5)
        self.alerts_table.setHorizontalHeaderLabels(["Timestamp", "Title", "Severity", "Status", "Source"])
        self.alerts_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.alerts_table.verticalHeader().setVisible(False)
        
        layout.addWidget(self.alerts_table)
        
    def setup_connections(self):
        """Set up signal-slot connections."""
        # Connect menu actions
        self.tabs.currentChanged.connect(self.on_tab_changed)
        
    def setup_timers(self):
        """Set up timers for periodic updates."""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_data)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def on_tab_changed(self, index):
        """Handle tab change events."""
        if self.tabs.tabText(index) == "Events":
            self.update_events_table()
        elif self.tabs.tabText(index) == "Alerts":
            self.update_alerts_table()
            
    def refresh_data(self):
        """Refresh all data in the UI."""
        current_tab = self.tabs.tabText(self.tabs.currentIndex())
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

    def update_events_table(self, limit: int = 100):
        """Update the events table with recent events from the database."""
        try:
            # Get events from database
            events = self.db.get_events(limit=limit)
            
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
                self.events_table.setItem(row, 1, QTableWidgetItem(event_data['source']))
                self.events_table.setItem(row, 2, QTableWidgetItem(event_data['event_type']))
                self.events_table.setItem(row, 3, QTableWidgetItem(event_data['severity']))
                self.events_table.setItem(row, 4, QTableWidgetItem(event_data['description']))
                
                # Store event ID in the first column's data
                if 'id' in event_data:
                    self.events_table.item(row, 0).setData(Qt.UserRole, event_data['id'])
                
                # Color code by severity
                severity = event_data.get('severity', 'info').lower()
                if severity in ['high', 'critical']:
                    color = QColor(255, 200, 200)  # Light red
                elif severity == 'medium':
                    color = QColor(255, 255, 200)  # Light yellow
                else:
                    color = QColor(200, 255, 200)  # Light green
                    
                for col in range(self.events_table.columnCount()):
                    if self.events_table.item(row, col):
                        self.events_table.item(row, col).setBackground(color)
            
            # Resize columns to fit content
            self.events_table.resizeColumnsToContents()
            
        except Exception as e:
            logging.error(f"Error updating events table: {e}")
            
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
