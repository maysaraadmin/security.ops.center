"""
DLP GUI Module (PyQt5 Version)

Provides a PyQt5-based graphical interface for the Data Loss Prevention system.
"""
import sys
import os
import logging
import queue
import threading
import time
import traceback
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Tuple, Callable, Coroutine
from pathlib import Path

# Configure logging before other imports
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dlp.gui')

# PyQt5 imports
try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                                QTabWidget, QLabel, QPushButton, QFileDialog, QMessageBox,
                                QTreeWidget, QTreeWidgetItem, QHeaderView, QSplitter, 
                                QTextEdit, QFormLayout, QLineEdit, QGroupBox, QComboBox,
                                QStatusBar, QAction, QMenu, QToolBar, QStyle, QProgressBar,
                                QTableWidget, QTableWidgetItem, QCheckBox, QListWidget, QListWidgetItem,
                                QSpinBox, QDialog, QDialogButtonBox)
    from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal, QObject, QSize, pyqtSlot, QEventLoop
    from PyQt5.QtGui import QIcon, QFont, QColor, QPalette, QTextCursor
except ImportError as e:
    logger.error("Failed to import PyQt5. Please install it with: pip install PyQt5")
    sys.exit(1)

# Local imports from dlp package
try:
    from dlp.core import DataType, ClassificationResult, DLPScanner
    from dlp.policies import PolicyEngine
except ImportError as e:
    logger.error("Failed to import DLP modules. Make sure the dlp package is properly installed.")
    logger.debug(f"Import error details: {str(e)}")
    logger.debug(f"Python path: {sys.path}")
    sys.exit(1)

logger = logging.getLogger('dlp.gui')

class ScanWorker(QObject):
    """Worker thread for running DLP scans."""
    progress = pyqtSignal(int, int, str)  # current, total, current_file
    result_ready = pyqtSignal(object)  # ClassificationResult
    finished = pyqtSignal()
    error = pyqtSignal(str)
    
    def __init__(self, scanner, paths=None, recursive=True, parent=None):
        super().__init__(parent)
        self.scanner = scanner
        self.paths = paths or []
        self.recursive = recursive
        self._is_running = True
        self._lock = threading.Lock()
    
    async def _process_file(self, file_path, total_files, current_index):
        """Process a single file asynchronously."""
        try:
            self.progress.emit(current_index + 1, total_files, file_path)
            
            # Create a queue to collect results
            results_queue = queue.Queue()
            
            # Define a callback that will be called when results are ready
            def on_result(result):
                results_queue.put(result)
                self.result_ready.emit(result)
            
            # Run the scan for each scanner
            for scanner in self.scanner.scanners:
                if not self._is_running:
                    break
                
                try:
                    # Run the scan
                    await self.scanner.scan(
                        [file_path],
                        callback=on_result,
                        interactive=False
                    )
                    
                except Exception as e:
                    error_msg = f"Error scanning {file_path}: {str(e)}"
                    self.error.emit(error_msg)
                    logger.error(error_msg, exc_info=True)
            
        except Exception as e:
            error_msg = f"Error processing {file_path}: {str(e)}"
            self.error.emit(error_msg)
            logger.error(error_msg, exc_info=True)
    
    def run(self):
        """Run the scan in a separate thread."""
        try:
            if not self.paths:
                self.error.emit("No paths specified for scanning")
                return
            
            # Get total number of files to scan
            file_paths = list(self._get_files_to_scan())
            total_files = len(file_paths)
            
            if total_files == 0:
                self.error.emit("No files found to scan")
                return
            
            # Create a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Process each file
            tasks = []
            for i, file_path in enumerate(file_paths):
                if not self._is_running:
                    break
                
                # Create a task for each file
                task = asyncio.ensure_future(self._process_file(file_path, total_files, i))
                tasks.append(task)
            
            # Run all tasks
            if tasks:
                loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
            
        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            self.error.emit(error_msg)
            logger.error(error_msg, exc_info=True)
            
        finally:
            # Clean up the event loop
            try:
                loop.close()
            except:
                pass
                
            self.finished.emit()
            
    def _get_files_to_scan(self):
        """Generate file paths to scan."""
        for path in self.paths:
            path = Path(path)
            if path.is_file():
                yield str(path.absolute())
            elif path.is_dir() and self.recursive:
                for root, _, files in os.walk(str(path)):
                    for file in files:
                        if not self._is_running:
                            return
                        file_path = Path(root) / file
                        if file_path.is_file():
                            yield str(file_path.absolute())
    
    def stop(self):
        """Stop the scan gracefully."""
        with self._lock:
            self._is_running = False

class DLPWindow(QMainWindow):
    """Main DLP GUI application window."""
    
    def __init__(self):
        """Initialize the DLP GUI."""
        super().__init__()
        
        # Initialize DLP components
        self.scanner = DLPScanner()
        self.policy_engine = PolicyEngine()
        
        # Data storage
        self.scan_results = []
        self.scan_worker = None
        self.scan_thread = None
        
        # Setup UI
        self.setup_ui()
        
        # Setup status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Set window properties
        self.setWindowTitle("Data Loss Prevention (PyQt5)")
        self.setGeometry(100, 100, 1200, 800)
    
    def setup_ui(self):
        """Initialize the main UI components."""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.setup_menu_bar()
        
        # Create toolbar
        self.setup_toolbar()
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create scan tab
        self.setup_scan_tab()
        
        # Create results tab
        self.setup_results_tab()
        
        # Create policies tab
        self.setup_policies_tab()
        
        # Create settings tab
        self.setup_settings_tab()
        
        # Create status bar
        self.setup_status_bar()
    
    def setup_menu_bar(self):
        """Set up the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Add scan actions
        scan_file_action = QAction('Scan &File...', self)
        scan_file_action.triggered.connect(self.scan_file)
        file_menu.addAction(scan_file_action)
        
        scan_dir_action = QAction('Scan &Directory...', self)
        scan_dir_action.triggered.connect(self.scan_directory)
        file_menu.addAction(scan_dir_action)
        
        file_menu.addSeparator()
        
        # Export actions
        export_results_action = QAction('&Export Results...', self)
        export_results_action.triggered.connect(self.export_results)
        file_menu.addAction(export_results_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        # Tools menu
        tools_menu = menubar.addMenu('&Tools')
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)
    
    def setup_toolbar(self):
        """Set up the toolbar."""
        toolbar = self.addToolBar('Main Toolbar')
        
        # Add scan file button
        scan_file_icon = self.style().standardIcon(QStyle.SP_FileIcon)
        scan_file_action = QAction(scan_file_icon, 'Scan File', self)
        scan_file_action.triggered.connect(self.scan_file)
        toolbar.addAction(scan_file_action)
        
        # Add scan directory button
        scan_dir_icon = self.style().standardIcon(QStyle.SP_DirIcon)
        scan_dir_action = QAction(scan_dir_icon, 'Scan Directory', self)
        scan_dir_action.triggered.connect(self.scan_directory)
        toolbar.addAction(scan_dir_action)
        
        toolbar.addSeparator()
        
        # Add stop scan button
        self.stop_scan_action = QAction('Stop Scan', self)
        self.stop_scan_action.setEnabled(False)
        self.stop_scan_action.triggered.connect(self.stop_scan)
        toolbar.addAction(self.stop_scan_action)
    
    def setup_scan_tab(self):
        """Set up the scan tab."""
        scan_tab = QWidget()
        layout = QVBoxLayout(scan_tab)
        
        # Add scan button
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.scan_directory)  # Default to directory scan
        button_layout.addWidget(self.scan_button)
        
        # Add stop button
        self.stop_scan_button = QPushButton("Stop Scan")
        self.stop_scan_button.setEnabled(False)
        self.stop_scan_button.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_scan_button)
        
        layout.addLayout(button_layout)
        
        # Add progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        # Add current file label
        self.current_file_label = QLabel("Ready to scan")
        layout.addWidget(self.current_file_label)
        
        # Add scan options group
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout()
        
        # Recursive scan checkbox
        self.recursive_checkbox = QCheckBox("Scan subdirectories")
        self.recursive_checkbox.setChecked(True)
        options_layout.addRow(self.recursive_checkbox)
        
        # File types to scan
        file_types_label = QLabel("File Types:")
        self.file_types_list = QListWidget()
        self.file_types_list.setSelectionMode(QListWidget.MultiSelection)
        self.file_types_list.addItems([
            "Documents (*.doc, *.docx, *.pdf, *.txt)",
            "Spreadsheets (*.xls, *.xlsx, *.csv)",
            "Presentations (*.ppt, *.pptx)",
            "Images (*.jpg, *.jpeg, *.png, *.bmp)",
            "Archives (*.zip, *.rar, *.7z)",
            "All Files (*.*)"
        ])
        # Select all by default
        for i in range(self.file_types_list.count()):
            self.file_types_list.item(i).setSelected(True)
        
        options_layout.addRow(file_types_label, self.file_types_list)
        
        # Add scan button
        scan_button = QPushButton("Start Scan")
        scan_button.clicked.connect(self.start_scan)
        
        options_layout.addRow(scan_button)
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Add progress group
        progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)
        
        # Current file label
        self.current_file_label = QLabel("Ready to scan...")
        progress_layout.addWidget(self.current_file_label)
        
        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setFont(QFont("Courier New", 10))
        progress_layout.addWidget(self.log_area)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group, 1)  # 1 is stretch factor
        
        # Add the tab
        self.tabs.addTab(scan_tab, "Scan")
    
    def setup_results_tab(self):
        """Set up the results tab."""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["File", "Sensitive Data", "Confidence", "Policy", "Actions"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        # Add context menu
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_results_context_menu)
        
        layout.addWidget(self.results_table)
        
        # Add the tab
        self.tabs.addTab(results_tab, "Results")
    
    def setup_policies_tab(self):
        """Set up the policies tab."""
        policies_tab = QWidget()
        layout = QVBoxLayout(policies_tab)
        
        # Add policy management UI here
        policy_label = QLabel("Data Protection Policies")
        policy_label.setAlignment(Qt.AlignCenter)
        policy_label.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(policy_label)
        
        # Add policy list
        self.policy_list = QListWidget()
        # Add sample policies (in a real app, these would come from the policy engine)
        self.policy_list.addItems([
            "Credit Card Numbers (PCI DSS)",
            "Social Security Numbers (US)",
            "Email Addresses",
            "Phone Numbers",
            "IP Addresses",
            "Custom Regular Expressions"
        ])
        
        # Set all items as checked by default
        for i in range(self.policy_list.count()):
            item = self.policy_list.item(i)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
        
        layout.addWidget(self.policy_list)
        
        # Add policy buttons
        button_layout = QHBoxLayout()
        
        add_policy_btn = QPushButton("Add Policy...")
        edit_policy_btn = QPushButton("Edit Policy")
        remove_policy_btn = QPushButton("Remove Policy")
        
        button_layout.addWidget(add_policy_btn)
        button_layout.addWidget(edit_policy_btn)
        button_layout.addWidget(remove_policy_btn)
        
        layout.addLayout(button_layout)
        
        # Add the tab
        self.tabs.addTab(policies_tab, "Policies")
    
    def setup_settings_tab(self):
        """Set up the settings tab."""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # Add settings form
        settings_group = QGroupBox("Application Settings")
        settings_layout = QFormLayout()
        
        # Log level
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        self.log_level_combo.setCurrentText("INFO")
        self.log_level_combo.currentTextChanged.connect(self.update_log_level)
        
        settings_layout.addRow("Log Level:", self.log_level_combo)
        
        # Auto-scan on startup
        self.auto_scan_checkbox = QCheckBox("Auto-scan on startup")
        settings_layout.addRow(self.auto_scan_checkbox)
        
        # Max file size
        self.max_file_size_spin = QSpinBox()
        self.max_file_size_spin.setRange(1, 1000)
        self.max_file_size_spin.setValue(10)
        self.max_file_size_spin.setSuffix(" MB")
        settings_layout.addRow("Max File Size:", self.max_file_size_spin)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Add save settings button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn, 0, Qt.AlignRight)
        
        # Add the tab
        self.tabs.addTab(settings_tab, "Settings")
    
    def setup_status_bar(self):
        """Set up the status bar."""
        # Add status labels
        self.status_label = QLabel("Ready")
        self.statusBar().addPermanentWidget(self.status_label)
        
        self.scan_status_label = QLabel("Scanned: 0")
        self.statusBar().addPermanentWidget(self.scan_status_label)
        
        self.matches_label = QLabel("Matches: 0")
        self.statusBar().addPermanentWidget(self.matches_label)
    
    def scan_file(self):
        """Open a file dialog to select files for scanning."""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Scan",
            "",
            "All Files (*.*);;Documents (*.doc *.docx *.pdf *.txt);;Spreadsheets (*.xls *.xlsx *.csv);;Presentations (*.ppt *.pptx)"
        )
        
        if file_paths:
            self.start_scan(file_paths)
    
    def scan_directory(self):
        """Open a directory dialog to select a directory for scanning."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Scan",
            "",
            QFileDialog.ShowDirsOnly | QFileDialog.DontResolveSymlinks
        )
        
        if dir_path:
            self.start_scan([dir_path])
    
    def start_scan(self, paths=None):
        """Start a new scan with the specified paths."""
        try:
            if paths:
                self.scan_paths = paths
                
            if not self.scan_paths:
                QMessageBox.warning(self, "No Paths", "No scan paths specified")
                return
                
            # Stop any existing scan
            self.stop_scan()
            
            # Clear previous results
            self.scan_results = []
            if hasattr(self, 'results_table'):
                self.results_table.setRowCount(0)
            
            # Get scan options
            recursive = self.recursive_checkbox.isChecked() if hasattr(self, 'recursive_checkbox') else True
            
            # Create and start worker thread
            self.scan_worker = ScanWorker(self.scanner, self.scan_paths, recursive=recursive)
            self.scan_thread = QThread()
            self.scan_worker.moveToThread(self.scan_thread)
            
            # Connect signals
            self.scan_worker.progress.connect(self.update_scan_progress)
            self.scan_worker.result_ready.connect(self.handle_scan_result)
            self.scan_worker.finished.connect(self.scan_finished)
            self.scan_worker.error.connect(self.scan_error)
            
            # Clean up thread when done
            self.scan_worker.finished.connect(self.scan_thread.quit)
            self.scan_worker.finished.connect(self.scan_worker.deleteLater)
            self.scan_thread.finished.connect(self.scan_thread.deleteLater)
            
            # Start the thread
            self.scan_thread.started.connect(self.scan_worker.run)
            self.scan_thread.start()
            
            # Update UI
            self.scan_button.setEnabled(False)
            self.stop_scan_button.setEnabled(True)
            if hasattr(self, 'stop_scan_action'):
                self.stop_scan_action.setEnabled(True)
                
            self.progress_bar.setMaximum(100)
            self.progress_bar.setValue(0)
            self.status_bar.showMessage("Scanning...")
            
        except Exception as e:
            logger.error("Failed to start scan", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
            
            # Reset UI on error
            self.scan_button.setEnabled(True)
            self.stop_scan_button.setEnabled(False)
            if hasattr(self, 'stop_scan_action'):
                self.stop_scan_action.setEnabled(False)
    
    def stop_scan(self):
        """Stop the current scan if one is running."""
        try:
            if hasattr(self, 'scan_worker') and self.scan_worker is not None:
                # Signal the worker to stop
                self.scan_worker.stop()
                
                # Wait for the thread to finish with a timeout
                if hasattr(self, 'scan_thread') and self.scan_thread and self.scan_thread.isRunning():
                    self.scan_thread.quit()
                    if not self.scan_thread.wait(2000):  # Wait up to 2 seconds
                        self.scan_thread.terminate()
                        self.scan_thread.wait()
                
                # Clean up
                self.scan_worker = None
                self.scan_thread = None
            
            # Update UI
            if hasattr(self, 'scan_button'):
                self.scan_button.setEnabled(True)
            if hasattr(self, 'stop_scan_button'):
                self.stop_scan_button.setEnabled(False)
            if hasattr(self, 'stop_scan_action'):
                self.stop_scan_action.setEnabled(False)
                
            self.status_bar.showMessage("Scan stopped")
            logger.info("Scan stopped by user")
            
        except Exception as e:
            logger.error("Error stopping scan", exc_info=True)
            self.status_bar.showMessage("Error stopping scan")
            
            # Make sure UI is in a consistent state even if there's an error
            if hasattr(self, 'scan_button'):
                self.scan_button.setEnabled(True)
            if hasattr(self, 'stop_scan_button'):
                self.stop_scan_button.setEnabled(False)
            if hasattr(self, 'stop_scan_action'):
                self.stop_scan_action.setEnabled(False)
            self.status_label.setText("Scan stopped by user")
            self.log_message("Scan stopped by user")
    
    def update_scan_progress(self, current, total, current_file):
        """Update the progress bar and current file label."""
        if total > 0:
            progress = int((current / total) * 100)
            self.progress_bar.setValue(progress)
        
        self.current_file_label.setText(f"Scanning: {current_file}")
        self.scan_status_label.setText(f"Scanned: {current}")
    
    def handle_scan_result(self, result):
        """Handle a scan result from the worker thread."""
        self.scan_results.append(result)
        self.update_results_table()
        
        # Log the finding
        for match in result.matches:
            self.log_message(f"Found {match.data_type.value} in {result.file_path} (Confidence: {match.confidence:.1%})")
        
        # Update status
        total_matches = sum(len(r.matches) for r in self.scan_results)
        self.matches_label.setText(f"Matches: {total_matches}")
    
    def scan_finished(self):
        """Handle scan completion."""
        self.scan_thread.quit()
        self.scan_thread.wait()
        
        self.stop_scan_action.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan completed")
        self.log_message("Scan completed")
        
        # Show notification if we found matches
        total_matches = sum(len(r.matches) for r in self.scan_results)
        if total_matches > 0:
            QMessageBox.information(
                self,
                "Scan Complete",
                f"Scan completed with {total_matches} potential data leak(s) found.",
                QMessageBox.Ok
            )
        else:
            QMessageBox.information(
                self,
                "Scan Complete",
                "Scan completed. No sensitive data found.",
                QMessageBox.Ok
            )
    
    def scan_error(self, error_message):
        """Handle scan errors."""
        self.scan_thread.quit()
        self.stop_scan_action.setEnabled(False)
        
        QMessageBox.critical(
            self,
            "Scan Error",
            f"An error occurred during scanning:\n{error_message}",
            QMessageBox.Ok
        )
        
        self.status_label.setText("Scan error")
        self.log_message(f"ERROR: {error_message}")
    
    def update_results_table(self):
        """Update the results table with the latest scan results."""
        self.results_table.setRowCount(0)  # Clear the table
        
        for result in self.scan_results:
            for match in result.matches:
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # File path
                file_item = QTableWidgetItem(result.file_path)
                file_item.setData(Qt.UserRole, result)  # Store the full result object
                
                # Data type
                data_type_item = QTableWidgetItem(match.data_type.value)
                
                # Confidence
                confidence_item = QTableWidgetItem(f"{match.confidence:.1%}")
                
                # Policy
                policy_item = QTableWidgetItem(match.policy_name or "Default")
                
                # Actions
                actions_widget = QWidget()
                actions_layout = QHBoxLayout()
                actions_layout.setContentsMargins(5, 2, 5, 2)
                
                view_btn = QPushButton("View")
                view_btn.setProperty("file_path", result.file_path)
                view_btn.setProperty("match_index", result.matches.index(match))
                view_btn.clicked.connect(self.view_match_details)
                
                actions_layout.addWidget(view_btn)
                actions_layout.addStretch()
                
                actions_widget.setLayout(actions_layout)
                
                # Add items to the table
                self.results_table.setItem(row, 0, file_item)
                self.results_table.setItem(row, 1, data_type_item)
                self.results_table.setItem(row, 2, confidence_item)
                self.results_table.setItem(row, 3, policy_item)
                self.results_table.setCellWidget(row, 4, actions_widget)
    
    def view_match_details(self):
        """Show details for a specific match."""
        button = self.sender()
        if not button:
            return
        
        file_path = button.property("file_path")
        match_index = button.property("match_index")
        
        # Find the result and match
        result = next((r for r in self.scan_results if r.file_path == file_path), None)
        if not result or match_index >= len(result.matches):
            return
        
        match = result.matches[match_index]
        
        # Show details in a dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Match Details")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        # File info
        file_group = QGroupBox("File Information")
        file_layout = QFormLayout()
        
        file_layout.addRow("File:", QLabel(result.file_path))
        file_layout.addRow("Size:", QLabel(f"{os.path.getsize(result.file_path):,} bytes"))
        file_layout.addRow("Last Modified:", QLabel(time.ctime(os.path.getmtime(result.file_path))))
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Match details
        match_group = QGroupBox("Match Details")
        match_layout = QFormLayout()
        
        match_layout.addRow("Data Type:", QLabel(match.data_type.value))
        match_layout.addRow("Confidence:", QLabel(f"{match.confidence:.1%}"))
        match_layout.addRow("Policy:", QLabel(match.policy_name or "Default"))
        
        # Add context (if available)
        if match.context:
            context_text = QTextEdit()
            context_text.setReadOnly(True)
            context_text.setPlainText(match.context)
            context_text.setLineWrapMode(QTextEdit.NoWrap)
            context_text.setFont(QFont("Courier New", 10))
            match_layout.addRow("Context:", context_text)
        
        match_group.setLayout(match_layout)
        layout.addWidget(match_group, 1)  # Stretch factor
        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(dialog.accept)
        layout.addWidget(button_box)
        
        dialog.exec_()
    
    def export_results(self):
        """Export scan results to a file."""
        if not self.scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "CSV Files (*.csv);;Text Files (*.txt)"
        )
        
        if not file_path:
            return  # User cancelled
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # Write header
                f.write("File,Data Type,Confidence,Policy,Context\n")
                
                # Write data
                for result in self.scan_results:
                    for match in result.matches:
                        # Escape quotes and commas in the context
                        context = (match.context or "").replace('"', '""').replace('\n', ' ').replace('\r', '')
                        
                        f.write(
                            f'"{result.file_path}",'
                            f'"{match.data_type.value}",'
                            f'"{match.confidence:.1%}",'
                            f'"{match.policy_name or "Default"}",'
                            f'"{context}"\n'
                        )
            
            QMessageBox.information(
                self,
                "Export Complete",
                f"Results exported to:\n{file_path}",
                QMessageBox.Ok
            )
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export results:\n{str(e)}",
                QMessageBox.Ok
            )
    
    def show_results_context_menu(self, position):
        """Show context menu for results table."""
        item = self.results_table.itemAt(position)
        if not item:
            return
        
        row = item.row()
        file_path = self.results_table.item(row, 0).text()
        
        menu = QMenu()
        
        view_action = menu.addAction("View Details")
        copy_path_action = menu.addAction("Copy File Path")
        open_file_action = menu.addAction("Open File Location")
        
        action = menu.exec_(self.results_table.viewport().mapToGlobal(position))
        
        if action == view_action:
            # Simulate clicking the view button
            button = self.results_table.cellWidget(row, 4).findChild(QPushButton)
            if button:
                button.click()
        
        elif action == copy_path_action:
            QApplication.clipboard().setText(file_path)
            self.statusBar().showMessage(f"Copied to clipboard: {file_path}", 3000)
        
        elif action == open_file_location:
            if os.path.exists(file_path):
                if os.name == 'nt':  # Windows
                    os.startfile(os.path.dirname(file_path))
                else:  # macOS and Linux
                    import subprocess
                    subprocess.Popen(['xdg-open', os.path.dirname(file_path)])
    
    def update_log_level(self, level):
        """Update the logging level."""
        level = getattr(logging, level.upper())
        logging.getLogger().setLevel(level)
        self.statusBar().showMessage(f"Log level set to: {logging.getLevelName(level)}", 3000)
    
    def save_settings(self):
        """Save application settings."""
        # In a real app, you would save these settings to a config file
        QMessageBox.information(
            self,
            "Settings Saved",
            "Your settings have been saved.",
            QMessageBox.Ok
        )
    
    def log_message(self, message):
        """Add a message to the log area with a timestamp."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        self.log_area.append(log_entry)
        
        # Auto-scroll to bottom
        self.log_area.verticalScrollBar().setValue(
            self.log_area.verticalScrollBar().maximum()
        )
    
    def show_about_dialog(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About DLP Scanner",
            "<h2>Data Loss Prevention Scanner</h2>"
            "<p>Version 1.0.0</p>"
            "<p>A PyQt5-based application for detecting sensitive data in files.</p>"
            "<p>© 2025 Security Ops Center</p>"
        )
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop any running scans
        if hasattr(self, 'scan_worker') and self.scan_worker:
            self.scan_worker.stop()
            
            if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
                self.scan_thread.quit()
                self.scan_thread.wait(2000)  # Wait up to 2 seconds
        
        event.accept()

def suppress_qt_warnings():
    """Suppress Qt warning messages."""
    import os
    # Suppress various Qt warnings
    os.environ["QT_LOGGING_RULES"] = "qt.qpa.window=false;qt.qpa.xcb.window=false"
    os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.*.debug=false"
    # Disable Qt debug messages
    os.environ["QT_LOGGING_RULES"] = "*.debug=false"
    # Suppress specific warnings
    os.environ["QT_LOGGING_RULES"] = "qt.qpa.*=false"

def main():
    """
    Main entry point for the DLP GUI application.
    """
    # Suppress Qt warnings
    suppress_qt_warnings()
    
    # Suppress specific Python warnings
    import warnings
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("dlp_scanner.log")
        ]
    )
    
    # Create the application
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the main window
    window = DLPWindow()
    window.show()
    
    # Run the application
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
