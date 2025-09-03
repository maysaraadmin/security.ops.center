"""
Windows Event Forwarding (WEF) Management UI.
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
                           QPushButton, QGroupBox, QHeaderView, QMessageBox, QDialog,
                           QFormLayout, QLineEdit, QTextEdit, QLabel, QCheckBox, QComboBox)
from PyQt5.QtCore import Qt
import logging

class WEFManager(QWidget):
    """Windows Event Forwarding management interface."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the WEF management interface."""
        layout = QVBoxLayout(self)
        
        # Subscription Group
        sub_group = QGroupBox("Event Subscriptions")
        sub_layout = QVBoxLayout()
        
        # Subscription table
        self.subscription_table = QTableWidget()
        self.subscription_table.setColumnCount(5)
        self.subscription_table.setHorizontalHeaderLabels(
            ["Name", "Status", "Events", "Last Run", "Next Run"]
        )
        self.subscription_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.subscription_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Subscription buttons
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Subscription")
        self.edit_btn = QPushButton("Edit")
        self.delete_btn = QPushButton("Delete")
        self.refresh_btn = QPushButton("Refresh")
        
        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.refresh_btn)
        
        sub_layout.addWidget(self.subscription_table)
        sub_layout.addLayout(btn_layout)
        sub_group.setLayout(sub_layout)
        
        # Forwarding Status Group
        status_group = QGroupBox("Forwarding Status")
        status_layout = QVBoxLayout()
        
        # Status table
        self.status_table = QTableWidget()
        self.status_table.setColumnCount(5)
        self.status_table.setHorizontalHeaderLabels(
            ["Source", "Type", "Events", "Last Event", "Status"]
        )
        self.status_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        status_layout.addWidget(self.status_table)
        status_group.setLayout(status_layout)
        
        # Add groups to layout
        layout.addWidget(sub_group, 2)  # 2/3 of space
        layout.addWidget(status_group, 1)  # 1/3 of space
        
        # Connect signals
        self.add_btn.clicked.connect(self.add_subscription)
        self.edit_btn.clicked.connect(self.edit_subscription)
        self.delete_btn.clicked.connect(self.delete_subscription)
        self.refresh_btn.clicked.connect(self.refresh_status)
        
        # Load initial data
        self.refresh_status()
    
    def add_subscription(self):
        """Open dialog to add a new WEF subscription."""
        dialog = WEFSubscriptionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.save_subscription(dialog.get_subscription_data())
    
    def edit_subscription(self):
        """Edit the selected subscription."""
        selected = self.subscription_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "No Selection", "Please select a subscription to edit.")
            return
            
        # TODO: Load subscription data and pass to dialog
        dialog = WEFSubscriptionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.save_subscription(dialog.get_subscription_data())
    
    def delete_subscription(self):
        """Delete the selected subscription."""
        selected = self.subscription_table.selectedItems()
        if not selected:
            QMessageBox.information(self, "No Selection", "Please select a subscription to delete.")
            return
            
        reply = QMessageBox.question(
            self, 
            "Confirm Delete",
            "Are you sure you want to delete the selected subscription?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # TODO: Delete subscription
            self.refresh_status()
    
    def save_subscription(self, data):
        """Save subscription data."""
        try:
            # TODO: Save subscription to config
            self.refresh_status()
            return True
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save subscription: {str(e)}")
            return False
    
    def refresh_status(self):
        """Refresh subscription and status information."""
        try:
            # Clear tables
            self.subscription_table.setRowCount(0)
            self.status_table.setRowCount(0)
            
            # TODO: Load actual subscription data
            # For now, add sample data
            self.add_sample_data()
            
        except Exception as e:
            logging.error(f"Error refreshing WEF status: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to refresh status: {str(e)}")
    
    def add_sample_data(self):
        """Add sample data for demonstration."""
        # Sample subscription data
        subscriptions = [
            {"name": "Security Events", "status": "Active", "events": "Security", 
             "last_run": "2023-05-15 10:30:45", "next_run": "2023-05-15 11:30:45"},
            {"name": "System Events", "status": "Active", "events": "System", 
             "last_run": "2023-05-15 10:31:12", "next_run": "2023-05-15 11:31:12"},
        ]
        
        # Add subscriptions to table
        self.subscription_table.setRowCount(len(subscriptions))
        for row, sub in enumerate(subscriptions):
            self.subscription_table.setItem(row, 0, QTableWidgetItem(sub["name"]))
            self.subscription_table.setItem(row, 1, QTableWidgetItem(sub["status"]))
            self.subscription_table.setItem(row, 2, QTableWidgetItem(sub["events"]))
            self.subscription_table.setItem(row, 3, QTableWidgetItem(sub["last_run"]))
            self.subscription_table.setItem(row, 4, QTableWidgetItem(sub["next_run"]))
        
        # Sample status data
        status_data = [
            {"source": "WORKSTATION1", "type": "Windows 10", "events": "1,245", 
             "last_event": "2023-05-15 10:31:22", "status": "Active"},
            {"source": "SERVER1", "type": "Windows Server 2019", "events": "3,421", 
             "last_event": "2023-05-15 10:31:45", "status": "Active"},
            {"source": "WORKSTATION2", "type": "Windows 11", "events": "892", 
             "last_event": "2023-05-15 10:30:12", "status": "Warning"},
        ]
        
        # Add status to table
        self.status_table.setRowCount(len(status_data))
        for row, status in enumerate(status_data):
            self.status_table.setItem(row, 0, QTableWidgetItem(status["source"]))
            self.status_table.setItem(row, 1, QTableWidgetItem(status["type"]))
            self.status_table.setItem(row, 2, QTableWidgetItem(status["events"]))
            self.status_table.setItem(row, 3, QTableWidgetItem(status["last_event"]))
            
            # Set status with color coding
            status_item = QTableWidgetItem(status["status"])
            if status["status"] == "Active":
                status_item.setForeground(Qt.darkGreen)
            elif status["status"] == "Warning":
                status_item.setForeground(Qt.darkYellow)
            else:
                status_item.setForeground(Qt.red)
                
            self.status_table.setItem(row, 4, status_item)


class WEFSubscriptionDialog(QDialog):
    """Dialog for adding/editing WEF subscriptions."""
    
    def __init__(self, parent=None, subscription=None):
        super().__init__(parent)
        self.subscription = subscription or {}
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the subscription dialog UI."""
        self.setWindowTitle("WEF Subscription")
        self.setMinimumWidth(600)
        
        layout = QVBoxLayout(self)
        form = QFormLayout()
        
        # Subscription name
        self.name_edit = QLineEdit()
        form.addRow("Subscription Name:", self.name_edit)
        
        # Event log selection
        self.log_combo = QComboBox()
        self.log_combo.addItems(["Security", "System", "Application", "Setup", "Forwarded Events"])
        form.addRow("Event Log:", self.log_combo)
        
        # Query editor
        self.query_edit = QTextEdit()
        self.query_edit.setMinimumHeight(150)
        form.addRow("Query (WQL):", self.query_edit)
        
        # Set default query if new subscription
        if not self.subscription:
            default_query = """<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(Level=1 or Level=2 or Level=3 or Level=4)]]</Select>
  </Query>
</QueryList>"""
            self.query_edit.setPlainText(default_query)
        
        # Buttons
        btn_box = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.cancel_btn = QPushButton("Cancel")
        
        btn_box.addStretch()
        btn_box.addWidget(self.save_btn)
        btn_box.addWidget(self.cancel_btn)
        
        layout.addLayout(form)
        layout.addLayout(btn_box)
        
        # Connect signals
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn.clicked.connect(self.reject)
    
    def get_subscription_data(self):
        """Get the subscription data from the form."""
        return {
            "name": self.name_edit.text().strip(),
            "log": self.log_combo.currentText(),
            "query": self.query_edit.toPlainText().strip()
        }
