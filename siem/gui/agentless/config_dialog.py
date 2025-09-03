"""
Configuration Dialog for Agentless Monitoring
-------------------------------------------
Provides a dialog for configuring agentless monitoring services.
"""
from typing import Dict, Any, Optional, Callable
from pathlib import Path

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                            QWidget, QLabel, QLineEdit, QSpinBox, QCheckBox,
                            QComboBox, QPushButton, QFormLayout, QMessageBox,
                            QFileDialog, QGroupBox, QTextEdit)
from PyQt5.QtCore import Qt, pyqtSignal

class ConfigDialog(QDialog):
    """Configuration dialog for agentless monitoring services."""
    
    config_saved = pyqtSignal(dict)  # Signal emitted when config is saved
    
    def __init__(self, config: Dict[str, Any], parent=None):
        """Initialize the configuration dialog.
        
        Args:
            config: Current configuration dictionary
            parent: Parent widget
        """
        super().__init__(parent)
        self.config = config.copy()
        self.setWindowTitle("Agentless Monitoring Configuration")
        self.setMinimumSize(800, 600)
        
        self.setup_ui()
        self.load_config()
        
    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        
        # Create tab widget for different configuration sections
        self.tabs = QTabWidget()
        
        # Syslog Configuration Tab
        self.syslog_tab = self.create_syslog_tab()
        self.tabs.addTab(self.syslog_tab, "Syslog")
        
        # SNMP Configuration Tab
        self.snmp_tab = self.create_snmp_tab()
        self.tabs.addTab(self.snmp_tab, "SNMP")
        
        # Windows Event Forwarding Tab
        self.wef_tab = self.create_wef_tab()
        self.tabs.addTab(self.wef_tab, "Windows Event Forwarding")
        
        layout.addWidget(self.tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.test_btn = QPushButton("Test Configuration")
        self.save_btn = QPushButton("Save")
        self.cancel_btn = QPushButton("Cancel")
        
        self.test_btn.clicked.connect(self.test_configuration)
        self.save_btn.clicked.connect(self.save_config)
        self.cancel_btn.clicked.connect(self.reject)
        
        button_layout.addWidget(self.test_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)
        
        layout.addLayout(button_layout)
    
    def create_syslog_tab(self) -> QWidget:
        """Create the Syslog configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Enable/Disable group
        group = QGroupBox("Syslog Server")
        form = QFormLayout()
        
        self.syslog_enabled = QCheckBox("Enable Syslog Server")
        self.syslog_host = QLineEdit()
        self.syslog_port = QSpinBox()
        self.syslog_port.setRange(1, 65535)
        self.syslog_protocol = QComboBox()
        self.syslog_protocol.addItems(["udp", "tcp"])
        
        form.addRow("Enabled:", self.syslog_enabled)
        form.addRow("Host:", self.syslog_host)
        form.addRow("Port:", self.syslog_port)
        form.addRow("Protocol:", self.syslog_protocol)
        
        group.setLayout(form)
        layout.addWidget(group)
        
        # Add a text area for custom syslog format
        format_group = QGroupBox("Message Format")
        format_layout = QVBoxLayout()
        self.syslog_format = QTextEdit()
        self.syslog_format.setPlaceholderText(
            "Enter custom syslog format (leave empty for default)\n"
            "Available variables: {timestamp}, {host}, {facility}, {severity}, {message}"
        )
        format_layout.addWidget(self.syslog_format)
        format_group.setLayout(format_layout)
        layout.addWidget(format_group)
        
        layout.addStretch()
        return tab
    
    def create_snmp_tab(self) -> QWidget:
        """Create the SNMP configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Enable/Disable group
        group = QGroupBox("SNMP Trap Receiver")
        form = QFormLayout()
        
        self.snmp_enabled = QCheckBox("Enable SNMP Trap Receiver")
        self.snmp_host = QLineEdit()
        self.snmp_port = QSpinBox()
        self.snmp_port.setRange(1, 65535)
        self.snmp_community = QLineEdit()
        self.snmp_community.setEchoMode(QLineEdit.Password)
        self.snmp_version = QComboBox()
        self.snmp_version.addItems(["1", "2c", "3"])
        
        form.addRow("Enabled:", self.snmp_enabled)
        form.addRow("Host:", self.snmp_host)
        form.addRow("Port:", self.snmp_port)
        form.addRow("Community:", self.snmp_community)
        form.addRow("Version:", self.snmp_version)
        
        group.setLayout(form)
        layout.addWidget(group)
        
        # SNMP v3 specific settings
        self.v3_group = QGroupBox("SNMP v3 Settings")
        v3_layout = QFormLayout()
        
        self.snmp_username = QLineEdit()
        self.snmp_auth_protocol = QComboBox()
        self.snmp_auth_protocol.addItems(["MD5", "SHA"])
        self.snmp_auth_key = QLineEdit()
        self.snmp_auth_key.setEchoMode(QLineEdit.Password)
        self.snmp_priv_protocol = QComboBox()
        self.snmp_priv_protocol.addItems(["DES", "AES"])
        self.snmp_priv_key = QLineEdit()
        self.snmp_priv_key.setEchoMode(QLineEdit.Password)
        
        v3_layout.addRow("Username:", self.snmp_username)
        v3_layout.addRow("Auth Protocol:", self.snmp_auth_protocol)
        v3_layout.addRow("Auth Key:", self.snmp_auth_key)
        v3_layout.addRow("Priv Protocol:", self.snmp_priv_protocol)
        v3_layout.addRow("Priv Key:", self.snmp_priv_key)
        
        self.v3_group.setLayout(v3_layout)
        self.v3_group.setEnabled(False)  # Disabled by default
        layout.addWidget(self.v3_group)
        
        # Connect version change signal
        self.snmp_version.currentTextChanged.connect(self.on_snmp_version_changed)
        
        layout.addStretch()
        return tab
    
    def create_wef_tab(self) -> QWidget:
        """Create the Windows Event Forwarding configuration tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Enable/Disable group
        group = QGroupBox("Windows Event Forwarding")
        form = QFormLayout()
        
        self.wef_enabled = QCheckBox("Enable Windows Event Forwarding")
        self.wef_server = QLineEdit()
        self.wef_username = QLineEdit()
        self.wef_password = QLineEdit()
        self.wef_password.setEchoMode(QLineEdit.Password)
        self.wef_domain = QLineEdit()
        
        form.addRow("Enabled:", self.wef_enabled)
        form.addRow("Server:", self.wef_server)
        form.addRow("Username:", self.wef_username)
        form.addRow("Password:", self.wef_password)
        form.addRow("Domain:", self.wef_domain)
        
        # Event query
        self.wef_query = QTextEdit()
        self.wef_query.setPlaceholderText(
            "Enter WQL query for event subscription\n"
            "Example: SELECT * FROM Win32_NTLogEvent WHERE Logfile='Security'"
        )
        
        group.setLayout(form)
        layout.addWidget(group)
        
        # Query group
        query_group = QGroupBox("Event Subscription Query")
        query_layout = QVBoxLayout()
        query_layout.addWidget(self.wef_query)
        query_group.setLayout(query_layout)
        layout.addWidget(query_group)
        
        # Test connection button
        test_btn = QPushButton("Test Connection")
        test_btn.clicked.connect(lambda: self.test_configuration())
        layout.addWidget(test_btn)
        
        layout.addStretch()
        return tab
    
    def on_snmp_version_changed(self, version: str):
        """Handle SNMP version change."""
        self.v3_group.setEnabled(version == "3")
    
    def load_config(self):
        """Load configuration into the UI."""
        # Syslog settings
        syslog = self.config.get('syslog', {})
        self.syslog_enabled.setChecked(syslog.get('enabled', False))
        self.syslog_host.setText(syslog.get('host', '0.0.0.0'))
        self.syslog_port.setValue(syslog.get('port', 514))
        self.syslog_protocol.setCurrentText(syslog.get('protocol', 'udp'))
        self.syslog_format.setPlainText(syslog.get('format', ''))
        
        # SNMP settings
        snmp = self.config.get('snmp', {})
        self.snmp_enabled.setChecked(snmp.get('enabled', False))
        self.snmp_host.setText(snmp.get('host', '0.0.0.0'))
        self.snmp_port.setValue(snmp.get('port', 162))
        self.snmp_community.setText(snmp.get('community', 'public'))
        self.snmp_version.setCurrentText(snmp.get('version', '2c'))
        
        # SNMP v3 settings
        self.snmp_username.setText(snmp.get('username', ''))
        self.snmp_auth_protocol.setCurrentText(snmp.get('auth_protocol', 'SHA'))
        self.snmp_auth_key.setText(snmp.get('auth_key', ''))
        self.snmp_priv_protocol.setCurrentText(snmp.get('priv_protocol', 'AES'))
        self.snmp_priv_key.setText(snmp.get('priv_key', ''))
        
        # WEF settings
        wef = self.config.get('windows_event_forwarding', {})
        self.wef_enabled.setChecked(wef.get('enabled', False))
        self.wef_server.setText(wef.get('server', ''))
        self.wef_username.setText(wef.get('username', ''))
        self.wef_password.setText(wef.get('password', ''))
        self.wef_domain.setText(wef.get('domain', ''))
        self.wef_query.setPlainText(wef.get('query', ''))
    
    def get_config(self) -> Dict[str, Any]:
        """Get configuration from the UI."""
        config = {}
        
        # Syslog settings
        config['syslog'] = {
            'enabled': self.syslog_enabled.isChecked(),
            'host': self.syslog_host.text(),
            'port': self.syslog_port.value(),
            'protocol': self.syslog_protocol.currentText(),
            'format': self.syslog_format.toPlainText()
        }
        
        # SNMP settings
        config['snmp'] = {
            'enabled': self.snmp_enabled.isChecked(),
            'host': self.snmp_host.text(),
            'port': self.snmp_port.value(),
            'community': self.snmp_community.text(),
            'version': self.snmp_version.currentText(),
            'username': self.snmp_username.text(),
            'auth_protocol': self.snmp_auth_protocol.currentText(),
            'auth_key': self.snmp_auth_key.text(),
            'priv_protocol': self.snmp_priv_protocol.currentText(),
            'priv_key': self.snmp_priv_key.text()
        }
        
        # WEF settings
        config['windows_event_forwarding'] = {
            'enabled': self.wef_enabled.isChecked(),
            'server': self.wef_server.text(),
            'username': self.wef_username.text(),
            'password': self.wef_password.text(),
            'domain': self.wef_domain.text(),
            'query': self.wef_query.toPlainText()
        }
        
        return config
    
    def validate_config(self) -> bool:
        """Validate the configuration."""
        config = self.get_config()
        
        # Add validation logic here
        # For example, check required fields, valid IPs, etc.
        
        return True
    
    def test_configuration(self):
        """Test the current configuration."""
        if not self.validate_config():
            return
            
        # Get the current tab to determine which service to test
        current_tab = self.tabs.currentIndex()
        
        if current_tab == 0:  # Syslog
            self.test_syslog_config()
        elif current_tab == 1:  # SNMP
            self.test_snmp_config()
        elif current_tab == 2:  # WEF
            self.test_wef_config()
    
    def test_syslog_config(self):
        """Test Syslog configuration."""
        QMessageBox.information(self, "Test", "Testing Syslog configuration...")
        # Implement actual test logic
        
    def test_snmp_config(self):
        """Test SNMP configuration."""
        QMessageBox.information(self, "Test", "Testing SNMP configuration...")
        # Implement actual test logic
        
    def test_wef_config(self):
        """Test WEF configuration."""
        QMessageBox.information(self, "Test", "Testing Windows Event Forwarding configuration...")
        # Implement actual test logic
    
    def save_config(self):
        """Save the configuration."""
        if not self.validate_config():
            return
            
        self.config = self.get_config()
        self.config_saved.emit(self.config)
        self.accept()


if __name__ == "__main__":
    import sys
    from PyQt5.QtWidgets import QApplication
    
    # Test the dialog
    app = QApplication(sys.argv)
    
    # Sample config
    config = {
        'syslog': {
            'enabled': True,
            'host': '0.0.0.0',
            'port': 514,
            'protocol': 'udp'
        },
        'snmp': {
            'enabled': False,
            'host': '0.0.0.0',
            'port': 162,
            'community': 'public',
            'version': '2c'
        },
        'windows_event_forwarding': {
            'enabled': False,
            'server': '',
            'username': '',
            'password': '',
            'domain': ''
        }
    }
    
    dialog = ConfigDialog(config)
    if dialog.exec_() == QDialog.Accepted:
        print("Configuration saved:", dialog.config)
    
    sys.exit(app.exec_())
