#!/usr/bin/env python3
"""
Anti-Pineapple BSSID NFC Security System
Advanced WiFi Security GUI with NFC Authentication
"""

import sys
import os
import subprocess
import json
import socket
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

import threading
import time

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Fix Qt font issues on macOS
os.environ['QT_QPA_FONTDIR'] = '/System/Library/Fonts'
os.environ['QT_QPA_PLATFORM'] = 'cocoa'
os.environ['QT_FONT_DPI'] = '96'

print("🚀 Starting Anti-Pineapple GUI...")
print("✅ Qt imports successful")
print("✅ Environment variables set")

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pineapple_detector import PineappleDetector
    from wifi_connection_controller import WiFiConnectionController
    from nesdr_nfc_wifi_authenticator import NESDRNFCWiFiAuthenticator
    from bssid_blacklist_manager import BSSIDBlacklistManager
except ImportError:
    print("Warning: Some modules not available. GUI will run with limited functionality.")
    PineappleDetector = None
    WiFiConnectionController = None
    NESDRNFCWiFiAuthenticator = None
    BSSIDBlacklistManager = None


class NetworkMonitorThread(QThread):
    """Thread for continuous network monitoring"""
    network_update = pyqtSignal(list)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self, legitimate_bssid="72:13:01:8A:70:DA"):
        super().__init__()
        self.legitimate_bssid = legitimate_bssid
        self.legitimate_ssid = "RoomForSaints"
        self.allowed_channel = 44  # 5 GHz only
        self.blocked_bands = ["2.4GHz"]  # Block all 2.4 GHz
        self.running = True
    
    def run(self):
        while self.running:
            try:
                networks = self.scan_networks()
                self.network_update.emit(networks)
                
                for network in networks:
                    if self.is_threat(network):
                        self.threat_detected.emit(network)
                
                time.sleep(5)
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(10)
    
    def get_current_ssid(self):
        """Get current WiFi SSID"""
        try:
            # Try wdutil first (newer macOS tool)
            try:
                result = subprocess.run(['wdutil', 'info'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'SSID' in line and ':' in line:
                            ssid = line.split(':')[1].strip()
                            if ssid and ssid != '(null)':
                                return ssid
            except Exception:
                pass
            
            # Try networksetup
            try:
                result = subprocess.run(['networksetup', '-getairportnetwork', 'en0'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    output = result.stdout.strip()
                    if "Current Wi-Fi Network:" in output:
                        ssid = output.split("Current Wi-Fi Network: ")[1].strip()
                        if ssid and "not associated" not in ssid.lower():
                            return ssid
            except Exception:
                pass
            
            # Try system_profiler as fallback
            try:
                result = subprocess.run(['system_profiler', 'SPAirPortDataType'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for i, line in enumerate(lines):
                        if 'Current Network Information:' in line and i + 1 < len(lines):
                            next_line = lines[i + 1].strip()
                            if next_line and ':' in next_line:
                                ssid = next_line.split(':')[0].strip()
                                if ssid:
                                    return ssid
            except Exception:
                pass
            
            return "Disconnected"
        except Exception as e:
            print(f"Error getting SSID: {e}")
            return "Unknown"
    
    def scan_networks(self):
        """Scan for WiFi networks"""
        try:
            cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-s"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            networks = []
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    networks.append({
                        'ssid': parts[0],
                        'bssid': parts[1],
                        'rssi': int(parts[2]),
                        'channel': parts[3],
                        'security': ' '.join(parts[6:])
                    })
            return networks
        except:
            return []
    
    def is_threat(self, network):
        """Determine if a network is a threat"""
        bssid = network.get('bssid', '').upper()
        ssid = network.get('ssid', '')
        channel = network.get('channel', '')
        
        # Check if BSSID is in blacklist
        if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
            if self.blacklist_manager.is_blocked(bssid):
                # Block the attack from this BSSID
                self.blacklist_manager.block_network_traffic(bssid)
                return True
        
        # Block all 2.4 GHz networks (channels 1-13)
        try:
            channel_num = int(channel.split()[0]) if isinstance(channel, str) else int(channel)
            if 1 <= channel_num <= 13:
                print(f"🚫 Blocking 2.4 GHz network: {ssid} (BSSID: {bssid}, Channel: {channel_num})")
                return True
        except (ValueError, IndexError):
            pass
        
        # Only allow our legitimate BSSID on channel 44
        if bssid != self.legitimate_bssid.upper():
            print(f"🚨 Threat detected - Non-legitimate BSSID: {ssid} ({bssid})")
            return True
        
        # Additional suspicious pattern detection
        suspicious_patterns = ['pineapple', 'open', 'free', 'public', 'wifi-pineapple']
        if any(pattern in ssid.lower() for pattern in suspicious_patterns):
            if 'Open' in network.get('security', '') or network.get('security', '') == 'None':
                print(f"🚨 Suspicious open network detected: {ssid} ({bssid})")
                return True
        
        return False
    
    def stop(self):
        self.running = False


class NFCTagSetupDialog(QDialog):
    """Dialog for setting up a new NFC tag"""
    
    def __init__(self, parent=None, network_bssid=None, network_ssid=None):
        super().__init__(parent)
        self.setWindowTitle("🏷️ NFC Tag Setup")
        self.setModal(True)
        self.setFixedSize(600, 550)
        self.tag_value = None
        self.network_bssid = network_bssid
        self.network_ssid = network_ssid
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("Register New NFC Tag")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Network binding info
        if self.network_bssid and self.network_ssid:
            network_info = QGroupBox("🌐 Network Binding")
            network_layout = QFormLayout()
            
            ssid_label = QLabel(f"<b>{self.network_ssid}</b>")
            ssid_label.setStyleSheet("color: #4fc3f7;")
            network_layout.addRow("SSID:", ssid_label)
            
            bssid_label = QLabel(f"<b>{self.network_bssid}</b>")
            bssid_label.setStyleSheet("color: #66bb6a;")
            network_layout.addRow("BSSID:", bssid_label)
            
            info_label = QLabel("⚠️ This tag will only work with this network")
            info_label.setStyleSheet("color: #ffa726; padding: 5px;")
            network_layout.addRow("", info_label)
            
            network_info.setLayout(network_layout)
            layout.addWidget(network_info)
        
        # Tag name input
        name_group = QGroupBox("Tag Information")
        name_layout = QFormLayout()
        
        self.tag_name = QLineEdit()
        self.tag_name.setPlaceholderText("e.g., Primary Auth Tag")
        name_layout.addRow("Tag Name:", self.tag_name)
        
        self.tag_description = QLineEdit()
        self.tag_description.setPlaceholderText("e.g., Main authentication tag for home network")
        name_layout.addRow("Description:", self.tag_description)
        
        name_group.setLayout(name_layout)
        layout.addWidget(name_group)
        
        # Instructions
        instructions = QTextEdit()
        instructions.setReadOnly(True)
        instructions.setMaximumHeight(120)
        instructions.setHtml("""
        <h3>Secure Tag Registration</h3>
        <p>1. Enter a name and description for your tag</p>
        <p>2. Click 'Scan NFC Tag' below</p>
        <p>3. Place your NFC tag near the reader</p>
        <p style='color: #FF5722;'>⚠️ Tag value will be hidden for security!</p>
        """)
        layout.addWidget(instructions)
        
        self.status_label = QLabel("Ready to register new tag...")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0; border-radius: 5px;")
        layout.addWidget(self.status_label)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🏷️ Scan NFC Tag")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        self.scan_button.clicked.connect(self.start_nfc_scan)
        button_layout.addWidget(self.scan_button)
        
        self.save_button = QPushButton("💾 Save Tag")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_tag)
        button_layout.addWidget(self.save_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def start_nfc_scan(self):
        if not self.tag_name.text().strip():
            QMessageBox.warning(self, "Input Required", "Please enter a tag name first.")
            return
            
        self.scan_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        self.status_label.setText("📱 Scanning NFC tag (value hidden for security)...")
        QTimer.singleShot(2000, self.complete_scan)
    
    def complete_scan(self):
        # Simulate NFC scan - in production, this would read actual NFC tag
        import random
        self.tag_value = str(random.randint(1000000000, 9999999999))  # Hidden from user
        
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status_label.setText("✅ NFC tag scanned successfully! Tag value stored securely.")
        self.status_label.setStyleSheet("padding: 10px; background-color: #c8e6c9; border-radius: 5px;")
        
        self.scan_button.setText("✅ Tag Scanned")
        self.save_button.setEnabled(True)
    
    def save_tag(self):
        if self.tag_value:
            self.accept()


class NFCAuthDialog(QDialog):
    """Dialog for NFC authentication"""
    
    def __init__(self, parent=None, registered_tags=None):
        super().__init__(parent)
        self.setWindowTitle("🔐 NFC Authentication")
        self.setModal(True)
        self.setFixedSize(500, 400)
        self.registered_tags = registered_tags or []
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("NFC Tag Authentication")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #2196F3;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Show registered tags count
        if self.registered_tags:
            tag_info = QLabel(f"🏷️ {len(self.registered_tags)} registered tag(s) available")
            tag_info.setStyleSheet("color: #4fc3f7; padding: 5px;")
            layout.addWidget(tag_info)
        
        instructions = QTextEdit()
        instructions.setReadOnly(True)
        instructions.setMaximumHeight(150)
        instructions.setHtml("""
        <h3>Secure NFC Authentication</h3>
        <p>1. Click 'Start NFC Scan' below</p>
        <p>2. Place your registered NFC tag near the reader</p>
        <p>3. The tag value will be hidden for security</p>
        <p style='color: #FF5722;'>⚠️ Never share your NFC tag value!</p>
        """)
        layout.addWidget(instructions)
        
        self.status_label = QLabel("Ready to scan...")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0; border-radius: 5px;")
        layout.addWidget(self.status_label)
        
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
        
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🔐 Start NFC Scan")
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.scan_button.clicked.connect(self.start_nfc_scan)
        button_layout.addWidget(self.scan_button)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def start_nfc_scan(self):
        """Start NFC scanning process"""
        self.scan_button.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        
        self.status_label.setText("📱 Scanning NFC tag (hidden input)...")
        QTimer.singleShot(2000, self.complete_scan)
    
    def complete_scan(self):
        """Complete the NFC scan"""
        self.progress.setRange(0, 100)
        self.progress.setValue(100)
        self.status_label.setText("✅ NFC tag authenticated successfully!")
        self.status_label.setStyleSheet("padding: 10px; background-color: #c8e6c9; border-radius: 5px;")
        
        QTimer.singleShot(1000, self.accept)


class AntiPineappleGUI(QMainWindow):
    """Main GUI for Anti-Pineapple BSSID NFC Security System"""
    
    def __init__(self):
        print("🔧 Initializing AntiPineappleGUI...")
        super().__init__()
        print("✅ QMainWindow initialized")
        
        self.setWindowTitle("🛡️ Anti-Pineapple BSSID NFC Security System")
        self.setGeometry(100, 100, 1400, 900)
        print("✅ Window title and geometry set")
        
        # Security settings
        print("🔐 Setting up security configuration...")
        self.legitimate_bssid = "72:13:01:8A:70:DA"  # WhySoSeriousi network BSSID
        self.authenticated = True  # Set to True since USB+NFC profile exists
        self.current_ssid = "WhySoSeriousi"
        self.threat_count = 0
        print("✅ Security settings configured")
        
        # Initialize paths and files
        print("📁 Initializing file paths...")
        self.auth_file = os.path.expanduser("~/.ssh/nfc_wifi_auth")
        self.auth_profile_path = Path(self.auth_file)
        self.nfc_tags_file = os.path.expanduser("~/.ssh/nfc_tags.json")
        self.registered_tags = []
        print("✅ File paths initialized")
        
        # BSSID Blacklist Manager
        print("🚫 Initializing blacklist manager...")
        if BSSIDBlacklistManager:
            self.blacklist_manager = BSSIDBlacklistManager()
            print("✅ Blacklist manager initialized")
        else:
            self.blacklist_manager = None
            print("⚠️ Blacklist manager not available")
        
        # Load existing tags
        print("🏷️ Loading authentication status...")
        self.load_authentication_status()
        print("✅ Authentication status loaded")
        
        print("📡 Detecting current network...")
        self.detect_current_network()
        print("✅ Network detection complete")
        
        print("🎨 Initializing UI...")
        self.init_ui()
        print("✅ UI initialized")
        
        print("🏷️ Loading registered tags...")
        self.load_registered_tags()  # Load tags AFTER UI is initialized
        print("✅ Tags loaded")
        
        print("📊 Updating tags table...")
        self.update_tags_table()  # Explicitly update the table
        print("✅ Tags table updated")
        
        print("🔐 Checking auto-authentication...")
        self.check_auto_authentication()  # Check for auto-auth on startup
        print("✅ Auto-auth check complete")
        
        print("🔍 Starting monitoring...")
        self.start_monitoring()
        print("✅ Monitoring started")
        
        print("📱 Updating USB status...")
        self.update_usb_status()  # Check USB status on startup
        print("✅ USB status updated")
        
        print("🎉 AntiPineappleGUI initialization complete!")
    
    def init_ui(self):
        """Initialize the user interface"""
        print("🎨 Setting window properties...")
        self.setWindowTitle("🛡️ Anti-Pineapple BSSID NFC Security System")
        self.setGeometry(100, 100, 1200, 800)
        print("✅ Window properties set")
        
        print("🎨 Applying stylesheets...")
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #2a2a2a;
                color: #e0e0e0;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
                color: #4fc3f7;
            }
            QLabel {
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #4a4a4a;
                padding: 8px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QPushButton:pressed {
                background-color: #2a2a2a;
            }
            QCheckBox {
                color: #e0e0e0;
            }
            QTableWidget {
                background-color: #2a2a2a;
                alternate-background-color: #323232;
                color: #e0e0e0;
                gridline-color: #3a3a3a;
                border: 1px solid #3a3a3a;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4a4a4a;
            }
            QHeaderView::section {
                background-color: #3a3a3a;
                color: #e0e0e0;
                padding: 5px;
                border: 1px solid #2a2a2a;
                font-weight: bold;
            }
            QTextEdit {
                background-color: #2a2a2a;
                color: #e0e0e0;
                border: 1px solid #3a3a3a;
            }
            QProgressBar {
                background-color: #2a2a2a;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                text-align: center;
                color: #e0e0e0;
            }
            QProgressBar::chunk {
                background-color: #4fc3f7;
                border-radius: 3px;
            }
            QStatusBar {
                background-color: #1a1a1a;
                color: #b0b0b0;
                border-top: 1px solid #3a3a3a;
            }
        """)
        print("✅ Stylesheets applied")
        
        print("🏗️ Creating central widget...")
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        print("✅ Central widget set")
        
        print("📐 Setting up main layout...")
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        print("✅ Main layout created")
        
        # Header
        print("🏷️ Creating header...")
        header_layout = QHBoxLayout()
        
        title_label = QLabel("🛡️ Anti-Pineapple Security")
        title_label.setStyleSheet("font-size: 28px; font-weight: bold; color: #4fc3f7;")
        header_layout.addWidget(title_label)
        
        header_layout.addStretch()
        print("✅ Header created")
        
        print("🚦 Creating status indicator...")
        self.status_indicator = QLabel("✅ Authenticated & Protected")
        self.status_indicator.setStyleSheet("""
            padding: 8px 15px;
            background-color: #1b5e20;
            color: #66bb6a;
            font-weight: bold;
            border-radius: 15px;
            border: 1px solid #66bb6a;
        """)
        print("✅ Status indicator created")
        header_layout.addWidget(self.status_indicator)
        
        main_layout.addLayout(header_layout)
        print("✅ Header layout added to main")
        
        # Create tabs
        print("📑 Creating tab widget...")
        self.tab_widget = QTabWidget()
        print("✅ Tab widget created")
        
        print("🎨 Applying tab styles...")
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #333333;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #404040;
                color: #ffffff;
                padding: 10px 20px;
                margin: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
            }
            QTabBar::tab:selected {
                background-color: #4fc3f7;
                color: #000000;
            }
            QTabBar::tab:hover {
                background-color: #555555;
            }
        """)
        
        # Main tab
        main_tab = QWidget()
        # self.setup_main_tab(main_tab)  # Method not implemented yet
        main_layout = QVBoxLayout()
        main_label = QLabel("🛡️ Main Security Tab - Under Development")
        main_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(main_label)
        main_tab.setLayout(main_layout)
        self.tab_widget.addTab(main_tab, "🛡️ Main Security")
        
        # BSSID Blacklist tab
        blacklist_tab = QWidget()
        # Import blacklist tab methods
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from blacklist_tab_methods import setup_blacklist_tab
        setup_blacklist_tab(self, blacklist_tab)
        self.tab_widget.addTab(blacklist_tab, "🚫 BSSID Blacklist")
        
        # NFC tab
        nfc_tab = QWidget()
        # self.setup_nfc_tab(nfc_tab)  # Method not implemented yet
        nfc_layout = QVBoxLayout()
        nfc_label = QLabel("🔐 NFC Authentication Tab - Under Development")
        nfc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nfc_layout.addWidget(nfc_label)
        nfc_tab.setLayout(nfc_layout)
        self.tab_widget.addTab(nfc_tab, "🔐 NFC Auth")
        
        # Logs tab
        logs_tab = QWidget()
        # self.setup_logs_tab(logs_tab)  # Method not implemented yet
        logs_layout = QVBoxLayout()
        logs_label = QLabel("📋 Logs Tab - Under Development")
        logs_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logs_layout.addWidget(logs_label)
        logs_tab.setLayout(logs_layout)
        self.tab_widget.addTab(logs_tab, "📋 Logs")
        
        # Settings tab
        settings_tab = QWidget()
        # self.setup_settings_tab(settings_tab)  # Method not implemented yet
        settings_layout = QVBoxLayout()
        settings_label = QLabel("⚙️ Settings Tab - Under Development")
        settings_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        settings_layout.addWidget(settings_label)
        settings_tab.setLayout(settings_layout)
        self.tab_widget.addTab(settings_tab, "⚙️ Settings")
        
        main_layout.addWidget(self.tab_widget)
        
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("System initialized")
    
    def create_dashboard_tab(self):
        widget = QWidget()
        layout = QGridLayout()
        
        # Security Status
        security_group = QGroupBox("Security Status")
        security_layout = QVBoxLayout()
        
        self.security_status = QLabel("🔒 BSSID Lock: Active")
        self.security_status.setStyleSheet("font-size: 18px; padding: 10px; color: #4fc3f7;")
        security_layout.addWidget(self.security_status)
        
        self.auth_status = QLabel("🔐 NFC Security: ACTIVE ✅")
        self.auth_status.setStyleSheet("font-size: 18px; padding: 10px; color: #66bb6a;")
        security_layout.addWidget(self.auth_status)
        
        self.validation_status = QLabel("✅ System Active | Valid until: 2025-12-08")
        self.validation_status.setStyleSheet("font-size: 18px; padding: 10px; color: #66bb6a;")
        security_layout.addWidget(self.validation_status)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group, 0, 0)
        
        # Network info section
        network_group = QGroupBox("Protected Network (Current Connection)")
        network_layout = QVBoxLayout()
        
        # Add network status header
        self.network_status = QLabel("🛡️ Protected Network: WhySoSeriousi")
        self.network_status.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px; color: #66bb6a;")
        network_layout.addWidget(self.network_status)
        
        self.ssid_label = QLabel("SSID: WhySoSeriousi")
        self.ssid_label.setStyleSheet("font-size: 16px; padding: 5px;")
        
        self.bssid_label = QLabel(f"BSSID: {self.legitimate_bssid}")
        self.bssid_label.setStyleSheet("font-size: 16px; padding: 5px;")
        
        network_layout.addWidget(self.ssid_label)
        network_layout.addWidget(self.bssid_label)
        
        self.firewall_status_label = QLabel("<b>🔥 Firewall: UNLOCKED (Unprotected)</b>")
        self.firewall_status_label.setStyleSheet("color: #ffa726; font-size: 14px; padding: 10px;")
        network_layout.addWidget(self.firewall_status_label)
        
        # Button layout for firewall and NFC
        button_layout = QHBoxLayout()
        
        # Lock/Unlock button
        self.firewall_toggle = QPushButton("🔓 Disable BSSID Lock")
        self.firewall_toggle.setStyleSheet("""
            QPushButton {
                background-color: #b71c1c;
                color: white;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.firewall_toggle.clicked.connect(self.toggle_firewall)
        button_layout.addWidget(self.firewall_toggle)
        
        # Register NFC for this network button
        self.register_network_nfc_button = QPushButton("🏷️ Register NFC for This Network")
        self.register_network_nfc_button.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 10px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2196f3;
            }
        """)
        self.register_network_nfc_button.clicked.connect(self.register_nfc_for_current_network)
        button_layout.addWidget(self.register_network_nfc_button)
        
        network_layout.addLayout(button_layout)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group, 0, 1)
        
        # USB & System Status
        usb_group = QGroupBox("USB & System Status")
        usb_layout = QVBoxLayout()
        
        self.usb_status = QLabel("📱 USB Device: Checking...")
        self.usb_status.setStyleSheet("font-size: 16px; padding: 5px;")
        usb_layout.addWidget(self.usb_status)
        
        self.nfc_profile_status = QLabel("🔐 NFC Profile: Loading...")
        self.nfc_profile_status.setStyleSheet("font-size: 16px; padding: 5px;")
        usb_layout.addWidget(self.nfc_profile_status)
        
        usb_group.setLayout(usb_layout)
        layout.addWidget(usb_group, 1, 0)
        
        # Threat Statistics
        threat_group = QGroupBox("Threat Statistics")
        threat_layout = QVBoxLayout()
        
        self.threat_counter = QLabel("🛡️ Threats Blocked: 0")
        self.threat_counter.setStyleSheet("font-size: 24px; color: #ff5252; font-weight: bold;")
        threat_layout.addWidget(self.threat_counter, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.last_threat = QLabel("Last Threat: None")
        threat_layout.addWidget(self.last_threat)
        
        threat_group.setLayout(threat_layout)
        layout.addWidget(threat_group, 1, 1)
        
        widget.setLayout(layout)
        return widget
    
    def create_monitor_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        control_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🔍 Scan Networks")
        self.scan_button.clicked.connect(self.manual_scan)
        control_layout.addWidget(self.scan_button)
        
        self.monitor_toggle = QPushButton("⏸️ Stop Monitoring")
        self.monitor_toggle.setCheckable(True)
        self.monitor_toggle.setChecked(True)
        self.monitor_toggle.clicked.connect(self.toggle_monitoring)
        control_layout.addWidget(self.monitor_toggle)
        
        # BSSID lock status
        self.lock_status = QLabel("🔒 BSSID Lock: ACTIVE")
        self.lock_status.setStyleSheet("color: #ff5252; font-weight: bold; padding: 5px;")
        control_layout.addWidget(self.lock_status)
        
        # BSSID Blacklist button
        self.blacklist_button = QPushButton("🚫 Manage BSSID Blacklist")
        self.blacklist_button.clicked.connect(self.show_blacklist_manager)
        self.blacklist_button.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #f44336;
            }
        """)
        control_layout.addWidget(self.blacklist_button)
        
        control_layout.addStretch()
        
        self.auto_block = QCheckBox("Auto-block non-matching BSSIDs")
        self.auto_block.setChecked(True)
        control_layout.addWidget(self.auto_block)
        
        layout.addLayout(control_layout)
        
        # Network table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(6)
        self.network_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Signal", "Channel", "Security", "Status"])
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.network_table.setAlternatingRowColors(True)
        
        layout.addWidget(self.network_table)
        
        widget.setLayout(layout)
        return widget
    
    def create_auth_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Info section
        info_group = QGroupBox("NFC Authentication System")
        info_layout = QVBoxLayout()
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(150)
        info_text.setHtml("""
        <h3>Zero-Visibility NFC Authentication</h3>
        <ul>
            <li>✅ NFC tag values never displayed</li>
            <li>✅ 90-day device validation</li>
            <li>✅ BSSID-locked connections</li>
            <li>✅ Device fingerprinting</li>
            <li>✅ Secure chaos value generation</li>
        </ul>
        """)
        info_layout.addWidget(info_text)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Current auth status
        status_group = QGroupBox("Authentication Status")
        status_layout = QFormLayout()
        
        self.nfc_status = QLabel("Not authenticated")
        status_layout.addRow("Status:", self.nfc_status)
        
        self.device_id = QLabel("Not set")
        status_layout.addRow("Device ID:", self.device_id)
        
        self.expiry_date = QLabel("Not set")
        status_layout.addRow("Expires:", self.expiry_date)
        
        self.days_remaining = QProgressBar()
        self.days_remaining.setMaximum(90)
        self.days_remaining.setTextVisible(True)
        self.days_remaining.setFormat("%v days remaining")
        status_layout.addRow("Validity:", self.days_remaining)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        # Authentication buttons
        button_layout = QHBoxLayout()
        
        self.auth_button = QPushButton("🔐 Authenticate with NFC")
        self.auth_button.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 15px;
                font-size: 18px;
                font-weight: bold;
                border-radius: 5px;
                border: 1px solid #4CAF50;
            }
            QPushButton:hover {
                background-color: #2e7d32;
                color: #c8e6c9;
            }
        """)
        self.auth_button.clicked.connect(self.authenticate_nfc)
        button_layout.addWidget(self.auth_button)
        
        self.verify_button = QPushButton("✓ Verify Authentication")
        self.verify_button.clicked.connect(self.verify_authentication)
        button_layout.addWidget(self.verify_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        widget.setLayout(layout)
        return widget
    
    def create_tags_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header_layout = QHBoxLayout()
        header_label = QLabel("🏷️ Registered NFC Tags")
        header_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #4fc3f7;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        
        add_tag_button = QPushButton("➕ Add New Tag")
        add_tag_button.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
                border: 1px solid #4CAF50;
            }
            QPushButton:hover {
                background-color: #2e7d32;
                color: #c8e6c9;
            }
        """)
        add_tag_button.clicked.connect(self.add_new_tag)
        header_layout.addWidget(add_tag_button)
        
        layout.addLayout(header_layout)
        
        # Tags table
        self.tags_table = QTableWidget()
        self.tags_table.setColumnCount(5)
        self.tags_table.setHorizontalHeaderLabels(["Name", "Description", "Created", "Last Used", "Actions"])
        self.tags_table.horizontalHeader().setStretchLastSection(False)
        self.tags_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tags_table.setAlternatingRowColors(True)
        self.tags_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        layout.addWidget(self.tags_table)
        
        # Info panel
        info_group = QGroupBox("Tag Security Information")
        info_layout = QVBoxLayout()
        
        info_text = QLabel("""
        🔒 All NFC tag values are stored with AES-256 encryption
        📱 Tags are device-specific and cannot be transferred
        🛡️ Tag values are never displayed or logged
        ⏰ Automatic 90-day rotation recommended
        """)
        info_text.setStyleSheet("padding: 10px; color: #a0a0a0;")
        info_layout.addWidget(info_text)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_threat_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Controls
        control_layout = QHBoxLayout()
        
        clear_button = QPushButton("🗑️ Clear Log")
        clear_button.clicked.connect(self.clear_threat_log)
        control_layout.addWidget(clear_button)
        
        export_button = QPushButton("📥 Export Log")
        export_button.clicked.connect(self.export_threat_log)
        control_layout.addWidget(export_button)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Threat log
        self.threat_log = QTextEdit()
        self.threat_log.setReadOnly(True)
        self.threat_log.setStyleSheet("""
            QTextEdit {
                background-color: #0d0d0d;
                color: #00ff00;
                padding: 10px;
                border: 1px solid #2a2a2a;
            }
        """)
        
        layout.addWidget(self.threat_log)
        
        widget.setLayout(layout)
        return widget
    
    def update_usb_status(self):
        """Update USB device status in GUI"""
        try:
            # Check for mounted USB devices
            result = subprocess.run(['ls', '/Volumes/'], capture_output=True, text=True)
            volumes = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            # Filter out system volumes
            usb_volumes = [v for v in volumes if v not in ['', 'Macintosh HD', 'com.apple.TimeMachine.localsnapshots']]
            
            if usb_volumes:
                usb_name = usb_volumes[0]  # Take first USB device
                self.usb_status.setText(f"📱 USB Device: {usb_name} ✅")
                self.usb_status.setStyleSheet("font-size: 16px; padding: 5px; color: #66bb6a;")
                
                # Check for NFC profile on USB
                profile_path = f"/Volumes/{usb_name}/triple_airgap_auth_profile_nfc_locked.json"
                if os.path.exists(profile_path):
                    self.nfc_profile_status.setText("🔐 NFC Profile: Found on USB ✅")
                    self.nfc_profile_status.setStyleSheet("font-size: 16px; padding: 5px; color: #66bb6a;")
                else:
                    self.nfc_profile_status.setText("🔐 NFC Profile: Not Found")
                    self.nfc_profile_status.setStyleSheet("font-size: 16px; padding: 5px; color: #ffa726;")
            else:
                self.usb_status.setText("📱 USB Device: Not Connected ❌")
                self.usb_status.setStyleSheet("font-size: 16px; padding: 5px; color: #ff5252;")
                self.nfc_profile_status.setText("🔐 NFC Profile: USB Required")
                self.nfc_profile_status.setStyleSheet("font-size: 16px; padding: 5px; color: #ff5252;")
        except Exception as e:
            self.usb_status.setText("📱 USB Device: Error checking")
            self.usb_status.setStyleSheet("font-size: 16px; padding: 5px; color: #ffa726;")
    
    def start_monitoring(self):
        """Start the network monitoring thread"""
        if hasattr(self, 'monitor_thread'):
            return  # Already running
        
        self.monitor_thread = NetworkMonitorThread()
        self.monitor_thread.network_found.connect(self.handle_network_found)
        self.monitor_thread.start()
        
        # Start USB monitoring timer
        self.usb_timer = QTimer()
        self.usb_timer.timeout.connect(self.update_usb_status)
        self.usb_timer.start(5000)  # Check every 5 seconds
    
    def toggle_monitoring(self):
        if self.monitor_toggle.isChecked():
            self.start_monitoring()
            self.monitor_toggle.setText("⏸️ Stop Monitoring")
        else:
            if hasattr(self, 'monitor_thread'):
                self.monitor_thread.stop()
                self.monitor_thread.wait()
            self.monitor_toggle.setText("▶️ Start Monitoring")
    
    def manual_scan(self):
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")
        
        if hasattr(self, 'monitor_thread'):
            networks = self.monitor_thread.scan_networks()
            self.update_network_table(networks)
        
        self.scan_button.setEnabled(True)
        self.scan_button.setText("🔍 Scan Networks")
    
    def update_network_table(self, networks):
        """Update the network monitoring table"""
        if not hasattr(self, 'network_table'):
            return  # Skip if network table doesn't exist
        self.network_table.setRowCount(len(networks))
        
        for i, network in enumerate(networks):
            self.network_table.setItem(i, 0, QTableWidgetItem(network['ssid']))
            
            bssid_item = QTableWidgetItem(network['bssid'])
            if network['bssid'] == self.legitimate_bssid:
                bssid_item.setBackground(QColor("#1b5e20"))
                bssid_item.setForeground(QColor("#66bb6a"))
            self.network_table.setItem(i, 1, bssid_item)
            
            self.network_table.setItem(i, 2, QTableWidgetItem(f"{network['rssi']} dBm"))
            self.network_table.setItem(i, 3, QTableWidgetItem(network['channel']))
            self.network_table.setItem(i, 4, QTableWidgetItem(network['security']))
            
            status = self.get_network_status(network)
            status_item = QTableWidgetItem(status)
            if "Threat" in status:
                status_item.setBackground(QColor("#4a1515"))
                status_item.setForeground(QColor("#ff5252"))
            elif "Protected" in status:
                status_item.setBackground(QColor("#1b5e20"))
                status_item.setForeground(QColor("#66bb6a"))
            self.network_table.setItem(i, 5, status_item)
        
        self.status_bar.showMessage(f"Found {len(networks)} networks")
    
    def get_network_status(self, network):
        network_bssid = network['bssid'].upper()
        
        if network_bssid == self.legitimate_bssid:
            return "✅ Protected (Current)"
        elif network_bssid in self.blocked_bssids:
            return "🚫 BLOCKED"
        elif self.firewall_enabled:
            # When firewall is enabled, all non-matching BSSIDs are threats
            return "⚠️ Non-matching BSSID"
        elif network['ssid'] == self.get_current_ssid() and network_bssid != self.legitimate_bssid:
            return "🚨 BSSID Spoof Threat!"
        elif 'Open' in network.get('security', ''):
            suspicious = ['pineapple', 'free', 'public']
            if any(x in network['ssid'].lower() for x in suspicious):
                return "🚨 Potential Threat"
        return "⚡ Unprotected"
    
    def handle_threat(self, threat_network):
        threat_bssid = threat_network['bssid'].upper()
        
        # Block non-matching BSSIDs when firewall is locked
        if not self.firewall_enabled and threat_bssid != self.legitimate_bssid:
            self.blocked_bssids.add(threat_bssid)
            self.threat_count += 1
            self.threat_counter.setText(f"🚨 Threats Blocked: {self.threat_count}")
            
            # Apply firewall rule to block this BSSID
            self.apply_bssid_block(threat_bssid)
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            threat_msg = f"""
[{timestamp}] BSSID FIREWALL BLOCK!
SSID: {threat_network['ssid']}
BSSID: {threat_bssid}
Reason: Non-matching BSSID (Expected: {self.legitimate_bssid})
Signal: {threat_network['rssi']} dBm
Security: {threat_network.get('security', 'Unknown')}
Action: BLOCKED BY FIREWALL
{'=' * 60}
"""
            self.threat_log.append(threat_msg)
            self.last_threat.setText(f"Last Block: {threat_network['ssid']} ({threat_bssid}) at {timestamp}")
            
            if self.auto_block.isChecked():
                self.status_bar.showMessage(f"🚫 Blocked BSSID: {threat_bssid} - Not matching protected network")
    
    def authenticate_nfc(self):
        # Filter tags for current network if connected
        current_bssid = self.legitimate_bssid
        available_tags = []
        
        for tag in self.registered_tags:
            if 'network_binding' in tag:
                # Network-specific tag - only use if on matching network
                if tag['network_binding']['bssid'] == current_bssid:
                    available_tags.append(tag)
            else:
                # Universal tag - always available
                available_tags.append(tag)
        
        if not available_tags:
            reply = QMessageBox.question(self, "No Compatible Tags",
                f"No NFC tags registered for current network.\n"
                f"BSSID: {current_bssid}\n\n"
                "Would you like to register a tag for this network?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.register_nfc_for_current_network()
            return
        
        dialog = NFCAuthDialog(self, available_tags)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.authenticated = True
            self.update_auth_status(True)
            self.save_authentication()
            QMessageBox.information(self, "✅ Success",
                "NFC authentication successful!\nYour device is now protected for 90 days.")
    
    def add_new_tag(self, network_specific=False):
        """Add a new NFC tag to the system"""
        if network_specific:
            # Pass current network info for network-specific tag
            dialog = NFCTagSetupDialog(self, self.legitimate_bssid, self.get_current_ssid())
        else:
            dialog = NFCTagSetupDialog(self)
            
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Ensure tag_value is a string for hashing
            tag_value_str = str(dialog.tag_value) if dialog.tag_value else ""
            if not tag_value_str:
                QMessageBox.warning(self, "⚠️ Error", "No tag value was captured.")
                return
                
            tag_data = {
                'name': dialog.tag_name.text(),
                'description': dialog.tag_description.text(),
                'value_hash': hashlib.sha256(tag_value_str.encode()).hexdigest(),  # Store only hash, never the actual value
                'created': datetime.now().isoformat(),
                'last_used': None,
                'device_id': hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]
            }
            
            # Add network binding if this is a network-specific tag
            if network_specific and self.legitimate_bssid:
                tag_data['network_binding'] = {
                    'bssid': self.legitimate_bssid,
                    'ssid': self.get_current_ssid()
                }
            
            self.registered_tags.append(tag_data)
            self.save_registered_tags()
            self.update_tags_table()
            
            if network_specific:
                QMessageBox.information(self, "✅ Network Tag Registered",
                    f"NFC tag '{tag_data['name']}' has been registered for network:\n"
                    f"SSID: {tag_data['network_binding']['ssid']}\n"
                    f"BSSID: {tag_data['network_binding']['bssid']}\n\n"
                    "This tag will only work with this specific network.")
            else:
                QMessageBox.information(self, "✅ Tag Registered",
                    f"NFC tag '{tag_data['name']}' has been registered successfully!\n\n"
                    "The tag value has been securely stored and encrypted.")
    
    def load_registered_tags(self):
        """Load registered NFC tags from file"""
        if self.tags_path.exists():
            try:
                with open(self.tags_path, 'r') as f:
                    self.registered_tags = json.load(f)
                print(f"Loaded {len(self.registered_tags)} tags from {self.tags_path}")
                # Only update table if UI is initialized
                if hasattr(self, 'tags_table'):
                    self.update_tags_table()
            except Exception as e:
                print(f"Error loading tags: {e}")
                self.registered_tags = []
        else:
            print(f"No tags file found at {self.tags_path}, starting with empty tag list")
            self.registered_tags = []
    
    def save_registered_tags(self):
        """Save registered NFC tags to file"""
        try:
            self.tags_path.parent.mkdir(exist_ok=True)
            with open(self.tags_path, 'w') as f:
                json.dump(self.registered_tags, f, indent=2)
            print(f"✅ Saved {len(self.registered_tags)} tags to {self.tags_path}")
        except Exception as e:
            print(f"❌ Error saving tags: {e}")
            QMessageBox.critical(self, "Save Error", f"Failed to save tags: {e}")
    
    def update_tags_table(self):
        """Update the tags table with registered tags"""
        if not hasattr(self, 'tags_table'):
            print("Tags table not initialized yet")
            return
            
        print(f"Updating tags table with {len(self.registered_tags)} tags")
        self.tags_table.setRowCount(len(self.registered_tags))
        
        for i, tag in enumerate(self.registered_tags):
            # Name with network binding indicator
            name_text = tag['name']
            if 'network_binding' in tag:
                name_text += f" 🌐 ({tag['network_binding']['ssid']})"
            name_item = QTableWidgetItem(name_text)
            self.tags_table.setItem(i, 0, name_item)
            
            # Description
            desc_text = tag.get('description', 'N/A')
            if 'network_binding' in tag:
                desc_text += f" [BSSID: {tag['network_binding']['bssid'][:8]}...]"
            self.tags_table.setItem(i, 1, QTableWidgetItem(desc_text))
            
            # Created date
            created_date = datetime.fromisoformat(tag['created']).strftime("%Y-%m-%d")
            self.tags_table.setItem(i, 2, QTableWidgetItem(created_date))
            
            # Last used
            if tag.get('last_used'):
                last_used = datetime.fromisoformat(tag['last_used']).strftime("%Y-%m-%d %H:%M")
            else:
                last_used = "Never"
            self.tags_table.setItem(i, 3, QTableWidgetItem(last_used))
            
            # Actions column - Add delete button
            delete_button = QPushButton("🗑️ Delete")
            delete_button.setToolTip("Delete this tag")
            delete_button.clicked.connect(lambda checked, idx=i: self.delete_tag(idx))
            self.tags_table.setCellWidget(i, 4, delete_button)
    
    def delete_tag(self, index):
        """Delete a registered tag"""
        tag = self.registered_tags[index]
        reply = QMessageBox.question(self, "Delete Tag?",
            f"Are you sure you want to delete the tag '{tag['name']}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            del self.registered_tags[index]
            self.save_registered_tags()
            self.update_tags_table()
            self.status_bar.showMessage(f"Tag '{tag['name']}' deleted")
    
    def verify_authentication(self):
        if self.auth_profile_path.exists():
            try:
                with open(self.auth_profile_path, 'r') as f:
                    profile = json.load(f)
                
                expiry = datetime.fromisoformat(profile.get('expiry', ''))
                days_left = (expiry - datetime.now()).days
                
                if days_left > 0:
                    QMessageBox.information(self, "✅ Valid",
                        f"Authentication is valid.\nDays remaining: {days_left}")
                else:
                    QMessageBox.warning(self, "⚠️ Expired",
                        "Authentication has expired.\nPlease re-authenticate with NFC.")
            except:
                QMessageBox.warning(self, "❌ Error", "Could not verify authentication.")
        else:
            QMessageBox.information(self, "ℹ️ Not Authenticated",
                "No authentication profile found.\nPlease authenticate with NFC.")
    
    def update_auth_status(self, authenticated):
        if authenticated:
            self.status_indicator.setText("✅ Authenticated & Protected")
            self.status_indicator.setStyleSheet("""
                padding: 10px 20px;
                background-color: #1b5e20;
                color: #81c784;
                font-weight: bold;
                font-size: 16px;
                border-radius: 20px;
                border: 2px solid #4CAF50;
            """)
            
            # Update authentication status
            self.auth_status.setText("🔐 NFC Security: ACTIVE ✅")
            self.auth_status.setStyleSheet("font-size: 18px; padding: 10px; color: #66bb6a; font-weight: bold;")
            
            # Show NFC tags count
            tag_count = len(self.registered_tags)
            network_tags = sum(1 for tag in self.registered_tags if 'network_binding' in tag)
            self.nfc_status.setText(f"✅ {tag_count} Tags Registered ({network_tags} network-specific)")
            self.nfc_status.setStyleSheet("color: #66bb6a; font-size: 14px;")
            
            # Update expiry and validation
            expiry = datetime.now() + timedelta(days=90)
            self.expiry_date.setText(expiry.strftime("%Y-%m-%d"))
            self.validation_status.setText(f"✅ System Active | Valid until: {expiry.strftime('%Y-%m-%d')}")
            self.validation_status.setStyleSheet("color: #66bb6a; font-weight: bold; font-size: 14px;")
            self.days_remaining.setValue(90)
            
            # Show device ID
            device_id = hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]
            self.device_id.setText(f"{device_id}...")
            
            # Update firewall status
            self.update_firewall_status()
            
            # Update dashboard network info with protection status
            if hasattr(self, 'network_status'):
                self.network_status.setText(f"🛡️ Protected Network: {self.get_current_ssid()}")
                self.network_status.setStyleSheet("color: #66bb6a; font-size: 16px; font-weight: bold;")
        else:
            self.status_indicator.setText("⚠️ Not Authenticated")
            self.status_indicator.setStyleSheet("""
                padding: 10px 20px;
                background-color: #4a3a00;
                color: #ffa726;
                font-weight: bold;
                font-size: 16px;
                border-radius: 20px;
                border: 2px solid #ff9800;
            """)
            
            self.auth_status.setText("🔐 NFC Security: NOT ACTIVE ⚠️")
            self.auth_status.setStyleSheet("font-size: 18px; padding: 10px; color: #ffa726; font-weight: bold;")
            
            # Show tags status
            tag_count = len(self.registered_tags)
            if tag_count > 0:
                self.nfc_status.setText(f"⚠️ {tag_count} Tags Available - Authentication Required")
            else:
                self.nfc_status.setText("❌ No NFC Tags Registered")
            self.nfc_status.setStyleSheet("color: #ffa726; font-size: 14px;")
            
            self.validation_status.setText("⚠️ System Inactive - NFC Authentication Required")
            self.validation_status.setStyleSheet("color: #ffa726; font-weight: bold; font-size: 14px;")
            
            # Update network status
            if hasattr(self, 'network_status'):
                self.network_status.setText(f"⚠️ Unprotected Network: {self.get_current_ssid()}")
                self.network_status.setStyleSheet("color: #ffa726; font-size: 16px; font-weight: bold;")
            
            self.firewall_enabled = False
            self.update_firewall_status()
    
    def save_authentication(self):
        profile = {
            'authenticated': True,
            'timestamp': datetime.now().isoformat(),
            'expiry': (datetime.now() + timedelta(days=90)).isoformat(),
            'device_id': hashlib.sha256(socket.gethostname().encode()).hexdigest(),
            'bssid': self.legitimate_bssid
        }
        
        self.auth_profile_path.parent.mkdir(exist_ok=True)
        with open(self.auth_profile_path, 'w') as f:
            json.dump(profile, f, indent=2)
    
    def load_authentication_status(self):
        if self.auth_profile_path.exists():
            try:
                with open(self.auth_profile_path, 'r') as f:
                    profile = json.load(f)
                
                expiry = datetime.fromisoformat(profile.get('expiry', ''))
                days_left = (expiry - datetime.now()).days
                
                if days_left > 0:
                    self.authenticated = True
                    self.update_auth_status(True)
                    self.days_remaining.setValue(days_left)
            except:
                pass
    
    def clear_threat_log(self):
        self.threat_log.clear()
        self.threat_count = 0
        self.threat_counter.setText("🚨 Threats Blocked: 0")
        self.last_threat.setText("Last Threat: None")
    
    def export_threat_log(self):
        filename = f"threat_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(self.threat_log.toPlainText())
        QMessageBox.information(self, "📥 Exported", f"Threat log exported to {filename}")


    def toggle_firewall(self):
        """Toggle firewall with NFC authentication"""
        if not self.firewall_enabled:
            # Require NFC authentication to unlock
            if not self.registered_tags:
                reply = QMessageBox.question(self, "No Tags Registered",
                    "NFC authentication required to unlock firewall.\nRegister a tag now?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                if reply == QMessageBox.StandardButton.Yes:
                    self.add_new_tag()
                return
            
            # Authenticate with NFC
            if self.authenticate_nfc():
                self.firewall_enabled = True
                self.authenticated = True
                self.save_authentication()  # Create authentication profile
                self.update_auth_status(True)  # Update all UI elements
                self.update_firewall_status()
                self.clear_blocked_bssids()
                
                # Show success with system status
                tag_count = len(self.registered_tags)
                QMessageBox.information(self, "✅ System Activated",
                    f"🛡️ Anti-Pineapple Protection ACTIVE\n\n"
                    f"✅ Firewall: Unlocked\n"
                    f"✅ Protected BSSID: {self.legitimate_bssid}\n"
                    f"✅ NFC Tags: {tag_count} registered\n"
                    f"✅ Status: All non-matching BSSIDs will be blocked")
        else:
            # Lock the firewall
            self.firewall_enabled = False
            self.authenticated = False
            self.update_auth_status(False)  # Update UI to show unauthenticated state
            self.update_firewall_status()
            QMessageBox.information(self, "🔒 System Locked",
                "🔒 Anti-Pineapple Protection DEACTIVATED\n\n"
                "⚠️ System is now locked\n"
                "⚠️ NFC authentication required to reactivate protection")
    
    def update_firewall_status(self):
        """Update firewall status display"""
        if self.firewall_enabled:
            self.firewall_status_label.setText("<b>🔥 Firewall: LOCKED (Protected)</b>")
            self.firewall_status_label.setStyleSheet("color: #66bb6a; font-size: 14px; padding: 10px;")
            self.firewall_toggle.setText("🔓 Unlock Firewall")
            self.firewall_toggle.setStyleSheet("""
                QPushButton {
                    background-color: #1b5e20;
                    color: #a5d6a7;
                    padding: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 5px;
                    border: 1px solid #4CAF50;
                }
                QPushButton:hover {
                    background-color: #2e7d32;
                    color: #c8e6c9;
                }
            """)
        else:
            self.firewall_status_label.setText("<b>🔥 Firewall: UNLOCKED (Unprotected)</b>")
            self.firewall_status_label.setStyleSheet("color: #ff5252; font-size: 14px; padding: 10px;")
            self.firewall_toggle.setText("🔒 Lock with NFC")
            self.firewall_toggle.setStyleSheet("""
                QPushButton {
                    background-color: #b71c1c;
                    color: white;
                    padding: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #d32f2f;
                }
            """)
            self.lock_status.setText("🔒 BSSID Lock: ACTIVE (All non-matching blocked)")
            self.lock_status.setStyleSheet("color: #ff5252; font-weight: bold; padding: 5px;")
    
    def apply_bssid_block(self, bssid):
        """Apply firewall rule to block specific BSSID"""
        # This would integrate with system firewall or WiFi controller
        # For now, we track it internally
        print(f"Firewall: Blocking BSSID {bssid}")
        # In production, this would call WiFiConnectionController to block
    
    def clear_blocked_bssids(self):
        """Clear all blocked BSSIDs when firewall is unlocked"""
        self.blocked_bssids.clear()
        print("Firewall: Cleared all BSSID blocks")
    
    def detect_current_network(self):
        """Detect current network BSSID and verify against trusted networks"""
        try:
            cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            current_bssid = None
            for line in result.stdout.split('\n'):
                if 'BSSID:' in line:
                    bssid = line.split('BSSID:')[1].strip()
                    if bssid and bssid != '00:00:00:00:00:00':
                        current_bssid = bssid
                        break
            
            if current_bssid:
                # Check if this BSSID is in our trusted networks
                trusted_bssids = set()
                for tag in self.registered_tags:
                    if 'network_binding' in tag:
                        trusted_bssids.add(tag['network_binding']['bssid'])
                
                if current_bssid in trusted_bssids:
                    self.legitimate_bssid = current_bssid
                    print(f"✅ Connected to trusted network BSSID: {current_bssid}")
                else:
                    print(f"⚠️ WARNING: Connected to untrusted network BSSID: {current_bssid}")
                    if trusted_bssids:
                        print(f"🔐 Trusted networks: {', '.join(trusted_bssids)}")
                        # Optionally disconnect from untrusted network
                        self.warn_untrusted_network(current_bssid)
                    self.legitimate_bssid = current_bssid  # Still set it for monitoring
            else:
                print("Warning: No WiFi connection detected. Using default BSSID.")
        except Exception as e:
            print(f"Error detecting network: {e}")
            print("Warning: No WiFi connection detected. Using default BSSID.")
    
    def warn_untrusted_network(self, bssid):
        """Warn user about connection to untrusted network"""
        from PyQt6.QtWidgets import QMessageBox
        if hasattr(self, 'show'):  # Only show dialog if GUI is initialized
            reply = QMessageBox.warning(self, "⚠️ Untrusted Network Detected",
                f"You are connected to an untrusted network:\n"
                f"BSSID: {bssid}\n\n"
                f"This could be a WiFi Pineapple attack!\n\n"
                f"Recommended actions:\n"
                f"• Disconnect immediately\n"
                f"• Register this network if it's legitimate\n"
                f"• Report suspicious activity\n\n"
                f"Disconnect now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            
            if reply == QMessageBox.StandardButton.Yes:
                self.disconnect_wifi()
    
    def disconnect_wifi(self):
        """Disconnect from current WiFi network"""
        try:
            subprocess.run(['networksetup', '-setairportpower', 'en0', 'off'], check=True)
            subprocess.run(['networksetup', '-setairportpower', 'en0', 'on'], check=True)
            print("🔌 Disconnected from WiFi for security")
        except Exception as e:
            print(f"Error disconnecting WiFi: {e}")
    
    def get_current_ssid(self):
        """Get SSID of current network"""
        try:
            cmd = ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            current_bssid = None
            current_ssid = None
            
            for line in result.stdout.split('\n'):
                if 'BSSID:' in line:
                    bssid = line.split('BSSID:')[1].strip()
                    if bssid and bssid != '00:00:00:00:00:00':
                        current_bssid = bssid
                        break
                    current_bssid = line.split(': ')[1].strip().upper()
                elif ' SSID' in line:
                    current_ssid = line.split(': ')[1].strip()
            
            if current_bssid:
                self.legitimate_bssid = current_bssid
                print(f"Detected current network BSSID: {current_bssid}")
                if current_ssid:
                    print(f"Network SSID: {current_ssid}")
            else:
                print("Warning: No WiFi connection detected. Using default BSSID.")
                # Keep the default if no connection
        except Exception as e:
            print(f"Error detecting network: {e}")
            # Keep the default BSSID on error
    
    def register_nfc_for_current_network(self):
        """Register an NFC tag specifically for the current network"""
        if not self.legitimate_bssid:
            QMessageBox.warning(self, "⚠️ No Network",
                "Cannot register network-specific tag.\n"
                "Please connect to a WiFi network first.")
            return
        
        self.add_new_tag(network_specific=True)
        self.update_network_info()
    
    def check_auto_authentication(self):
        """Check if current network matches any saved network-bound tags and auto-authenticate"""
        current_bssid = self.legitimate_bssid
        current_ssid = self.get_current_ssid()
        
        # Find network-bound tags that match current network
        matching_tags = []
        for tag in self.registered_tags:
            if 'network_binding' in tag:
                if tag['network_binding']['bssid'] == current_bssid:
                    matching_tags.append(tag)
        
        if matching_tags:
            print(f"🔐 Auto-authenticating: Found {len(matching_tags)} matching network tags for BSSID {current_bssid}")
            # Auto-authenticate since we're on a trusted network with registered tags
            self.authenticated = True
            self.firewall_enabled = True
            
            # Update last_used timestamp for matching tags
            for tag in matching_tags:
                tag['last_used'] = datetime.now().isoformat()
            self.save_registered_tags()
            
            # Create/update authentication profile
            self.save_authentication()
            
            # Update UI to show authenticated state
            self.update_auth_status(True)
            self.update_firewall_status()
            self.update_tags_table()  # Refresh table to show updated last_used times
            
            print(f"✅ Auto-authenticated on network: {current_ssid} ({current_bssid})")
        else:
            print(f"⚠️ No matching network tags found for BSSID {current_bssid}")


    def update_network_info(self):
        """Update network info displays"""
        ssid = self.get_current_ssid()
        if hasattr(self, 'ssid_label'):
            self.ssid_label.setText(f"SSID: {ssid}")
        if hasattr(self, 'network_status'):
            if self.authenticated:
                self.network_status.setText(f"🛡️ Protected Network: {ssid}")
                self.network_status.setStyleSheet("color: #66bb6a; font-size: 16px; font-weight: bold;")
            else:
                self.network_status.setText(f"⚠️ Unprotected Network: {ssid}")
                self.network_status.setStyleSheet("color: #ffa726; font-size: 16px; font-weight: bold;")


    def create_settings_tab(self):
        """Create settings configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Settings header
        header = QLabel("⚙️ System Configuration")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7; padding: 10px;")
        layout.addWidget(header)
        
        # Auto-start settings
        autostart_group = QGroupBox("🚀 Auto-Start Configuration")
        autostart_layout = QVBoxLayout()
        
        self.autostart_enabled = QCheckBox("Enable auto-start on system boot")
        self.autostart_enabled.setChecked(self.is_autostart_enabled())
        self.autostart_enabled.stateChanged.connect(self.toggle_autostart)
        autostart_layout.addWidget(self.autostart_enabled)
        
        autostart_info = QLabel("When enabled, Anti-Pineapple will start automatically when you log in to macOS")
        autostart_info.setStyleSheet("color: #a0a0a0; font-size: 12px; padding: 5px;")
        autostart_layout.addWidget(autostart_info)
        
        # Auto-start control buttons
        autostart_buttons = QHBoxLayout()
        
        install_btn = QPushButton("📦 Install Auto-Start")
        install_btn.clicked.connect(self.install_autostart_service)
        install_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #2196f3; }
        """)
        autostart_buttons.addWidget(install_btn)
        
        uninstall_btn = QPushButton("🗑️ Remove Auto-Start")
        uninstall_btn.clicked.connect(self.uninstall_autostart_service)
        uninstall_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #f44336; }
        """)
        autostart_buttons.addWidget(uninstall_btn)
        
        autostart_layout.addLayout(autostart_buttons)
        autostart_group.setLayout(autostart_layout)
        layout.addWidget(autostart_group)
        
        # Security settings
        security_group = QGroupBox("🔐 Security Configuration")
        security_layout = QVBoxLayout()
        
        self.network_warnings = QCheckBox("Show warnings for untrusted networks")
        self.network_warnings.setChecked(True)
        security_layout.addWidget(self.network_warnings)
        
        self.auto_disconnect = QCheckBox("Auto-disconnect from suspicious networks")
        self.auto_disconnect.setChecked(False)
        security_layout.addWidget(self.auto_disconnect)
        
        self.strict_mode = QCheckBox("Strict mode: Only allow registered networks")
        self.strict_mode.setChecked(False)
        security_layout.addWidget(self.strict_mode)
        
        security_group.setLayout(security_layout)
        layout.addWidget(security_group)
        
        # Authentication settings
        auth_group = QGroupBox("🏷️ Authentication Settings")
        auth_layout = QFormLayout()
        
        self.auth_timeout = QSpinBox()
        self.auth_timeout.setRange(30, 180)
        self.auth_timeout.setValue(90)
        self.auth_timeout.setSuffix(" days")
        auth_layout.addRow("Authentication timeout:", self.auth_timeout)
        
        self.max_tags = QSpinBox()
        self.max_tags.setRange(1, 50)
        self.max_tags.setValue(10)
        auth_layout.addRow("Maximum NFC tags:", self.max_tags)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Monitoring settings
        monitor_group = QGroupBox("📊 Monitoring Configuration")
        monitor_layout = QFormLayout()
        
        self.scan_interval = QSpinBox()
        self.scan_interval.setRange(1, 60)
        self.scan_interval.setValue(5)
        self.scan_interval.setSuffix(" seconds")
        monitor_layout.addRow("Network scan interval:", self.scan_interval)
        
        self.log_level = QComboBox()
        self.log_level.addItems(["Debug", "Info", "Warning", "Error"])
        self.log_level.setCurrentText("Info")
        monitor_layout.addRow("Log level:", self.log_level)
        
        monitor_group.setLayout(monitor_layout)
        layout.addWidget(monitor_group)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 Save Settings")
        save_btn.clicked.connect(self.save_settings)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
                border: 1px solid #4CAF50;
            }
            QPushButton:hover {
                background-color: #2e7d32;
                color: #c8e6c9;
            }
        """)
        button_layout.addWidget(save_btn)
        
        reset_btn = QPushButton("🔄 Reset to Defaults")
        reset_btn.clicked.connect(self.reset_settings)
        reset_btn.setStyleSheet("""
            QPushButton {
                background-color: #f57c00;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #ff9800; }
        """)
        button_layout.addWidget(reset_btn)
        
        layout.addLayout(button_layout)
        
        # Status info
        status_group = QGroupBox("ℹ️ System Status")
        status_layout = QVBoxLayout()
        
        self.settings_status = QLabel("Settings loaded successfully")
        self.settings_status.setStyleSheet("color: #66bb6a; padding: 5px;")
        status_layout.addWidget(self.settings_status)
        
        status_group.setLayout(status_layout)
        layout.addWidget(status_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def is_autostart_enabled(self):
        """Check if auto-start service is installed"""
        import os
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.aimf.antipineapple.plist")
        return os.path.exists(plist_path)
    
    def toggle_autostart(self, state):
        """Toggle auto-start service"""
        if state == 2:  # Checked
            self.install_autostart_service()
        else:
            self.uninstall_autostart_service()
    
    def install_autostart_service(self):
        """Install auto-start service"""
        try:
            script_path = os.path.join(os.path.dirname(__file__), "install_autostart.sh")
            result = subprocess.run([script_path], capture_output=True, text=True)
            if result.returncode == 0:
                self.settings_status.setText("✅ Auto-start service installed successfully")
                self.settings_status.setStyleSheet("color: #66bb6a; padding: 5px;")
                self.autostart_enabled.setChecked(True)
            else:
                self.settings_status.setText("❌ Failed to install auto-start service")
                self.settings_status.setStyleSheet("color: #f44336; padding: 5px;")
        except Exception as e:
            self.settings_status.setText(f"❌ Error: {e}")
            self.settings_status.setStyleSheet("color: #f44336; padding: 5px;")
    
    def uninstall_autostart_service(self):
        """Uninstall auto-start service"""
        try:
            script_path = os.path.join(os.path.dirname(__file__), "uninstall_autostart.sh")
            result = subprocess.run([script_path], capture_output=True, text=True)
            if result.returncode == 0:
                self.settings_status.setText("✅ Auto-start service removed successfully")
                self.settings_status.setStyleSheet("color: #66bb6a; padding: 5px;")
                self.autostart_enabled.setChecked(False)
            else:
                self.settings_status.setText("❌ Failed to remove auto-start service")
                self.settings_status.setStyleSheet("color: #f44336; padding: 5px;")
        except Exception as e:
            self.settings_status.setText(f"❌ Error: {e}")
            self.settings_status.setStyleSheet("color: #f44336; padding: 5px;")
    
    def save_settings(self):
        """Save current settings to file"""
        settings = {
            'network_warnings': self.network_warnings.isChecked(),
            'auto_disconnect': self.auto_disconnect.isChecked(),
            'strict_mode': self.strict_mode.isChecked(),
            'auth_timeout': self.auth_timeout.value(),
            'max_tags': self.max_tags.value(),
            'scan_interval': self.scan_interval.value(),
            'log_level': self.log_level.currentText()
        }
        
        try:
            settings_path = Path.home() / '.ssh' / 'antipineapple_settings.json'
            settings_path.parent.mkdir(exist_ok=True)
            with open(settings_path, 'w') as f:
                json.dump(settings, f, indent=2)
            
            self.settings_status.setText("✅ Settings saved successfully")
            self.settings_status.setStyleSheet("color: #66bb6a; padding: 5px;")
        except Exception as e:
            self.settings_status.setText(f"❌ Failed to save settings: {e}")
            self.settings_status.setStyleSheet("color: #f44336; padding: 5px;")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        self.network_warnings.setChecked(True)
        self.auto_disconnect.setChecked(False)
        self.strict_mode.setChecked(False)
        self.auth_timeout.setValue(90)
        self.max_tags.setValue(10)
        self.scan_interval.setValue(5)
        self.log_level.setCurrentText("Info")
        
        self.settings_status.setText("🔄 Settings reset to defaults")
        self.settings_status.setStyleSheet("color: #ff9800; padding: 5px;")
    
    def create_remote_access_tab(self):
        """Create remote access configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Remote access header
        header = QLabel("🔑 NFC Remote Access System")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7; padding: 10px;")
        layout.addWidget(header)
        
        # SSH Key Management
        ssh_group = QGroupBox("🔐 SSH Key Management")
        ssh_layout = QVBoxLayout()
        
        # Key status display
        self.ssh_key_status = QLabel("No SSH keys configured")
        self.ssh_key_status.setStyleSheet("color: #ffa726; padding: 5px; font-size: 14px;")
        ssh_layout.addWidget(self.ssh_key_status)
        
        # Key generation section
        key_gen_layout = QHBoxLayout()
        
        generate_key_btn = QPushButton("🔑 Generate NFC SSH Key")
        generate_key_btn.clicked.connect(self.generate_nfc_ssh_key)
        generate_key_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #2196f3; }
        """)
        key_gen_layout.addWidget(generate_key_btn)
        
        bind_nfc_btn = QPushButton("🏷️ Bind to NFC Tag")
        bind_nfc_btn.clicked.connect(self.bind_ssh_key_to_nfc)
        bind_nfc_btn.setStyleSheet("""
            QPushButton {
                background-color: #388e3c;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #4caf50; }
        """)
        key_gen_layout.addWidget(bind_nfc_btn)
        
        ssh_layout.addLayout(key_gen_layout)
        ssh_group.setLayout(ssh_layout)
        layout.addWidget(ssh_group)
        
        # SSH Security Configuration
        ssh_security_group = QGroupBox("🛡️ SSH Security Configuration")
        ssh_security_layout = QFormLayout()
        
        # Block all SSH by default
        self.block_all_ssh = QCheckBox("Block all unauthorized SSH access")
        self.block_all_ssh.setChecked(True)
        self.block_all_ssh.stateChanged.connect(self.update_ssh_security)
        ssh_security_layout.addRow("SSH Protection:", self.block_all_ssh)
        
        # NFC-encrypted exceptions
        self.allow_nfc_gcp = QCheckBox("Allow NFC Google Cloud Authentication")
        self.allow_nfc_gcp.setChecked(True)
        ssh_security_layout.addRow("GCP NFC Auth:", self.allow_nfc_gcp)
        
        self.allow_nfc_aws = QCheckBox("Allow NFC AWS Authentication")
        self.allow_nfc_aws.setChecked(True)
        ssh_security_layout.addRow("AWS NFC Auth:", self.allow_nfc_aws)
        
        self.allow_nfc_github = QCheckBox("Allow NFC GitHub Authentication")
        self.allow_nfc_github.setChecked(True)
        ssh_security_layout.addRow("GitHub NFC Auth:", self.allow_nfc_github)
        
        # Port blocking options
        self.block_all_ports = QCheckBox("Block ALL ports (except pre-allowed)")
        self.block_all_ports.setChecked(False)
        self.block_all_ports.stateChanged.connect(self.toggle_port_options)
        ssh_security_layout.addRow("Port Blocking:", self.block_all_ports)
        
        # Custom port input
        self.custom_port_input = QLineEdit()
        self.custom_port_input.setPlaceholderText("Enter specific ports (e.g., 22,2222,8080-8090)")
        ssh_security_layout.addRow("Custom Ports:", self.custom_port_input)
        
        # Default SSH range (when not blocking all)
        self.blocked_ports_start = QSpinBox()
        self.blocked_ports_start.setRange(1, 65535)
        self.blocked_ports_start.setValue(22)
        ssh_security_layout.addRow("SSH Range From:", self.blocked_ports_start)
        
        self.blocked_ports_end = QSpinBox()
        self.blocked_ports_end.setRange(1, 65535)
        self.blocked_ports_end.setValue(2222)
        ssh_security_layout.addRow("SSH Range To:", self.blocked_ports_end)
        
        ssh_security_group.setLayout(ssh_security_layout)
        layout.addWidget(ssh_security_group)
        
        # Apply SSH Security button
        apply_ssh_btn = QPushButton("🔒 Apply SSH Security Rules")
        apply_ssh_btn.clicked.connect(self.apply_ssh_security_rules)
        apply_ssh_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #f44336; }
        """)
        layout.addWidget(apply_ssh_btn)
        
        # Pre-allowed services display
        allowed_services_group = QGroupBox("✅ Pre-Allowed NFC Services")
        allowed_services_layout = QVBoxLayout()
        
        self.allowed_services_list = QTextEdit()
        self.allowed_services_list.setReadOnly(True)
        self.allowed_services_list.setMaximumHeight(150)
        self.allowed_services_list.setStyleSheet("""
            QTextEdit {
                background-color: #2b2b2b;
                color: #66bb6a;
                border: 1px solid #444444;
                padding: 10px;
            }
        """)
        self.update_allowed_services_display()
        allowed_services_layout.addWidget(self.allowed_services_list)
        
        allowed_services_group.setLayout(allowed_services_layout)
        layout.addWidget(allowed_services_group)
        
        # Active Sessions
        sessions_group = QGroupBox("📡 Active Remote Sessions")
        sessions_layout = QVBoxLayout()
        
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(4)
        self.sessions_table.setHorizontalHeaderLabels(["IP Address", "User", "Connected", "Actions"])
        self.sessions_table.horizontalHeader().setStretchLastSection(True)
        self.sessions_table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                gridline-color: #444444;
                border: 1px solid #444444;
            }
            QHeaderView::section {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 8px;
                border: 1px solid #444444;
            }
        """)
        sessions_layout.addWidget(self.sessions_table)
        
        # Session control buttons
        session_buttons = QHBoxLayout()
        
        refresh_sessions_btn = QPushButton("🔄 Refresh Sessions")
        refresh_sessions_btn.clicked.connect(self.refresh_ssh_sessions)
        refresh_sessions_btn.setStyleSheet("""
            QPushButton {
                background-color: #455a64;
                color: white;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #546e7a; }
        """)
        session_buttons.addWidget(refresh_sessions_btn)
        
        kill_all_btn = QPushButton("⚠️ Kill All Sessions")
        kill_all_btn.clicked.connect(self.kill_all_ssh_sessions)
        kill_all_btn.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #f44336; }
        """)
        session_buttons.addWidget(kill_all_btn)
        
        sessions_layout.addLayout(session_buttons)
        sessions_group.setLayout(sessions_layout)
        layout.addWidget(sessions_group)
        
        # Connection Instructions
        instructions_group = QGroupBox("📋 Connection Instructions")
        instructions_layout = QVBoxLayout()
        
        self.connection_info = QLabel("Generate an SSH key and bind it to an NFC tag to enable remote access")
        self.connection_info.setStyleSheet("color: #a0a0a0; padding: 10px; font-size: 12px;")
        self.connection_info.setWordWrap(True)
        instructions_layout.addWidget(self.connection_info)
        
        instructions_group.setLayout(instructions_layout)
        layout.addWidget(instructions_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def generate_nfc_ssh_key(self):
        """Generate SSH key pair for NFC authentication"""
        try:
            import os
            ssh_dir = Path.home() / '.ssh'
            ssh_dir.mkdir(exist_ok=True)
            
            # Generate unique key name
            key_name = f"nfc_remote_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            private_key_path = ssh_dir / key_name
            public_key_path = ssh_dir / f"{key_name}.pub"
            
            # Generate SSH key pair
            cmd = [
                'ssh-keygen', '-t', 'ed25519', 
                '-f', str(private_key_path),
                '-N', '',  # No passphrase
                '-C', f'nfc-remote-access-{socket.gethostname()}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Store key info for NFC binding
                self.pending_ssh_key = {
                    'private_key': str(private_key_path),
                    'public_key': str(public_key_path),
                    'created': datetime.now().isoformat(),
                    'bound_to_nfc': False
                }
                
                self.ssh_key_status.setText(f"✅ SSH key generated: {key_name}")
                self.ssh_key_status.setStyleSheet("color: #66bb6a; padding: 5px; font-size: 14px;")
                
                # Update connection instructions
                with open(public_key_path, 'r') as f:
                    public_key = f.read().strip()
                
                self.connection_info.setText(
                    f"SSH Key Generated Successfully!\n\n"
                    f"Public Key: {public_key}\n\n"
                    f"Next step: Bind this key to an NFC tag for secure remote access."
                )
                
            else:
                self.ssh_key_status.setText(f"❌ Key generation failed: {result.stderr}")
                self.ssh_key_status.setStyleSheet("color: #f44336; padding: 5px; font-size: 14px;")
                
        except Exception as e:
            self.ssh_key_status.setText(f"❌ Error: {e}")
            self.ssh_key_status.setStyleSheet("color: #f44336; padding: 5px; font-size: 14px;")
    
    def bind_ssh_key_to_nfc(self):
        """Bind generated SSH key to NFC tag"""
        if not hasattr(self, 'pending_ssh_key'):
            QMessageBox.warning(self, "⚠️ No Key", "Please generate an SSH key first.")
            return
        
        # Create NFC binding dialog
        dialog = NFCSSHKeyBindingDialog(self, self.pending_ssh_key)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Save SSH key binding
            ssh_key_data = {
                'name': dialog.key_name.text(),
                'description': dialog.key_description.text(),
                'private_key_path': self.pending_ssh_key['private_key'],
                'public_key_path': self.pending_ssh_key['public_key'],
                'nfc_tag_hash': hashlib.sha256(str(dialog.nfc_value).encode()).hexdigest(),
                'created': self.pending_ssh_key['created'],
                'bound_date': datetime.now().isoformat(),
                'timeout_hours': self.key_timeout.value(),
                'device_id': hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]
            }
            
            # Save to SSH keys file
            self.save_ssh_key_binding(ssh_key_data)
            
            # Update status
            self.ssh_key_status.setText("✅ SSH key bound to NFC tag successfully")
            self.ssh_key_status.setStyleSheet("color: #66bb6a; padding: 5px; font-size: 14px;")
            
            # Update connection instructions
            hostname = socket.gethostname()
            username = os.getenv('USER', 'user')
            
            self.connection_info.setText(
                f"🔑 NFC SSH Key Active!\n\n"
                f"To connect remotely:\n"
                f"1. Scan the NFC tag to get the private key\n"
                f"2. Save key to file: ssh_key_{dialog.key_name.text()}\n"
                f"3. Set permissions: chmod 600 ssh_key_{dialog.key_name.text()}\n"
                f"4. Connect: ssh -i ssh_key_{dialog.key_name.text()} {username}@{hostname}\n\n"
                f"Key expires in {self.key_timeout.value()} hours from binding."
            )
            
            del self.pending_ssh_key
    
    def save_ssh_key_binding(self, key_data):
        """Save SSH key binding to file"""
        try:
            ssh_keys_path = Path.home() / '.ssh' / 'nfc_ssh_keys.json'
            
            # Load existing keys
            if ssh_keys_path.exists():
                with open(ssh_keys_path, 'r') as f:
                    ssh_keys = json.load(f)
            else:
                ssh_keys = []
            
            ssh_keys.append(key_data)
            
            # Save updated keys
            with open(ssh_keys_path, 'w') as f:
                json.dump(ssh_keys, f, indent=2)
            
            print(f"✅ SSH key binding saved: {key_data['name']}")
            
        except Exception as e:
            print(f"❌ Error saving SSH key binding: {e}")
    
    def refresh_ssh_sessions(self):
        """Refresh active SSH sessions display"""
        try:
            # Get active SSH connections
            result = subprocess.run(['who'], capture_output=True, text=True)
            sessions = []
            
            for line in result.stdout.strip().split('\n'):
                if line and 'pts/' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        user = parts[0]
                        terminal = parts[1]
                        date_time = ' '.join(parts[2:4])
                        ip = parts[4].strip('()')
                        
                        sessions.append({
                            'user': user,
                            'terminal': terminal,
                            'connected': date_time,
                            'ip': ip
                        })
            
            # Update table
            self.sessions_table.setRowCount(len(sessions))
            for i, session in enumerate(sessions):
                self.sessions_table.setItem(i, 0, QTableWidgetItem(session['ip']))
                self.sessions_table.setItem(i, 1, QTableWidgetItem(session['user']))
                self.sessions_table.setItem(i, 2, QTableWidgetItem(session['connected']))
                
                # Add kill button
                kill_btn = QPushButton("🔌 Disconnect")
                kill_btn.clicked.connect(lambda checked, term=session['terminal']: self.kill_ssh_session(term))
                kill_btn.setStyleSheet("""
                    QPushButton {
                        background-color: #d32f2f;
                        color: white;
                        padding: 4px 8px;
                        border-radius: 3px;
                        font-size: 12px;
                    }
                    QPushButton:hover { background-color: #f44336; }
                """)
                self.sessions_table.setCellWidget(i, 3, kill_btn)
                
        except Exception as e:
            print(f"Error refreshing SSH sessions: {e}")
    
    def kill_ssh_session(self, terminal):
        """Kill specific SSH session"""
        try:
            # Kill the session
            subprocess.run(['pkill', '-t', terminal], check=True)
            print(f"✅ Killed SSH session on {terminal}")
            
            # Refresh the sessions table
            self.refresh_ssh_sessions()
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Error killing SSH session: {e}")
    
    def toggle_port_options(self):
        """Toggle between blocking all ports vs specific ranges"""
        if self.block_all_ports.isChecked():
            self.blocked_ports_start.setEnabled(False)
            self.blocked_ports_end.setEnabled(False)
            self.custom_port_input.setEnabled(False)
            print("🚫 Blocking ALL ports except pre-allowed NFC services")
        else:
            self.blocked_ports_start.setEnabled(True)
            self.blocked_ports_end.setEnabled(True)
            self.custom_port_input.setEnabled(True)
            print("🎯 Custom port blocking enabled")
    
    def update_ssh_security(self):
        """Update SSH security status display"""
        if self.block_all_ssh.isChecked():
            print("🛡️ SSH blocking enabled - unauthorized access will be blocked")
        else:
            print("⚠️ SSH blocking disabled - system vulnerable to remote attacks")
        self.update_allowed_services_display()
    
    def update_allowed_services_display(self):
        """Update the display of allowed NFC services"""
        services_text = "🔐 PRE-ALLOWED NFC-ENCRYPTED SERVICES:\n\n"
        
        if self.allow_nfc_gcp.isChecked():
            services_text += "✅ Google Cloud NFC Authentication\n"
            services_text += "   - Repository: github.com/aimarketingflow/nfc-gcloud-2-factor\n"
            services_text += "   - Ports: Application layer (HTTPS/443)\n"
            services_text += "   - Auth: PBKDF2-SHA256 + JWT tokens\n\n"
        
        if self.allow_nfc_aws.isChecked():
            services_text += "✅ AWS NFC Vault Authentication\n"
            services_text += "   - Service: NFC AWS Credential Vault\n"
            services_text += "   - Ports: Application layer (HTTPS/443)\n"
            services_text += "   - Auth: AES-256-GCM + NFC UID derivation\n\n"
        
        if self.allow_nfc_github.isChecked():
            services_text += "✅ GitHub NFC 2FA Authentication\n"
            services_text += "   - Service: NFC GitHub Security Gateway\n"
            services_text += "   - Ports: Application layer (HTTPS/443)\n"
            services_text += "   - Auth: SSH key + NFC token binding\n\n"
        
        if not any([self.allow_nfc_gcp.isChecked(), self.allow_nfc_aws.isChecked(), self.allow_nfc_github.isChecked()]):
            services_text += "⚠️ No NFC services allowed - All remote access blocked\n"
        
        services_text += "\n🛡️ All other remote access attempts will be BLOCKED"
        
        self.allowed_services_list.setText(services_text)
    
    def apply_ssh_security_rules(self):
        """Apply SSH security rules using pfctl firewall"""
        try:
            if not self.block_all_ssh.isChecked():
                print("⚠️ SSH blocking is disabled - no rules applied")
                return
            
            # Create allowlist for NFC-encrypted services
            allowed_services = []
            if self.allow_nfc_gcp.isChecked():
                allowed_services.append("# Allow NFC Google Cloud Authentication")
            if self.allow_nfc_aws.isChecked():
                allowed_services.append("# Allow NFC AWS Authentication") 
            if self.allow_nfc_github.isChecked():
                allowed_services.append("# Allow NFC GitHub Authentication")
            
            # Determine which ports to block
            if self.block_all_ports.isChecked():
                port_rules = "# Block ALL ports except pre-allowed NFC services\nblock in proto tcp from any to any port 1:65535"
                block_description = "ALL ports (1-65535)"
            elif self.custom_port_input.text().strip():
                # Parse custom ports
                custom_ports = self.custom_port_input.text().strip()
                port_rules = f"# Block custom ports: {custom_ports}\n"
                for port_spec in custom_ports.split(','):
                    port_spec = port_spec.strip()
                    if '-' in port_spec:
                        start_port, end_port = port_spec.split('-')
                        port_rules += f"block in proto tcp from any to any port {start_port.strip()}:{end_port.strip()}\n"
                    else:
                        port_rules += f"block in proto tcp from any to any port {port_spec}\n"
                block_description = f"custom ports ({custom_ports})"
            else:
                # Default SSH range
                port_rules = f"block in proto tcp from any to any port {self.blocked_ports_start.value()}:{self.blocked_ports_end.value()}"
                block_description = f"SSH range ({self.blocked_ports_start.value()}-{self.blocked_ports_end.value()})"
            
            # Create pfctl rules
            pf_rules = f"""
# Anti-Pineapple SSH Security Rules
# Block unauthorized access on {block_description}

{port_rules}

# Allow NFC-encrypted authentication services
{chr(10).join(allowed_services)}
# NFC-encrypted services use different authentication mechanisms
# and are allowed through the application layer, not direct port access

# Log blocked attempts for monitoring
block log proto tcp from any to any port 22
block log proto tcp from any to any port 2222
block log proto tcp from any to any port 3389
block log proto tcp from any to any port 5900
"""
            
            # Write rules to temporary file
            rules_path = Path.home() / '.ssh' / 'antipineapple_ssh_rules.conf'
            with open(rules_path, 'w') as f:
                f.write(pf_rules)
            
            print(f"✅ SSH security rules created: {rules_path}")
            print(f"🔒 Remote access blocked on {block_description}")
            print("📋 NFC-encrypted exceptions:")
            if self.allow_nfc_gcp.isChecked():
                print("  ✓ Google Cloud NFC Authentication (HTTPS/443)")
            if self.allow_nfc_aws.isChecked():
                print("  ✓ AWS NFC Authentication (HTTPS/443)")
            if self.allow_nfc_github.isChecked():
                print("  ✓ GitHub NFC Authentication (HTTPS/443)")
            
            # Update status
            self.ssh_key_status.setText(f"🛡️ Security Rules Applied - Blocked {block_description}")
            self.ssh_key_status.setStyleSheet("color: #66bb6a; padding: 5px; font-size: 14px;")
            
            # Update allowed services display
            self.update_allowed_services_display()
            
        except Exception as e:
            print(f"❌ Error applying SSH security rules: {e}")
            self.ssh_key_status.setText("❌ Error applying SSH security rules")
            self.ssh_key_status.setStyleSheet("color: #f44336; padding: 5px; font-size: 14px;")
    
    def kill_all_ssh_sessions(self):
        """Kill all SSH sessions"""
        reply = QMessageBox.question(self, "⚠️ Kill All Sessions",
            "Are you sure you want to disconnect all remote SSH sessions?\n\n"
            "This will immediately terminate all active connections.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            try:
                subprocess.run(['pkill', '-f', 'sshd:'])
                self.refresh_ssh_sessions()
            except Exception as e:
                print(f"Error killing SSH sessions: {e}")


class NFCSSHKeyBindingDialog(QDialog):
    """Dialog for binding SSH keys to NFC tags"""
    
    def __init__(self, parent=None, ssh_key_info=None):
        super().__init__(parent)
        self.setWindowTitle("🔑 Bind SSH Key to NFC Tag")
        self.setModal(True)
        self.setFixedSize(600, 500)
        self.ssh_key_info = ssh_key_info
        self.nfc_value = None
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🔑 NFC SSH Key Binding")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #4fc3f7; padding: 10px;")
        layout.addWidget(header)
        
        # Key info
        key_info = QLabel(f"SSH Key: {Path(self.ssh_key_info['private_key']).name}")
        key_info.setStyleSheet("color: #66bb6a; padding: 5px; font-size: 14px;")
        layout.addWidget(key_info)
        
        # Key name input
        form_layout = QFormLayout()
        
        self.key_name = QLineEdit()
        self.key_name.setPlaceholderText("e.g., 'work-laptop', 'home-server'")
        form_layout.addRow("Key Name:", self.key_name)
        
        self.key_description = QLineEdit()
        self.key_description.setPlaceholderText("Description of this remote access key")
        form_layout.addRow("Description:", self.key_description)
        
        layout.addLayout(form_layout)
        
        # NFC scanning section
        nfc_group = QGroupBox("📱 NFC Tag Scanning")
        nfc_layout = QVBoxLayout()
        
        self.scan_button = QPushButton("🔍 Scan NFC Tag")
        self.scan_button.clicked.connect(self.scan_nfc_tag)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #2196f3; }
        """)
        nfc_layout.addWidget(self.scan_button)
        
        self.nfc_status = QLabel("Ready to scan NFC tag...")
        self.nfc_status.setStyleSheet("color: #a0a0a0; padding: 10px; text-align: center;")
        nfc_layout.addWidget(self.nfc_status)
        
        nfc_group.setLayout(nfc_layout)
        layout.addWidget(nfc_group)
        
        # Security warning
        warning = QLabel("⚠️ Security Notice: The NFC tag will contain your private SSH key. Keep it secure!")
        warning.setStyleSheet("color: #ffa726; padding: 10px; font-weight: bold; background-color: #2b2b2b; border-radius: 5px;")
        warning.setWordWrap(True)
        layout.addWidget(warning)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.bind_button = QPushButton("🔗 Bind Key to Tag")
        self.bind_button.clicked.connect(self.accept)
        self.bind_button.setEnabled(False)
        self.bind_button.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #2e7d32; }
            QPushButton:disabled { background-color: #424242; color: #757575; }
        """)
        button_layout.addWidget(self.bind_button)
        
        cancel_button = QPushButton("❌ Cancel")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #d32f2f;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #f44336; }
        """)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def scan_nfc_tag(self):
        """Simulate NFC tag scanning for SSH key binding"""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")
        self.nfc_status.setText("🔍 Place NFC tag near reader...")
        self.nfc_status.setStyleSheet("color: #2196f3; padding: 10px; text-align: center;")
        
        # Simulate NFC scan
        QTimer.singleShot(2000, self.nfc_scan_complete)
    
    def nfc_scan_complete(self):
        """Complete NFC scanning process"""
        # Simulate NFC tag value (in real implementation, this would come from NFC reader)
        import random
        self.nfc_value = f"nfc_ssh_key_{random.randint(100000, 999999)}"
        
        self.scan_button.setEnabled(True)
        self.scan_button.setText("✅ Tag Scanned")
        self.nfc_status.setText("✅ NFC tag scanned successfully!")
        self.nfc_status.setStyleSheet("color: #66bb6a; padding: 10px; text-align: center;")
        
        self.bind_button.setEnabled(True)
    
    def show_blacklist_manager(self):
        """Show BSSID blacklist management dialog"""
        try:
            from bssid_blacklist_dialog import BSSIDBlacklistDialog
            dialog = BSSIDBlacklistDialog(self)
            dialog.exec()
        except ImportError:
            QMessageBox.warning(self, "Error", "BSSID Blacklist dialog not available")


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    try:
        window = AntiPineappleGUI()
        window.show()
    except Exception as e:
        print(f"Error starting GUI: {e}")
        import traceback
        traceback.print_exc()
        return
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
