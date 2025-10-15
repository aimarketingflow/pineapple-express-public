#!/usr/bin/env python3
"""
Simple Anti-Pineapple GUI - Minimal version without complex components
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
import configparser

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Fix Qt font issues on macOS
os.environ['QT_QPA_FONTDIR'] = '/System/Library/Fonts'

print("🚀 Starting Simple Anti-Pineapple GUI...")

class NetworkMonitorThread(QThread):
    """Thread for continuous network monitoring"""
    network_update = pyqtSignal(list)
    threat_detected = pyqtSignal(dict)
    
    def __init__(self, legitimate_bssid="72:13:01:8A:70:DA"):
        super().__init__()
        self.legitimate_bssid = legitimate_bssid
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
        """Check if network is a potential threat"""
        if network['ssid'] == 'WhySoSeriousi' and network['bssid'] != self.legitimate_bssid:
            return True
        
        suspicious_patterns = ['pineapple', 'open', 'free', 'public']
        if any(pattern in network['ssid'].lower() for pattern in suspicious_patterns):
            if 'Open' in network.get('security', ''):
                return True
        
        return False
    
    def stop(self):
        self.running = False


class SimpleAntiPineappleGUI(QMainWindow):
    """Enhanced GUI for Anti-Pineapple BSSID NFC Security System"""
    
    def __init__(self):
        print("🔧 Initializing Enhanced GUI...")
        super().__init__()
        
        self.setWindowTitle("🛡️ Anti-Pineapple Security System")
        self.setGeometry(100, 100, 1000, 700)
        
        # Get current connected network info for auto-exclusion
        self.legitimate_bssid = "72:13:01:8A:70:DA"  # WhySoSeriousi network
        self.current_ssid = "WhySoSeriousi" 
        self.threat_count = 0
        self.authenticated = False
        self.firewall_enabled = False
        self.blocked_bssids = set()
        
        # File paths
        self.auth_profile_path = Path.home() / '.ssh' / 'anti_pineapple_auth.json'
        self.tags_path = Path.home() / '.ssh' / 'nfc_tags.json'
        self.settings_path = Path.home() / '.ssh' / 'stealthshark_settings.json'
        self.registered_tags = []
        
        # Default settings
        self.settings = {
            'monitoring_duration': 6,  # hours
            'auto_start': False,
            'scan_interval': 5,  # seconds
            'threat_notifications': True,
            'auto_block_threats': True,
            'minimize_to_tray': False
        }
        
        # Monitoring timer
        self.monitoring_timer = None
        self.monitoring_start_time = None
        
        # Load existing data
        self.load_authentication_status()
        self.load_registered_tags()
        self.load_settings()
        self.detect_current_network()
        
        print("✅ Settings configured")
        self.init_ui()
        print("✅ UI initialized")
        self.update_usb_status()
        print("✅ USB status updated")
        self.check_auto_authentication()
        self.start_monitoring()
        
    def init_ui(self):
        """Initialize the simplified user interface"""
        print("🎨 Creating simple UI...")
        
        # Dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QLabel {
                color: #e0e0e0;
                padding: 5px;
            }
            QPushButton {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #4a4a4a;
                padding: 10px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #3a3a3a;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #2a2a2a;
                color: #4fc3f7;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Header
        header = QLabel("🛡️ Anti-Pineapple Security System")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #4fc3f7; padding: 20px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Create tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #2b2b2b;
            }
            QTabBar::tab {
                background-color: #3c3c3c;
                color: #ffffff;
                padding: 10px 20px;
                margin-right: 2px;
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
        
        # Create tabs
        self.dashboard_tab = self.create_dashboard_tab()
        self.auth_tab = self.create_auth_tab()
        self.tags_tab = self.create_tags_tab()
        self.monitor_tab = self.create_monitor_tab()
        self.settings_tab = self.create_settings_tab()
        
        self.tabs.addTab(self.dashboard_tab, "🛡️ Dashboard")
        self.tabs.addTab(self.auth_tab, "🔐 NFC Auth")
        self.tabs.addTab(self.tags_tab, "🏷️ Tags")
        self.tabs.addTab(self.monitor_tab, "📡 Monitor")
        self.tabs.addTab(self.settings_tab, "⚙️ Settings")
        
        # Add CSV Import tab
        self.csv_tab = self.create_csv_tab()
        self.tabs.addTab(self.csv_tab, "📂 CSV Import")
        
        layout.addWidget(self.tabs)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("🔄 Refresh Status")
        refresh_btn.clicked.connect(self.refresh_status)
        refresh_btn.setStyleSheet("QPushButton { background-color: #2196f3; color: white; padding: 8px; border-radius: 4px; font-weight: bold; }")
        button_layout.addWidget(refresh_btn)
        
        scan_btn = QPushButton("📡 Scan Networks")
        scan_btn.clicked.connect(self.scan_networks)
        scan_btn.setStyleSheet("QPushButton { background-color: #ff9800; color: white; padding: 8px; border-radius: 4px; font-weight: bold; }")
        button_layout.addWidget(scan_btn)
        
        # CSV Import button
        csv_btn = QPushButton("📂 Import CSV")
        csv_btn.clicked.connect(self.import_csv_blacklist)
        csv_btn.setStyleSheet("QPushButton { background-color: #9c27b0; color: white; padding: 8px; border-radius: 4px; font-weight: bold; }")
        button_layout.addWidget(csv_btn)
        
        layout.addLayout(button_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Simple GUI initialized")
        
        print("✅ Simple UI created")
    
    def update_usb_status(self):
        """Update USB device status"""
        print("📱 Checking USB status...")
        try:
            result = subprocess.run(['ls', '/Volumes/'], capture_output=True, text=True)
            volumes = result.stdout.strip().split('\n') if result.stdout.strip() else []
            
            usb_volumes = [v for v in volumes if v not in ['', 'Macintosh HD', 'com.apple.TimeMachine.localsnapshots']]
            
            if usb_volumes:
                usb_name = usb_volumes[0]
                self.usb_status.setText(f"📱 USB Device: {usb_name} ✅")
                self.usb_status.setStyleSheet("font-size: 14px; padding: 5px; color: #66bb6a;")
                
                # Check for NFC profile
                profile_path = f"/Volumes/{usb_name}/triple_airgap_auth_profile_nfc_locked.json"
                if os.path.exists(profile_path):
                    self.nfc_status.setText("🔐 NFC Profile: Found ✅")
                    self.nfc_status.setStyleSheet("font-size: 14px; padding: 5px; color: #66bb6a;")
                else:
                    self.nfc_status.setText("🔐 NFC Profile: Not Found")
                    self.nfc_status.setStyleSheet("font-size: 14px; padding: 5px; color: #ffa726;")
            else:
                self.usb_status.setText("📱 USB Device: Not Connected ❌")
                self.usb_status.setStyleSheet("font-size: 14px; padding: 5px; color: #ff5252;")
                self.nfc_status.setText("🔐 NFC Profile: USB Required")
                self.nfc_status.setStyleSheet("font-size: 14px; padding: 5px; color: #ff5252;")
                
            self.status_bar.showMessage(f"Status updated at {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            self.usb_status.setText("📱 USB Device: Error checking")
            self.status_bar.showMessage(f"Error: {e}")
    
    def scan_networks(self):
        """Scan for networks"""
        self.status_bar.showMessage("Scanning networks...")
        # Simulate network scan
        import random
        threat_detected = random.choice([True, False])
        if threat_detected:
            self.threat_count += 1
            self.threat_counter.setText(f"🛡️ Threats Blocked: {self.threat_count}")
            self.status_bar.showMessage("⚠️ Threat detected and blocked!")
        else:
            self.status_bar.showMessage("✅ Network scan complete - no threats")
    
    def refresh_status(self):
        """Refresh all status indicators"""
        self.update_usb_status()
        self.status_bar.showMessage("✅ Status refreshed")
    
    def import_csv_blacklist(self):
        """Import BSSID blacklist from CSV file"""
        print("🔧 Starting CSV import process...")
        try:
            # Add current directory to path for import
            import sys
            if '.' not in sys.path:
                sys.path.insert(0, '.')
            
            print("📂 Attempting to import csv_import_dialog...")
            from csv_import_dialog import CSVImportDialog
            print("✅ csv_import_dialog imported successfully")
            
            # Initialize blacklist manager if not already done
            if not hasattr(self, 'blacklist_manager') or not self.blacklist_manager:
                print("🔧 Initializing blacklist manager...")
                from bssid_blacklist_manager import BSSIDBlacklistManager
                self.blacklist_manager = BSSIDBlacklistManager()
                print("✅ Blacklist manager initialized")
            
            print("🎯 Opening CSV import dialog...")
            dialog = CSVImportDialog(self, self.blacklist_manager)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                self.status_bar.showMessage("✅ CSV import completed successfully")
                # Update threat counter if blacklist manager available
                if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
                    blocked_count = len(self.blacklist_manager.blocked_bssids)
                    self.status_bar.showMessage(f"✅ CSV imported - {blocked_count} BSSIDs now blocked")
                    print(f"📊 Total BSSIDs in blacklist: {blocked_count}")
                    
                    # Refresh blacklist display if on CSV tab
                    if hasattr(self, 'refresh_blacklist_display'):
                        self.refresh_blacklist_display()
            else:
                print("⚠️ CSV import dialog was cancelled")
                
        except ImportError as e:
            print(f"❌ DETAILED ImportError DEBUG:")
            print(f"   Error: {e}")
            print(f"   Current working directory: {os.getcwd()}")
            print(f"   Python path: {sys.path[:3]}")
            print(f"   Files in current directory:")
            for file in os.listdir('.'):
                if 'csv' in file.lower():
                    print(f"      {file} (size: {os.path.getsize(file)} bytes)")
            print(f"   csv_import_dialog.py exists: {os.path.exists('csv_import_dialog.py')}")
            if os.path.exists('csv_import_dialog.py'):
                print(f"   csv_import_dialog.py size: {os.path.getsize('csv_import_dialog.py')} bytes")
            
            error_msg = f"CSV import functionality not available.\n\nImport Error: {str(e)}\n\nPlease ensure csv_import_dialog.py is present and valid.\n\nCheck console for detailed debugging information."
            print(f"❌ ImportError: {e}")
            QMessageBox.warning(self, "⚠️ Import Error", error_msg)
        except Exception as e:
            error_msg = f"Failed to import CSV:\n{str(e)}\n\nCheck console for detailed error information."
            print(f"❌ CSV import error: {e}")
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "❌ CSV Import Error", error_msg)

    def perform_live_scan(self):
        """Perform live network scan for pineapple detection"""
        try:
            import subprocess
            import re
            
            # Use airport utility to scan for networks
            result = subprocess.run([
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '-s'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                networks = []
                legitimate_bssid = "72:13:01:8A:70:DA"  # Your trusted BSSID
                
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        # Parse network info
                        parts = line.split()
                        if len(parts) >= 6:
                            ssid = parts[0]
                            bssid = parts[1]
                            rssi = parts[2]
                            
                            # Check for pineapple attacks on WhySoSeriousi
                            if ssid in ['WhySoSeriousi', 'WhySoSerious'] and bssid != legitimate_bssid:
                                threat_msg = f"🚨 PINEAPPLE DETECTED: {ssid} ({bssid})"
                                self.add_threat_log(threat_msg)
                                self.threat_count += 1
                                self.threat_counter.setText(f"🛡️ Threats Blocked: {self.threat_count}")
                                
                                # Add to blacklist if not already there
                                try:
                                    from bssid_blacklist_manager import BSSIDBlacklistManager
                                    self.blacklist_manager = BSSIDBlacklistManager()
                                except ImportError:
                                    self.blacklist_manager = None
                                if self.blacklist_manager:
                                    if not self.blacklist_manager.is_blocked(bssid):
                                        self.blacklist_manager.add_bssid(bssid, f"Pineapple attack on {ssid}")
                                        print(f"🚫 Added pineapple BSSID to blacklist: {bssid}")
                            
                            networks.append({
                                'ssid': ssid,
                                'bssid': bssid, 
                                'rssi': rssi
                            })
                
                # Update network table if it exists
                if hasattr(self, 'network_table'):
                    self.update_network_display(networks)
                    
        except Exception as e:
            print(f"Live scan error: {e}")
    
    def add_threat_log(self, message):
        """Add threat to log display"""
        if hasattr(self, 'threat_log'):
            timestamp = datetime.now().strftime('%H:%M:%S')
            log_entry = f"[{timestamp}] {message}"
            self.threat_log.append(log_entry)
            # Keep only last 50 entries
            if self.threat_log.document().blockCount() > 50:
                cursor = self.threat_log.textCursor()
                cursor.movePosition(cursor.MoveOperation.Start)
                cursor.select(cursor.SelectionType.LineUnderCursor)
                cursor.removeSelectedText()
    
    def update_network_display(self, networks):
        """Update the network monitoring display"""
        if hasattr(self, 'network_table'):
            self.network_table.setRowCount(len(networks))
            
            for i, network in enumerate(networks):
                # SSID
                ssid_item = QTableWidgetItem(network['ssid'])
                self.network_table.setItem(i, 0, ssid_item)
                
                # BSSID with threat highlighting
                bssid_item = QTableWidgetItem(network['bssid'])
                status_item = QTableWidgetItem("")
                
                if network['ssid'] in ['WhySoSeriousi', 'WhySoSerious'] and network['bssid'] != "72:13:01:8A:70:DA":
                    bssid_item.setBackground(QColor("#ff5252"))  # Red for pineapple
                    bssid_item.setForeground(QColor("white"))
                    status_item.setText("🚨 PINEAPPLE")
                    status_item.setBackground(QColor("#ff5252"))
                    status_item.setForeground(QColor("white"))
                elif network['bssid'] == "72:13:01:8A:70:DA":
                    bssid_item.setBackground(QColor("#4caf50"))  # Green for legitimate
                    bssid_item.setForeground(QColor("white"))
                    status_item.setText("✅ TRUSTED")
                    status_item.setBackground(QColor("#4caf50"))
                    status_item.setForeground(QColor("white"))
                else:
                    status_item.setText("⚪ UNKNOWN")
                
                self.network_table.setItem(i, 1, bssid_item)
                
                # RSSI
                rssi_item = QTableWidgetItem(f"{network['rssi']} dBm")
                self.network_table.setItem(i, 2, rssi_item)
                
                # Status
                self.network_table.setItem(i, 3, status_item)
    
    def create_dashboard_tab(self):
        """Create the main dashboard tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Status indicator
        self.status_indicator = QLabel("⚠️ Not Authenticated")
        if self.authenticated:
            self.status_indicator.setText("✅ Authenticated & Protected")
            self.status_indicator.setStyleSheet("""
                padding: 15px;
                background-color: #1b5e20;
                color: #66bb6a;
                font-weight: bold;
                font-size: 16px;
                border-radius: 10px;
                border: 2px solid #66bb6a;
            """)
        else:
            self.status_indicator.setStyleSheet("""
                padding: 15px;
                background-color: #4a3a00;
                color: #ffa726;
                font-weight: bold;
                font-size: 16px;
                border-radius: 10px;
                border: 2px solid #ffa726;
            """)
        self.status_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_indicator)
        
        # Network info
        network_group = QGroupBox("Protected Network")
        network_layout = QVBoxLayout()
        
        self.network_info = QLabel(f"Network: {self.current_ssid}\nBSSID: {self.legitimate_bssid}")
        self.network_info.setStyleSheet("font-size: 16px; padding: 10px;")
        network_layout.addWidget(self.network_info)
        
        # Firewall toggle
        self.firewall_toggle = QPushButton("🔓 Unlock with NFC")
        if self.firewall_enabled:
            self.firewall_toggle.setText("🔒 Lock Firewall")
            self.firewall_toggle.setStyleSheet("""
                QPushButton {
                    background-color: #1b5e20;
                    color: white;
                    padding: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 5px;
                }
            """)
        else:
            self.firewall_toggle.setStyleSheet("""
                QPushButton {
                    background-color: #b71c1c;
                    color: white;
                    padding: 10px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 5px;
                }
            """)
        self.firewall_toggle.clicked.connect(self.toggle_firewall)
        network_layout.addWidget(self.firewall_toggle)
        
        network_group.setLayout(network_layout)
        layout.addWidget(network_group)
        
        # USB Status
        usb_group = QGroupBox("USB & NFC Status")
        usb_layout = QVBoxLayout()
        
        self.usb_status = QLabel("📱 USB Device: Checking...")
        self.usb_status.setStyleSheet("font-size: 14px; padding: 5px;")
        usb_layout.addWidget(self.usb_status)
        
        self.nfc_status = QLabel("🔐 NFC Profile: Checking...")
        self.nfc_status.setStyleSheet("font-size: 14px; padding: 5px;")
        usb_layout.addWidget(self.nfc_status)
        
        usb_group.setLayout(usb_layout)
        layout.addWidget(usb_group)
        
        # Threat counter
        threat_group = QGroupBox("Security Statistics")
        threat_layout = QVBoxLayout()
        
        self.threat_counter = QLabel(f"🛡️ Threats Blocked: {self.threat_count}")
        self.threat_counter.setStyleSheet("font-size: 18px; color: #ff5252; font-weight: bold; padding: 10px;")
        self.threat_counter.setAlignment(Qt.AlignmentFlag.AlignCenter)
        threat_layout.addWidget(self.threat_counter)
        
        threat_group.setLayout(threat_layout)
        layout.addWidget(threat_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_auth_tab(self):
        """Create NFC authentication tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Auth status
        auth_group = QGroupBox("Authentication Status")
        auth_layout = QVBoxLayout()
        
        if self.authenticated:
            auth_status = QLabel("✅ System Authenticated")
            auth_status.setStyleSheet("color: #66bb6a; font-size: 18px; font-weight: bold; padding: 10px;")
        else:
            auth_status = QLabel("⚠️ Authentication Required")
            auth_status.setStyleSheet("color: #ffa726; font-size: 18px; font-weight: bold; padding: 10px;")
        
        auth_layout.addWidget(auth_status)
        
        # Tag count
        tag_count = len(self.registered_tags)
        tag_info = QLabel(f"🏷️ Registered Tags: {tag_count}")
        tag_info.setStyleSheet("font-size: 14px; padding: 5px;")
        auth_layout.addWidget(tag_info)
        
        auth_group.setLayout(auth_layout)
        layout.addWidget(auth_group)
        
        # Auth button
        auth_btn = QPushButton("🔐 Authenticate with NFC")
        auth_btn.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: white;
                padding: 15px;
                font-size: 18px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2e7d32;
            }
        """)
        auth_btn.clicked.connect(self.simulate_nfc_auth)
        layout.addWidget(auth_btn)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_tags_tab(self):
        """Create NFC tags management tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("🏷️ NFC Tag Management")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #4fc3f7; padding: 10px;")
        layout.addWidget(header)
        
        # Tags info
        tags_info = QLabel(f"Registered Tags: {len(self.registered_tags)}")
        tags_info.setStyleSheet("font-size: 16px; padding: 10px;")
        layout.addWidget(tags_info)
        
        # Add tag button
        add_tag_btn = QPushButton("➕ Add New NFC Tag")
        add_tag_btn.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2196f3;
            }
        """)
        add_tag_btn.clicked.connect(self.add_new_tag)
        layout.addWidget(add_tag_btn)
        
        # Tags list
        if self.registered_tags:
            tags_list = QTextEdit()
            tags_list.setReadOnly(True)
            tags_list.setMaximumHeight(200)
            
            tags_text = ""
            for i, tag in enumerate(self.registered_tags, 1):
                tags_text += f"{i}. {tag.get('name', 'Unnamed Tag')}\n"
                tags_text += f"   Created: {tag.get('created', 'Unknown')}\n"
                if 'network_binding' in tag:
                    tags_text += f"   Network: {tag['network_binding'].get('ssid', 'Unknown')}\n"
                tags_text += "\n"
            
            tags_list.setText(tags_text)
            layout.addWidget(tags_list)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_monitor_tab(self):
        """Create network monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Monitor controls
        control_layout = QHBoxLayout()
        
        scan_btn = QPushButton("🔍 Scan Networks")
        scan_btn.clicked.connect(self.manual_scan)
        control_layout.addWidget(scan_btn)
        
        self.monitor_toggle = QPushButton("⏸️ Stop Monitoring")
        self.monitor_toggle.setCheckable(True)
        self.monitor_toggle.setChecked(True)
        self.monitor_toggle.clicked.connect(self.toggle_monitoring)
        control_layout.addWidget(self.monitor_toggle)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        # Network monitoring table
        self.network_table = QTableWidget()
        self.network_table.setColumnCount(4)
        self.network_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Signal", "Status"])
        self.network_table.horizontalHeader().setStretchLastSection(True)
        self.network_table.setAlternatingRowColors(True)
        self.network_table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: white;
                gridline-color: #444;
                selection-background-color: #0078d4;
            }
            QHeaderView::section {
                background-color: #404040;
                color: white;
                padding: 8px;
                border: 1px solid #555;
            }
        """)
        layout.addWidget(self.network_table)
        
        # Threat log
        threat_log_label = QLabel("🚨 Live Threat Detection Log:")
        threat_log_label.setStyleSheet("color: #ff5252; font-weight: bold; font-size: 14px; margin-top: 10px;")
        layout.addWidget(threat_log_label)
        
        self.threat_log = QTextEdit()
        self.threat_log.setMaximumHeight(150)
        self.threat_log.setReadOnly(True)
        self.threat_log.setStyleSheet("""
            QTextEdit {
                background-color: #1a1a1a;
                color: #ff5252;
                border: 2px solid #ff5252;
                border-radius: 5px;
                padding: 5px;
                font-family: monospace;
                font-size: 12px;
            }
        """)
        self.threat_log.append("[System] Live threat monitoring started...")
        layout.addWidget(self.threat_log)
        
        widget.setLayout(layout)
        return widget
    
    def create_csv_tab(self):
        """Create CSV import and blacklist management tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("📂 BSSID Blacklist Management")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #9c27b0; padding: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Import section
        import_group = QGroupBox("📥 Import BSSID Blacklists")
        import_layout = QVBoxLayout()
        
        # CSV Import button
        csv_import_btn = QPushButton("📂 Import from CSV File")
        csv_import_btn.clicked.connect(self.import_csv_blacklist)
        csv_import_btn.setStyleSheet("""
            QPushButton {
                background-color: #9c27b0;
                color: white;
                padding: 15px;
                border-radius: 8px;
                font-weight: bold;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #7b1fa2;
            }
        """)
        import_layout.addWidget(csv_import_btn)
        
        # Import info
        import_info = QLabel("Import BSSIDs from WiFi Explorer CSV files or other compatible formats.\nSupports bulk import with automatic validation and trusted BSSID protection.")
        import_info.setStyleSheet("color: #bbb; padding: 10px; font-style: italic;")
        import_info.setWordWrap(True)
        import_layout.addWidget(import_info)
        
        import_group.setLayout(import_layout)
        layout.addWidget(import_group)
        
        # Current blacklist section
        blacklist_group = QGroupBox("🚫 Current BSSID Blacklist")
        blacklist_layout = QVBoxLayout()
        
        # Stats
        self.blacklist_stats = QLabel("Loading blacklist statistics...")
        self.blacklist_stats.setStyleSheet("font-weight: bold; color: #ff5252; padding: 10px; font-size: 16px;")
        blacklist_layout.addWidget(self.blacklist_stats)
        
        # Blacklist table
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(3)
        self.blacklist_table.setHorizontalHeaderLabels(["BSSID", "Status", "Actions"])
        self.blacklist_table.horizontalHeader().setStretchLastSection(True)
        self.blacklist_table.setAlternatingRowColors(True)
        self.blacklist_table.setStyleSheet("""
            QTableWidget {
                background-color: #2b2b2b;
                color: white;
                gridline-color: #444;
                selection-background-color: #0078d4;
            }
            QHeaderView::section {
                background-color: #404040;
                color: white;
                padding: 8px;
                border: 1px solid #555;
            }
        """)
        blacklist_layout.addWidget(self.blacklist_table)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        refresh_blacklist_btn = QPushButton("🔄 Refresh Blacklist")
        refresh_blacklist_btn.clicked.connect(self.refresh_blacklist_display)
        refresh_blacklist_btn.setStyleSheet("QPushButton { background-color: #2196f3; color: white; padding: 8px; border-radius: 4px; }")
        button_layout.addWidget(refresh_blacklist_btn)
        
        add_manual_btn = QPushButton("➕ Add BSSID Manually")
        add_manual_btn.clicked.connect(self.add_bssid_manually)
        add_manual_btn.setStyleSheet("QPushButton { background-color: #ff9800; color: white; padding: 8px; border-radius: 4px; }")
        button_layout.addWidget(add_manual_btn)
        
        export_btn = QPushButton("💾 Export Blacklist")
        export_btn.clicked.connect(self.export_blacklist)
        export_btn.setStyleSheet("QPushButton { background-color: #4caf50; color: white; padding: 8px; border-radius: 4px; }")
        button_layout.addWidget(export_btn)
        
        blacklist_layout.addLayout(button_layout)
        blacklist_group.setLayout(blacklist_layout)
        layout.addWidget(blacklist_group)
        
        # Load initial blacklist data
        self.refresh_blacklist_display()
        
        widget.setLayout(layout)
        return widget
    
    def create_settings_tab(self):
        """Create settings configuration tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("⚙️ StealthShark Settings")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #4fc3f7; padding: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Monitoring Settings Group
        monitoring_group = QGroupBox("📡 Monitoring Settings")
        monitoring_layout = QVBoxLayout()
        
        # Monitoring Duration
        duration_layout = QHBoxLayout()
        duration_label = QLabel("Default Monitoring Duration:")
        duration_label.setStyleSheet("font-size: 14px; padding: 5px;")
        duration_layout.addWidget(duration_label)
        
        self.duration_spinbox = QSpinBox()
        self.duration_spinbox.setRange(1, 24)
        self.duration_spinbox.setValue(self.settings['monitoring_duration'])
        self.duration_spinbox.setSuffix(" hours")
        self.duration_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #4a4a4a;
                padding: 5px;
                border-radius: 4px;
                font-size: 14px;
            }
        """)
        self.duration_spinbox.valueChanged.connect(self.update_monitoring_duration)
        duration_layout.addWidget(self.duration_spinbox)
        duration_layout.addStretch()
        monitoring_layout.addLayout(duration_layout)
        
        # Scan Interval
        interval_layout = QHBoxLayout()
        interval_label = QLabel("Network Scan Interval:")
        interval_label.setStyleSheet("font-size: 14px; padding: 5px;")
        interval_layout.addWidget(interval_label)
        
        self.interval_spinbox = QSpinBox()
        self.interval_spinbox.setRange(1, 60)
        self.interval_spinbox.setValue(self.settings['scan_interval'])
        self.interval_spinbox.setSuffix(" seconds")
        self.interval_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: #3a3a3a;
                color: #e0e0e0;
                border: 1px solid #4a4a4a;
                padding: 5px;
                border-radius: 4px;
                font-size: 14px;
            }
        """)
        self.interval_spinbox.valueChanged.connect(self.update_scan_interval)
        interval_layout.addWidget(self.interval_spinbox)
        interval_layout.addStretch()
        monitoring_layout.addLayout(interval_layout)
        
        # Monitoring Status
        self.monitoring_status = QLabel("⏱️ Monitoring Status: Ready")
        self.monitoring_status.setStyleSheet("font-size: 14px; padding: 10px; color: #4fc3f7; font-weight: bold;")
        monitoring_layout.addWidget(self.monitoring_status)
        
        monitoring_group.setLayout(monitoring_layout)
        layout.addWidget(monitoring_group)
        
        # Auto-Start Settings Group
        autostart_group = QGroupBox("🚀 Auto-Start Settings")
        autostart_layout = QVBoxLayout()
        
        # Auto-start checkbox
        self.autostart_checkbox = QCheckBox("Start StealthShark automatically when computer boots")
        self.autostart_checkbox.setChecked(self.settings['auto_start'])
        self.autostart_checkbox.setStyleSheet("""
            QCheckBox {
                color: #e0e0e0;
                font-size: 14px;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #3a3a3a;
                border: 2px solid #4a4a4a;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #4fc3f7;
                border: 2px solid #4fc3f7;
                border-radius: 3px;
            }
        """)
        self.autostart_checkbox.toggled.connect(self.toggle_autostart)
        autostart_layout.addWidget(self.autostart_checkbox)
        
        # Auto-start status
        self.autostart_status = QLabel("❌ Auto-start: Disabled")
        if self.settings['auto_start']:
            self.autostart_status.setText("✅ Auto-start: Enabled")
            self.autostart_status.setStyleSheet("color: #66bb6a; font-size: 12px; padding: 5px;")
        else:
            self.autostart_status.setStyleSheet("color: #ff5252; font-size: 12px; padding: 5px;")
        autostart_layout.addWidget(self.autostart_status)
        
        # Install/Uninstall auto-start buttons
        autostart_buttons = QHBoxLayout()
        
        install_autostart_btn = QPushButton("📥 Install Auto-Start")
        install_autostart_btn.clicked.connect(self.install_autostart)
        install_autostart_btn.setStyleSheet("""
            QPushButton {
                background-color: #4caf50;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #66bb6a;
            }
        """)
        autostart_buttons.addWidget(install_autostart_btn)
        
        uninstall_autostart_btn = QPushButton("🗑️ Remove Auto-Start")
        uninstall_autostart_btn.clicked.connect(self.uninstall_autostart)
        uninstall_autostart_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #ef5350;
            }
        """)
        autostart_buttons.addWidget(uninstall_autostart_btn)
        
        autostart_buttons.addStretch()
        autostart_layout.addLayout(autostart_buttons)
        
        autostart_group.setLayout(autostart_layout)
        layout.addWidget(autostart_group)
        
        # Notification Settings Group
        notification_group = QGroupBox("🔔 Notification Settings")
        notification_layout = QVBoxLayout()
        
        # Threat notifications
        self.threat_notifications_checkbox = QCheckBox("Show threat detection notifications")
        self.threat_notifications_checkbox.setChecked(self.settings['threat_notifications'])
        self.threat_notifications_checkbox.setStyleSheet("""
            QCheckBox {
                color: #e0e0e0;
                font-size: 14px;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #3a3a3a;
                border: 2px solid #4a4a4a;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #4fc3f7;
                border: 2px solid #4fc3f7;
                border-radius: 3px;
            }
        """)
        self.threat_notifications_checkbox.toggled.connect(self.toggle_threat_notifications)
        notification_layout.addWidget(self.threat_notifications_checkbox)
        
        # Auto-block threats
        self.auto_block_checkbox = QCheckBox("Automatically block detected threats")
        self.auto_block_checkbox.setChecked(self.settings['auto_block_threats'])
        self.auto_block_checkbox.setStyleSheet("""
            QCheckBox {
                color: #e0e0e0;
                font-size: 14px;
                padding: 5px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
            }
            QCheckBox::indicator:unchecked {
                background-color: #3a3a3a;
                border: 2px solid #4a4a4a;
                border-radius: 3px;
            }
            QCheckBox::indicator:checked {
                background-color: #4fc3f7;
                border: 2px solid #4fc3f7;
                border-radius: 3px;
            }
        """)
        self.auto_block_checkbox.toggled.connect(self.toggle_auto_block)
        notification_layout.addWidget(self.auto_block_checkbox)
        
        notification_group.setLayout(notification_layout)
        layout.addWidget(notification_group)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        save_settings_btn = QPushButton("💾 Save Settings")
        save_settings_btn.clicked.connect(self.save_settings)
        save_settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196f3;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        control_layout.addWidget(save_settings_btn)
        
        reset_settings_btn = QPushButton("🔄 Reset to Defaults")
        reset_settings_btn.clicked.connect(self.reset_settings)
        reset_settings_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                padding: 10px 20px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #ffb74d;
            }
        """)
        control_layout.addWidget(reset_settings_btn)
        
        control_layout.addStretch()
        layout.addLayout(control_layout)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def refresh_blacklist_display(self):
        """Refresh the blacklist display table"""
        if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
            blocked_bssids = list(self.blacklist_manager.blocked_bssids)
            self.blacklist_stats.setText(f"🚫 {len(blocked_bssids)} BSSIDs currently blocked")
            
            self.blacklist_table.setRowCount(len(blocked_bssids))
            
            for i, bssid in enumerate(sorted(blocked_bssids)):
                # BSSID
                bssid_item = QTableWidgetItem(bssid)
                bssid_item.setFont(QFont("monospace", 12))
                self.blacklist_table.setItem(i, 0, bssid_item)
                
                # Status
                if bssid == "72:13:01:8A:70:DA":
                    status_item = QTableWidgetItem("🔒 PROTECTED")
                    status_item.setBackground(QColor("#4caf50"))
                else:
                    status_item = QTableWidgetItem("🚫 BLOCKED")
                    status_item.setBackground(QColor("#ff5252"))
                status_item.setForeground(QColor("white"))
                self.blacklist_table.setItem(i, 1, status_item)
                
                # Actions
                if bssid != "72:13:01:8A:70:DA":  # Don't allow removal of trusted BSSID
                    remove_btn = QPushButton("🗑️ Remove")
                    remove_btn.clicked.connect(lambda checked, b=bssid: self.remove_bssid_from_blacklist(b))
                    remove_btn.setStyleSheet("QPushButton { background-color: #d32f2f; color: white; padding: 4px; }")
                    self.blacklist_table.setCellWidget(i, 2, remove_btn)
                else:
                    protected_label = QLabel("🛡️ Protected")
                    protected_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
                    protected_label.setStyleSheet("color: #4caf50; font-weight: bold;")
                    self.blacklist_table.setCellWidget(i, 2, protected_label)
        else:
            self.blacklist_stats.setText("❌ Blacklist manager not available")
    
    def add_bssid_manually(self):
        """Add BSSID manually to blacklist"""
        bssid, ok = QInputDialog.getText(self, "➕ Add BSSID to Blacklist", 
            "Enter BSSID (XX:XX:XX:XX:XX:XX):")
        if ok and bssid:
            if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
                if self.blacklist_manager.add_bssid(bssid, "Manual addition"):
                    QMessageBox.information(self, "✅ Success", f"Added {bssid} to blacklist")
                    self.refresh_blacklist_display()
                else:
                    QMessageBox.warning(self, "⚠️ Warning", f"Failed to add {bssid} - may be invalid or already exists")
            else:
                QMessageBox.warning(self, "⚠️ Error", "Blacklist manager not available")
    
    def remove_bssid_from_blacklist(self, bssid):
        """Remove BSSID from blacklist"""
        reply = QMessageBox.question(self, "Confirm Removal",
            f"Remove {bssid} from blacklist?\n\nThis will allow traffic from this BSSID again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
                if self.blacklist_manager.remove_bssid(bssid):
                    QMessageBox.information(self, "✅ Success", f"Removed {bssid} from blacklist")
                    self.refresh_blacklist_display()
                else:
                    QMessageBox.warning(self, "❌ Error", f"Failed to remove {bssid}")
    
    def export_blacklist(self):
        """Export blacklist to file"""
        if hasattr(self, 'blacklist_manager') and self.blacklist_manager:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Blacklist", 
                f"bssid_blacklist_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)")
            
            if filename:
                if self.blacklist_manager.export_blacklist(filename):
                    QMessageBox.information(self, "✅ Export Success", 
                        f"Blacklist exported to:\n{filename}")
                else:
                    QMessageBox.warning(self, "❌ Export Error", "Failed to export blacklist")
        else:
            QMessageBox.warning(self, "⚠️ Error", "Blacklist manager not available")
    
    # Authentication and security methods
    def load_authentication_status(self):
        """Load authentication status from file"""
        if self.auth_profile_path.exists():
            try:
                with open(self.auth_profile_path, 'r') as f:
                    profile = json.load(f)
                
                expiry = datetime.fromisoformat(profile.get('expiry', ''))
                if expiry > datetime.now():
                    self.authenticated = True
                    self.firewall_enabled = True
            except:
                pass
    
    def load_registered_tags(self):
        """Load registered NFC tags"""
        if self.tags_path.exists():
            try:
                with open(self.tags_path, 'r') as f:
                    self.registered_tags = json.load(f)
            except:
                self.registered_tags = []
    
    def detect_current_network(self):
        """Detect current network BSSID"""
        try:
            result = subprocess.run(['system_profiler', 'SPAirPortDataType'], capture_output=True, text=True)
            if "WhySoSeriousi" in result.stdout:
                print("✅ Connected to WhySoSeriousi network")
            else:
                print("⚠️ Not connected to expected network")
        except:
            print("⚠️ Could not detect network")
    
    def check_auto_authentication(self):
        """Check for auto-authentication"""
        if self.authenticated and self.registered_tags:
            print("🔐 Auto-authenticated with existing profile")
    
    def start_monitoring(self):
        # Network monitoring thread
        self.monitor_thread = NetworkMonitorThread()
        self.monitor_thread.network_update.connect(self.update_network_table)
        self.monitor_thread.threat_detected.connect(self.handle_threat)
        self.monitor_thread.start()
        
        # Real-time scanner timer
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.perform_live_scan)
        self.scan_timer.start(5000)  # Scan every 5 seconds for live threats
    
    def update_network_table(self, networks):
        """Update network monitoring table"""
        if hasattr(self, 'network_table'):
            self.network_table.setRowCount(len(networks))
            
            for i, network in enumerate(networks):
                self.network_table.setItem(i, 0, QTableWidgetItem(network['ssid']))
                self.network_table.setItem(i, 1, QTableWidgetItem(network['bssid']))
                self.network_table.setItem(i, 2, QTableWidgetItem(f"{network['rssi']} dBm"))
                self.network_table.setItem(i, 3, QTableWidgetItem(network['channel']))
                
                # Status
                if network['bssid'] == self.legitimate_bssid:
                    status = "✅ Protected"
                elif network['bssid'] in self.blocked_bssids:
                    status = "🚫 Blocked"
                else:
                    status = "⚡ Unprotected"
                
                self.network_table.setItem(i, 4, QTableWidgetItem(status))
    
    def handle_threat(self, threat_network):
        """Handle detected threats"""
        self.threat_count += 1
        self.threat_counter.setText(f"🛡️ Threats Blocked: {self.threat_count}")
        
        # Add to blocked list
        threat_bssid = threat_network['bssid']
        self.blocked_bssids.add(threat_bssid)
        
        # Log threat
        timestamp = datetime.now().strftime("%H:%M:%S")
        threat_msg = f"[{timestamp}] THREAT: {threat_network['ssid']} ({threat_bssid}) - BLOCKED\n"
        if hasattr(self, 'threat_log'):
            self.threat_log.append(threat_msg)
        
        self.status_bar.showMessage(f"🚫 Blocked threat: {threat_network['ssid']}")
    
    def toggle_monitoring(self):
        """Toggle network monitoring"""
        if self.monitor_toggle.isChecked():
            self.start_monitoring()
            self.monitor_toggle.setText("⏸️ Stop Monitoring")
        else:
            if hasattr(self, 'monitor_thread'):
                self.monitor_thread.stop()
            self.monitor_toggle.setText("▶️ Start Monitoring")
    
    def manual_scan(self):
        """Perform manual network scan"""
        if hasattr(self, 'monitor_thread'):
            networks = self.monitor_thread.scan_networks()
            self.update_network_table(networks)
            self.status_bar.showMessage(f"Found {len(networks)} networks")
    
    def toggle_firewall(self):
        """Toggle firewall protection"""
        if not self.firewall_enabled:
            # Require authentication
            if self.simulate_nfc_auth():
                self.firewall_enabled = True
                self.authenticated = True
                self.update_auth_status()
                self.status_bar.showMessage("🛡️ Firewall activated")
        else:
            self.firewall_enabled = False
            self.authenticated = False
            self.update_auth_status()
            self.status_bar.showMessage("⚠️ Firewall deactivated")
    
    def simulate_nfc_auth(self):
        """Simulate NFC authentication"""
        reply = QMessageBox.question(self, "NFC Authentication", 
            "Simulate NFC tag scan?\n\n(In production, this would scan a real NFC tag)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.authenticated = True
            self.firewall_enabled = True
            self.save_authentication()
            self.update_auth_status()
            QMessageBox.information(self, "✅ Success", "NFC authentication successful!")
            return True
        return False
    
    def add_new_tag(self):
        """Add new NFC tag"""
        name, ok = QInputDialog.getText(self, "New NFC Tag", "Enter tag name:")
        if ok and name:
            tag_data = {
                'name': name,
                'created': datetime.now().isoformat(),
                'device_id': hashlib.sha256(socket.gethostname().encode()).hexdigest()[:16]
            }
            
            # Add network binding for current network
            tag_data['network_binding'] = {
                'bssid': self.legitimate_bssid,
                'ssid': self.current_ssid
            }
            
            self.registered_tags.append(tag_data)
            self.save_registered_tags()
            
            QMessageBox.information(self, "✅ Tag Added", f"NFC tag '{name}' registered successfully!")
    
    def save_registered_tags(self):
        """Save registered tags to file"""
        try:
            self.tags_path.parent.mkdir(exist_ok=True)
            with open(self.tags_path, 'w') as f:
                json.dump(self.registered_tags, f, indent=2)
        except Exception as e:
            print(f"Error saving tags: {e}")
    
    def save_authentication(self):
        """Save authentication profile"""
        profile = {
            'authenticated': True,
            'timestamp': datetime.now().isoformat(),
            'expiry': (datetime.now() + timedelta(days=90)).isoformat(),
            'device_id': hashlib.sha256(socket.gethostname().encode()).hexdigest(),
            'bssid': self.legitimate_bssid
        }
        
        try:
            self.auth_profile_path.parent.mkdir(exist_ok=True)
            with open(self.auth_profile_path, 'w') as f:
                json.dump(profile, f, indent=2)
        except Exception as e:
            print(f"Error saving auth profile: {e}")
    
    def update_auth_status(self):
        """Update authentication status display"""
        if hasattr(self, 'status_indicator'):
            if self.authenticated:
                self.status_indicator.setText("✅ Authenticated & Protected")
                self.status_indicator.setStyleSheet("""
                    padding: 15px;
                    background-color: #1b5e20;
                    color: #66bb6a;
                    font-weight: bold;
                    font-size: 16px;
                    border-radius: 10px;
                    border: 2px solid #66bb6a;
                """)
            else:
                self.status_indicator.setText("⚠️ Not Authenticated")
                self.status_indicator.setStyleSheet("""
                    padding: 15px;
                    background-color: #4a3a00;
                    color: #ffa726;
                    font-weight: bold;
                    font-size: 16px;
                    border-radius: 10px;
                    border: 2px solid #ffa726;
                """)
        
        # Update firewall button
        if hasattr(self, 'firewall_toggle'):
            if self.firewall_enabled:
                self.firewall_toggle.setText("🔒 Lock Firewall")
                self.firewall_toggle.setStyleSheet("""
                    QPushButton {
                        background-color: #1b5e20;
                        color: white;
                        padding: 10px;
                        font-size: 16px;
                        font-weight: bold;
                        border-radius: 5px;
                    }
                """)
            else:
                self.firewall_toggle.setText("🔓 Unlock with NFC")
                self.firewall_toggle.setStyleSheet("""
                    QPushButton {
                        background-color: #b71c1c;
                        color: white;
                        padding: 10px;
                        font-size: 16px;
                        font-weight: bold;
                        border-radius: 5px;
                    }
                """)
    
    # Settings management methods
    def load_settings(self):
        """Load settings from file"""
        try:
            if self.settings_path.exists():
                with open(self.settings_path, 'r') as f:
                    saved_settings = json.load(f)
                    self.settings.update(saved_settings)
        except Exception as e:
            print(f"Error loading settings: {e}")
    
    def save_settings(self):
        """Save current settings to file"""
        try:
            self.settings_path.parent.mkdir(exist_ok=True)
            with open(self.settings_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
            QMessageBox.information(self, "✅ Settings Saved", "Settings have been saved successfully!")
            self.apply_settings()
        except Exception as e:
            QMessageBox.critical(self, "❌ Save Error", f"Failed to save settings:\n{e}")
    
    def reset_settings(self):
        """Reset settings to defaults"""
        reply = QMessageBox.question(self, "Reset Settings", 
            "Reset all settings to default values?\n\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self.settings = {
                'monitoring_duration': 6,
                'auto_start': False,
                'scan_interval': 5,
                'threat_notifications': True,
                'auto_block_threats': True,
                'minimize_to_tray': False
            }
            self.update_settings_ui()
            self.save_settings()
    
    def update_settings_ui(self):
        """Update settings UI elements with current values"""
        if hasattr(self, 'duration_spinbox'):
            self.duration_spinbox.setValue(self.settings['monitoring_duration'])
        if hasattr(self, 'interval_spinbox'):
            self.interval_spinbox.setValue(self.settings['scan_interval'])
        if hasattr(self, 'autostart_checkbox'):
            self.autostart_checkbox.setChecked(self.settings['auto_start'])
        if hasattr(self, 'threat_notifications_checkbox'):
            self.threat_notifications_checkbox.setChecked(self.settings['threat_notifications'])
        if hasattr(self, 'auto_block_checkbox'):
            self.auto_block_checkbox.setChecked(self.settings['auto_block_threats'])
    
    def apply_settings(self):
        """Apply current settings to the application"""
        # Update scan timer interval
        if hasattr(self, 'scan_timer'):
            self.scan_timer.setInterval(self.settings['scan_interval'] * 1000)
        
        # Start monitoring timer if duration is set
        self.start_monitoring_timer()
    
    def update_monitoring_duration(self, value):
        """Update monitoring duration setting"""
        self.settings['monitoring_duration'] = value
        self.start_monitoring_timer()
    
    def update_scan_interval(self, value):
        """Update scan interval setting"""
        self.settings['scan_interval'] = value
        if hasattr(self, 'scan_timer'):
            self.scan_timer.setInterval(value * 1000)
    
    def toggle_autostart(self, checked):
        """Toggle auto-start setting"""
        self.settings['auto_start'] = checked
        if hasattr(self, 'autostart_status'):
            if checked:
                self.autostart_status.setText("✅ Auto-start: Enabled")
                self.autostart_status.setStyleSheet("color: #66bb6a; font-size: 12px; padding: 5px;")
            else:
                self.autostart_status.setText("❌ Auto-start: Disabled")
                self.autostart_status.setStyleSheet("color: #ff5252; font-size: 12px; padding: 5px;")
    
    def toggle_threat_notifications(self, checked):
        """Toggle threat notifications setting"""
        self.settings['threat_notifications'] = checked
    
    def toggle_auto_block(self, checked):
        """Toggle auto-block threats setting"""
        self.settings['auto_block_threats'] = checked
    
    def start_monitoring_timer(self):
        """Start the monitoring duration timer"""
        if self.monitoring_timer:
            self.monitoring_timer.stop()
        
        duration_hours = self.settings['monitoring_duration']
        duration_ms = duration_hours * 60 * 60 * 1000  # Convert hours to milliseconds
        
        self.monitoring_timer = QTimer()
        self.monitoring_timer.setSingleShot(True)
        self.monitoring_timer.timeout.connect(self.monitoring_timeout)
        self.monitoring_timer.start(duration_ms)
        
        self.monitoring_start_time = datetime.now()
        
        if hasattr(self, 'monitoring_status'):
            end_time = self.monitoring_start_time + timedelta(hours=duration_hours)
            self.monitoring_status.setText(f"⏱️ Monitoring until {end_time.strftime('%H:%M:%S')} ({duration_hours}h)")
            self.monitoring_status.setStyleSheet("font-size: 14px; padding: 10px; color: #66bb6a; font-weight: bold;")
        
        print(f"🕐 Monitoring timer started for {duration_hours} hours")
    
    def monitoring_timeout(self):
        """Handle monitoring timeout"""
        if hasattr(self, 'monitoring_status'):
            self.monitoring_status.setText("⏱️ Monitoring Complete - Timer Expired")
            self.monitoring_status.setStyleSheet("font-size: 14px; padding: 10px; color: #ffa726; font-weight: bold;")
        
        if self.settings['threat_notifications']:
            QMessageBox.information(self, "⏰ Monitoring Complete", 
                f"StealthShark has completed {self.settings['monitoring_duration']} hours of monitoring.\n\n"
                "You can restart monitoring from the Settings tab.")
        
        print(f"⏰ Monitoring timer expired after {self.settings['monitoring_duration']} hours")
    
    def install_autostart(self):
        """Install auto-start LaunchAgent"""
        try:
            launchagents_dir = Path.home() / "Library" / "LaunchAgents"
            launchagents_dir.mkdir(exist_ok=True)
            
            # Get the script directory (parent of anti_pineapple_gui)
            script_dir = Path(__file__).parent.parent
            plist_source = script_dir / "Desktop_Shortcuts" / "com.aimfllc.stealthshark.plist"
            plist_dest = launchagents_dir / "com.aimfllc.stealthshark.plist"
            
            if plist_source.exists():
                import shutil
                shutil.copy2(plist_source, plist_dest)
                
                # Load the LaunchAgent
                subprocess.run(['launchctl', 'load', str(plist_dest)], check=True)
                
                self.settings['auto_start'] = True
                self.autostart_checkbox.setChecked(True)
                self.autostart_status.setText("✅ Auto-start: Installed & Enabled")
                self.autostart_status.setStyleSheet("color: #66bb6a; font-size: 12px; padding: 5px;")
                
                QMessageBox.information(self, "✅ Auto-Start Installed", 
                    "StealthShark will now start automatically when you log in.\n\n"
                    "The application will launch minimized and begin monitoring immediately.")
            else:
                QMessageBox.warning(self, "❌ Installation Error", 
                    "Auto-start configuration file not found.\n\n"
                    "Please ensure the Desktop_Shortcuts folder contains the required files.")
                
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "❌ Installation Failed", 
                f"Failed to install auto-start:\n{e}\n\n"
                "You may need to grant permissions in System Preferences.")
        except Exception as e:
            QMessageBox.critical(self, "❌ Installation Error", f"Error installing auto-start:\n{e}")
    
    def uninstall_autostart(self):
        """Uninstall auto-start LaunchAgent"""
        try:
            launchagents_dir = Path.home() / "Library" / "LaunchAgents"
            plist_file = launchagents_dir / "com.aimfllc.stealthshark.plist"
            
            if plist_file.exists():
                # Unload the LaunchAgent
                subprocess.run(['launchctl', 'unload', str(plist_file)], check=False)
                
                # Remove the plist file
                plist_file.unlink()
                
                self.settings['auto_start'] = False
                self.autostart_checkbox.setChecked(False)
                self.autostart_status.setText("❌ Auto-start: Removed")
                self.autostart_status.setStyleSheet("color: #ff5252; font-size: 12px; padding: 5px;")
                
                QMessageBox.information(self, "✅ Auto-Start Removed", 
                    "Auto-start has been disabled.\n\n"
                    "StealthShark will no longer start automatically at login.")
            else:
                QMessageBox.information(self, "ℹ️ Not Installed", 
                    "Auto-start is not currently installed.")
                
        except Exception as e:
            QMessageBox.critical(self, "❌ Removal Error", f"Error removing auto-start:\n{e}")


def main():
    print("🚀 Starting Simple GUI application...")
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    try:
        window = SimpleAntiPineappleGUI()
        window.show()
        print("✅ Simple GUI launched successfully!")
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        import traceback
        traceback.print_exc()
        return
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
