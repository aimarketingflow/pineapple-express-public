#!/usr/bin/env python3
"""
Anti-Pineapple + Hotspot Blocker - Enhanced Security System
Combines WiFi Pineapple detection with iPhone hotspot blocking
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Import the hotspot blocker module
from hotspot_blocker_module import HotspotBlockerThread

# Import the original Anti-Pineapple GUI
from anti_pineapple_gui import *


class HotspotBlockerTab(QWidget):
    """Tab for iPhone Hotspot Blocker functionality"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.blocker_thread = HotspotBlockerThread()
        self.blocker_thread.hotspot_detected.connect(self.on_hotspot_detected)
        self.blocker_thread.hotspot_blocked.connect(self.on_hotspot_blocked)
        self.blocker_thread.status_update.connect(self.on_status_update)
        self.init_ui()
        
    def init_ui(self):
        """Initialize the hotspot blocker UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("📱 iPhone Hotspot Blocker")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ff9800; padding: 10px;")
        layout.addWidget(title)
        
        # Description
        desc = QLabel(
            "Automatically detects and blocks iPhone hotspot connections.\n"
            "Protects against accidental connections to mobile hotspots."
        )
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setStyleSheet("color: #a0a0a0; padding: 10px;")
        layout.addWidget(desc)
        
        # Control Panel
        control_group = QGroupBox("🎛️ Control Panel")
        control_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                border: 2px solid #ff9800;
                border-radius: 10px;
                margin-top: 10px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #ff9800;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
        """)
        control_layout = QVBoxLayout()
        
        # Enable/Disable button
        self.toggle_button = QPushButton("🚀 Start Hotspot Blocker")
        self.toggle_button.clicked.connect(self.toggle_blocker)
        self.toggle_button.setStyleSheet("""
            QPushButton {
                background-color: #1b5e20;
                color: #a5d6a7;
                padding: 15px;
                font-size: 16px;
                font-weight: bold;
                border-radius: 8px;
            }
            QPushButton:hover { background-color: #2e7d32; }
        """)
        control_layout.addWidget(self.toggle_button)
        
        # Status indicator
        status_layout = QHBoxLayout()
        status_label = QLabel("Status:")
        status_label.setStyleSheet("color: #a0a0a0; font-size: 14px;")
        self.status_indicator = QLabel("⚪ Inactive")
        self.status_indicator.setStyleSheet("color: #757575; font-size: 14px; font-weight: bold;")
        status_layout.addWidget(status_label)
        status_layout.addWidget(self.status_indicator)
        status_layout.addStretch()
        control_layout.addLayout(status_layout)
        
        control_group.setLayout(control_layout)
        layout.addWidget(control_group)
        
        # Pattern Management
        pattern_group = QGroupBox("🔍 Detection Patterns")
        pattern_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                border: 2px solid #2196f3;
                border-radius: 10px;
                margin-top: 10px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #2196f3;
            }
        """)
        pattern_layout = QVBoxLayout()
        
        # Pattern list
        self.pattern_list = QListWidget()
        self.pattern_list.setStyleSheet("""
            QListWidget {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        for pattern in self.blocker_thread.iphone_patterns:
            self.pattern_list.addItem(pattern)
        pattern_layout.addWidget(self.pattern_list)
        
        # Add pattern controls
        add_pattern_layout = QHBoxLayout()
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("Enter regex pattern (e.g., .*MyPhone.*)")
        self.pattern_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #555;
                border-radius: 5px;
                padding: 8px;
            }
        """)
        add_pattern_layout.addWidget(self.pattern_input)
        
        add_button = QPushButton("➕ Add")
        add_button.clicked.connect(self.add_pattern)
        add_button.setStyleSheet("""
            QPushButton {
                background-color: #1976d2;
                color: white;
                padding: 8px 15px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #2196f3; }
        """)
        add_pattern_layout.addWidget(add_button)
        
        remove_button = QPushButton("➖ Remove")
        remove_button.clicked.connect(self.remove_pattern)
        remove_button.setStyleSheet("""
            QPushButton {
                background-color: #c62828;
                color: white;
                padding: 8px 15px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #d32f2f; }
        """)
        add_pattern_layout.addWidget(remove_button)
        
        pattern_layout.addLayout(add_pattern_layout)
        pattern_group.setLayout(pattern_layout)
        layout.addWidget(pattern_group)
        
        # Activity Log
        log_group = QGroupBox("📋 Activity Log")
        log_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                border: 2px solid #4caf50;
                border-radius: 10px;
                margin-top: 10px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #4caf50;
            }
        """)
        log_layout = QVBoxLayout()
        
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                border: 1px solid #555;
                border-radius: 5px;
                padding: 10px;
                font-family: 'Courier New', monospace;
            }
        """)
        log_layout.addWidget(self.log_display)
        
        # Clear log button
        clear_button = QPushButton("🗑️ Clear Log")
        clear_button.clicked.connect(self.log_display.clear)
        clear_button.setStyleSheet("""
            QPushButton {
                background-color: #424242;
                color: #a0a0a0;
                padding: 8px;
                border-radius: 5px;
            }
            QPushButton:hover { background-color: #616161; }
        """)
        log_layout.addWidget(clear_button)
        
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)
        
        # Statistics
        stats_group = QGroupBox("📊 Statistics")
        stats_group.setStyleSheet("""
            QGroupBox {
                background-color: #2b2b2b;
                border: 2px solid #9c27b0;
                border-radius: 10px;
                margin-top: 10px;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                color: #9c27b0;
            }
        """)
        stats_layout = QHBoxLayout()
        
        self.blocked_count_label = QLabel("🚫 Blocked: 0")
        self.blocked_count_label.setStyleSheet("color: #ff5252; font-size: 16px; font-weight: bold;")
        stats_layout.addWidget(self.blocked_count_label)
        
        self.detected_count_label = QLabel("⚠️ Detected: 0")
        self.detected_count_label.setStyleSheet("color: #ffa726; font-size: 16px; font-weight: bold;")
        stats_layout.addWidget(self.detected_count_label)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        self.setLayout(layout)
        
        # Start the thread (but not enabled)
        self.blocker_thread.start()
        
    def toggle_blocker(self):
        """Toggle hotspot blocker on/off"""
        if self.blocker_thread.enabled:
            # Disable
            self.blocker_thread.enabled = False
            self.toggle_button.setText("🚀 Start Hotspot Blocker")
            self.toggle_button.setStyleSheet("""
                QPushButton {
                    background-color: #1b5e20;
                    color: #a5d6a7;
                    padding: 15px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 8px;
                }
                QPushButton:hover { background-color: #2e7d32; }
            """)
            self.status_indicator.setText("⚪ Inactive")
            self.status_indicator.setStyleSheet("color: #757575; font-size: 14px; font-weight: bold;")
            self.log_message("🛑 Hotspot blocker stopped")
        else:
            # Enable
            self.blocker_thread.enabled = True
            self.toggle_button.setText("⏹️ Stop Hotspot Blocker")
            self.toggle_button.setStyleSheet("""
                QPushButton {
                    background-color: #c62828;
                    color: white;
                    padding: 15px;
                    font-size: 16px;
                    font-weight: bold;
                    border-radius: 8px;
                }
                QPushButton:hover { background-color: #d32f2f; }
            """)
            self.status_indicator.setText("🟢 Active")
            self.status_indicator.setStyleSheet("color: #4caf50; font-size: 14px; font-weight: bold;")
            self.log_message("✅ Hotspot blocker started")
    
    def add_pattern(self):
        """Add new detection pattern"""
        pattern = self.pattern_input.text().strip()
        if pattern:
            self.blocker_thread.add_pattern(pattern)
            self.pattern_list.addItem(pattern)
            self.pattern_input.clear()
            self.log_message(f"➕ Added pattern: {pattern}")
    
    def remove_pattern(self):
        """Remove selected pattern"""
        current_item = self.pattern_list.currentItem()
        if current_item:
            pattern = current_item.text()
            self.blocker_thread.remove_pattern(pattern)
            self.pattern_list.takeItem(self.pattern_list.currentRow())
            self.log_message(f"➖ Removed pattern: {pattern}")
    
    def on_hotspot_detected(self, ssid):
        """Handle hotspot detection"""
        self.log_message(f"⚠️ DETECTED: iPhone hotspot '{ssid}'")
        current = int(self.detected_count_label.text().split(": ")[1])
        self.detected_count_label.setText(f"⚠️ Detected: {current + 1}")
    
    def on_hotspot_blocked(self, ssid):
        """Handle hotspot blocking"""
        self.log_message(f"🚫 BLOCKED: '{ssid}' - Disconnected from network")
        current = int(self.blocked_count_label.text().split(": ")[1])
        self.blocked_count_label.setText(f"🚫 Blocked: {current + 1}")
    
    def on_status_update(self, message):
        """Handle status updates"""
        self.log_message(f"ℹ️ {message}")
    
    def log_message(self, message):
        """Add message to log"""
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")
        # Auto-scroll to bottom
        cursor = self.log_display.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.log_display.setTextCursor(cursor)


class EnhancedAntiPineappleGUI(AntiPineappleGUI):
    """Enhanced Anti-Pineapple GUI with Hotspot Blocker"""
    
    def __init__(self):
        super().__init__()
        self.add_hotspot_blocker_tab()
    
    def add_hotspot_blocker_tab(self):
        """Add the Hotspot Blocker tab"""
        hotspot_tab = HotspotBlockerTab(self)
        self.tab_widget.addTab(hotspot_tab, "📱 Hotspot Blocker")
        print("✅ Hotspot Blocker tab added")


def main():
    """Main entry point"""
    print("🚀 Starting Enhanced Anti-Pineapple + Hotspot Blocker...")
    
    app = QApplication(sys.argv)
    app.setApplicationName("Anti-Pineapple + Hotspot Blocker")
    
    window = EnhancedAntiPineappleGUI()
    window.show()
    
    print("✅ Enhanced GUI ready!")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
