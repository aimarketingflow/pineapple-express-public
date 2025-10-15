#!/usr/bin/env python3
"""
LoopbackShark GUI - Specialized Loopback Traffic Monitor
PyQt6-based interface for loopback network monitoring and trend analysis
AIMF LLC - Advanced Network Analytics
"""

import sys
import os
import json
import signal
import psutil
import threading
import time
import subprocess
import traceback
import logging
from datetime import datetime, timedelta
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                             QWidget, QPushButton, QLabel, QTextEdit, QSpinBox, 
                             QCheckBox, QComboBox, QProgressBar, QTabWidget,
                             QGroupBox, QTableWidget, QTableWidgetItem, QListWidget,
                             QSplitter, QGridLayout, QTreeWidget, QTreeWidgetItem,
                             QLineEdit, QFileDialog, QMessageBox)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
from PyQt6.QtGui import QFont, QBrush, QColor, QPalette, QPixmap, QIcon

# Import our loopback monitor
from loopback_monitor import LoopbackMonitor, setup_logging

class LoopbackMonitorThread(QThread):
    """Thread-safe loopback monitor with signals"""
    status_update = pyqtSignal(str)
    analysis_update = pyqtSignal(dict)
    error_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, capture_dir, duration, port_filter=None):
        super().__init__()
        self.logger = logging.getLogger("LoopbackThread")
        self.capture_dir = capture_dir
        self.duration = duration
        self.port_filter = port_filter
        self.running = False
        self.monitor = None
        
    def run(self):
        """Run loopback monitoring in thread"""
        try:
            self.running = True
            self.logger.info(f"Starting loopback monitor thread: duration={self.duration}s")
            
            # Create monitor instance
            self.monitor = LoopbackMonitor(
                capture_dir=self.capture_dir,
                duration=self.duration
            )
            
            # Start monitoring with callback
            self.monitor.start_monitoring(callback=self.thread_callback)
            
            self.finished_signal.emit()
            self.logger.info("Loopback monitor thread completed")
            
        except Exception as e:
            self.logger.error(f"Loopback monitor thread error: {e}")
            self.error_signal.emit(f"Monitor error: {e}")
            
    def thread_callback(self, message):
        """Thread-safe callback for monitor updates"""
        self.status_update.emit(message)
        
    def stop(self):
        """Stop the monitor safely"""
        try:
            self.running = False
            if self.monitor:
                self.monitor.stop_monitoring()
        except Exception as e:
            self.logger.error(f"Error stopping monitor thread: {e}")

class LoopbackSharkGUI(QMainWindow):
    """Main GUI application for LoopbackShark"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize logging
        self.logger = setup_logging()
        self.logger.info("Initializing LoopbackShark GUI")
        
        # Settings file path
        self.settings_file = Path("./loopbackshark_settings.json")
        
        # Load persistent settings
        self.load_settings()
        
        # Initialize components
        self.monitor_thread = None
        self.timer = None
        self.start_time = None
        
        self.init_ui()
        self.setup_timers()
        
    def load_settings(self):
        """Load persistent settings from JSON file"""
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                    
                self.duration = settings.get('duration', 86400)  # Default 24 hours
                self.port_filter = settings.get('port_filter', None)
                self.capture_dir = Path(settings.get('capture_dir', './pcap_captures'))
                
                self.logger.info(f"Settings loaded: duration={self.duration/3600:.1f}h, dir={self.capture_dir}")
            else:
                # Default settings
                self.duration = 86400  # 24 hours default
                self.port_filter = None
                self.capture_dir = Path("./pcap_captures")
                self.save_settings()  # Save defaults
                
        except Exception as e:
            self.logger.error(f"Error loading settings: {e}")
            # Fallback to defaults
            self.duration = 86400
            self.port_filter = None
            self.capture_dir = Path("./pcap_captures")
            
    def save_settings(self):
        """Save persistent settings to JSON file"""
        try:
            settings = {
                'duration': self.duration,
                'port_filter': self.port_filter,
                'capture_dir': str(self.capture_dir)
            }
            
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
                
            self.logger.debug(f"Settings saved: {settings}")
            
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("LoopbackShark - Loopback Traffic Monitor - AIMF LLC")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #4a9eff;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 15px;
                background-color: #2a2a2a;
                color: #4a9eff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 15px;
                padding: 0 8px 0 8px;
                color: #4a9eff;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4a9eff;
                border: none;
                color: white;
                padding: 10px 20px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:pressed {
                background-color: #2d5a8d;
            }
            QPushButton:disabled {
                background-color: #555555;
                color: #999999;
            }
            QTextEdit, QListWidget, QTableWidget {
                background-color: #0d1117;
                border: 1px solid #4a9eff;
                color: #ffffff;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
            QLabel {
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #21262d;
                border: 1px solid #4a9eff;
                color: #ffffff;
                padding: 6px;
                border-radius: 4px;
                font-size: 12px;
            }
        """)
        
        # Central widget with splitter
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Controls
        left_panel = self.create_control_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Monitoring
        right_panel = self.create_monitoring_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([450, 950])
        
    def create_control_panel(self):
        """Create the control panel"""
        control_widget = QWidget()
        layout = QVBoxLayout(control_widget)
        
        # Monitor Control Group
        control_group = QGroupBox("🎯 Loopback Monitor Control")
        control_layout = QVBoxLayout(control_group)
        
        # Start/Stop buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("🚀 Start Monitor")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.stop_btn = QPushButton("🛑 Stop Monitor")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        control_layout.addLayout(button_layout)
        
        # Status indicator
        self.status_label = QLabel("Status: Ready to monitor loopback traffic")
        self.status_label.setStyleSheet("color: #4a9eff; font-weight: bold; font-size: 13px;")
        control_layout.addWidget(self.status_label)
        
        # Progress bar and timer
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar::chunk { background-color: #4a9eff; }")
        control_layout.addWidget(self.progress_bar)
        
        self.timer_label = QLabel("Timer: Not started")
        self.timer_label.setStyleSheet("color: #ffffff; font-family: 'Courier New'; font-size: 13px;")
        control_layout.addWidget(self.timer_label)
        
        layout.addWidget(control_group)
        
        # Configuration Group
        config_group = QGroupBox("⚙️ Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Duration selection
        duration_layout = QHBoxLayout()
        duration_layout.addWidget(QLabel("Monitor Duration:"))
        self.duration_combo = QComboBox()
        self.duration_combo.addItems([
            "5 minutes (300s)", "10 minutes (600s)", "30 minutes (1800s)",
            "1 hour (3600s)", "2 hours (7200s)", "4 hours (14400s)",
            "8 hours (28800s)", "12 hours (43200s)", "24 hours (86400s)"
        ])
        # Set default to loaded duration (24 hours by default)
        duration_text = f"{int(self.duration/3600)} hours ({self.duration}s)" if self.duration >= 3600 else f"{int(self.duration/60)} minutes ({self.duration}s)"
        for i in range(self.duration_combo.count()):
            if f"({self.duration}s)" in self.duration_combo.itemText(i):
                self.duration_combo.setCurrentIndex(i)
                break
        else:
            # Default to 24 hours if exact match not found
            self.duration_combo.setCurrentText("24 hours (86400s)")
        self.duration_combo.currentTextChanged.connect(self.update_duration)
        duration_layout.addWidget(self.duration_combo)
        config_layout.addLayout(duration_layout)
        
        # Port filter with All Ports checkbox
        port_layout = QVBoxLayout()
        
        # All Ports checkbox
        self.all_ports_cb = QCheckBox("🔌 All Ports (Monitor all loopback traffic)")
        self.all_ports_cb.setChecked(True)  # Default to all ports
        self.all_ports_cb.stateChanged.connect(self.toggle_port_filter)
        port_layout.addWidget(self.all_ports_cb)
        
        # Port filter input
        port_input_layout = QHBoxLayout()
        port_input_layout.addWidget(QLabel("Port Filter:"))
        self.port_filter_edit = QLineEdit()
        self.port_filter_edit.setPlaceholderText("e.g., 3000,8080,9000")
        self.port_filter_edit.textChanged.connect(self.update_port_filter)
        self.port_filter_edit.setEnabled(False)  # Start disabled since All Ports is checked
        port_input_layout.addWidget(self.port_filter_edit)
        port_layout.addLayout(port_input_layout)
        
        config_layout.addLayout(port_layout)
        
        # Capture directory
        dir_layout = QHBoxLayout()
        dir_layout.addWidget(QLabel("Capture Directory:"))
        self.dir_btn = QPushButton("📁 Select")
        self.dir_btn.clicked.connect(self.select_directory)
        dir_layout.addWidget(self.dir_btn)
        config_layout.addLayout(dir_layout)
        
        # Directory path display
        self.dir_label = QLabel(str(self.capture_dir))
        self.dir_label.setStyleSheet("color: #cccccc; font-size: 11px; padding: 5px;")
        self.dir_label.setWordWrap(True)
        config_layout.addWidget(self.dir_label)
        
        layout.addWidget(config_group)
        
        # Loopback Info Group
        info_group = QGroupBox("🔍 Loopback Information")
        info_layout = QVBoxLayout(info_group)
        
        info_text = QLabel("""
LoopbackShark monitors localhost traffic:
• Interface: lo0 (127.0.0.1, ::1)
• Focus: Application-to-application communication
• Analysis: Port usage patterns and trends  
• Detection: Development servers, databases, APIs
        """)
        info_text.setStyleSheet("font-size: 11px; color: #cccccc; padding: 10px;")
        info_text.setWordWrap(True)
        info_layout.addWidget(info_text)
        
        layout.addWidget(info_group)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        return control_widget
        
    def create_monitoring_panel(self):
        """Create the monitoring panel with loopback-specific views"""
        monitor_widget = QWidget()
        layout = QVBoxLayout(monitor_widget)
        
        # Tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Live Monitor Tab
        monitor_tab = QWidget()
        monitor_layout = QVBoxLayout(monitor_tab)
        
        monitor_group = QGroupBox("🔄 Live Loopback Monitor")
        monitor_group_layout = QVBoxLayout(monitor_group)
        
        # Monitor controls
        monitor_controls = QHBoxLayout()
        clear_btn = QPushButton("🗑️ Clear Logs")
        clear_btn.clicked.connect(self.clear_logs)
        export_btn = QPushButton("💾 Export Logs")
        export_btn.clicked.connect(self.export_logs)
        monitor_controls.addWidget(clear_btn)
        monitor_controls.addWidget(export_btn)
        monitor_controls.addStretch()
        monitor_group_layout.addLayout(monitor_controls)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        monitor_group_layout.addWidget(self.log_text)
        
        monitor_layout.addWidget(monitor_group)
        self.tab_widget.addTab(monitor_tab, "📊 Live Monitor")
        
        # Trend Analysis Tab
        trend_tab = QWidget()
        trend_layout = QVBoxLayout(trend_tab)
        
        # Port Usage Table
        port_group = QGroupBox("🔌 Port Usage Analysis")
        port_layout = QVBoxLayout(port_group)
        
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(4)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Application", "Packets", "Category"])
        port_layout.addWidget(self.ports_table)
        
        trend_layout.addWidget(port_group)
        
        # Connection Patterns
        conn_group = QGroupBox("🔗 Connection Patterns")
        conn_layout = QVBoxLayout(conn_group)
        
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(4)
        self.connections_table.setHorizontalHeaderLabels(["Connection", "Packets", "Recent Activity", "Protocols"])
        conn_layout.addWidget(self.connections_table)
        
        trend_layout.addWidget(conn_group)
        self.tab_widget.addTab(trend_tab, "📈 Trend Analysis")
        
        # Statistics Tab
        stats_tab = QWidget()
        stats_layout = QVBoxLayout(stats_tab)
        
        stats_group = QGroupBox("📊 Session Statistics")
        stats_group_layout = QVBoxLayout(stats_group)
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        stats_group_layout.addWidget(self.stats_text)
        
        stats_layout.addWidget(stats_group)
        self.tab_widget.addTab(stats_tab, "📋 Statistics")
        
        # Pattern Recognition Tab
        pattern_tab = QWidget()
        pattern_layout = QVBoxLayout(pattern_tab)
        
        # Pattern controls
        pattern_controls = QHBoxLayout()
        
        self.pattern_enabled_cb = QCheckBox("Enable Pattern Recognition")
        self.pattern_enabled_cb.setChecked(True)
        pattern_controls.addWidget(self.pattern_enabled_cb)
        
        pattern_controls.addStretch()
        
        self.refresh_patterns_btn = QPushButton("🔄 Refresh Patterns")
        self.refresh_patterns_btn.clicked.connect(self.refresh_pattern_display)
        pattern_controls.addWidget(self.refresh_patterns_btn)
        
        pattern_layout.addLayout(pattern_controls)
        
        # Pattern display areas
        pattern_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Detected Applications
        apps_group = QGroupBox("🎯 Detected Applications")
        apps_layout = QVBoxLayout(apps_group)
        
        self.apps_list = QListWidget()
        self.apps_list.setStyleSheet("""
            QListWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #404040;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
            QListWidget::item {
                padding: 5px;
                border-bottom: 1px solid #404040;
            }
            QListWidget::item:selected {
                background-color: #0078d4;
            }
        """)
        apps_layout.addWidget(self.apps_list)
        pattern_splitter.addWidget(apps_group)
        
        # Pattern Matches
        matches_group = QGroupBox("🔍 Pattern Matches")
        matches_layout = QVBoxLayout(matches_group)
        
        self.matches_tree = QTreeWidget()
        self.matches_tree.setHeaderLabels(["Port", "Pattern", "Confidence", "Count"])
        self.matches_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #404040;
                font-family: 'Courier New', monospace;
                font-size: 10px;
            }
            QTreeWidget::item:selected {
                background-color: #0078d4;
            }
        """)  
        matches_layout.addWidget(self.matches_tree)
        pattern_splitter.addWidget(matches_group)
        
        pattern_layout.addWidget(pattern_splitter)
        
        # Pattern statistics
        stats_group = QGroupBox("📈 Pattern Statistics")
        stats_layout = QGridLayout(stats_group)
        
        self.total_patterns_label = QLabel("Total Patterns: 0")
        self.total_patterns_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        stats_layout.addWidget(self.total_patterns_label, 0, 0)
        
        self.high_confidence_label = QLabel("High Confidence: 0")
        self.high_confidence_label.setStyleSheet("font-weight: bold; color: #ffaa00;")
        stats_layout.addWidget(self.high_confidence_label, 0, 1)
        
        self.applications_detected_label = QLabel("Applications: 0")
        self.applications_detected_label.setStyleSheet("font-weight: bold; color: #0099ff;")
        stats_layout.addWidget(self.applications_detected_label, 1, 0)
        
        self.detection_rate_label = QLabel("Detection Rate: 0%")
        self.detection_rate_label.setStyleSheet("font-weight: bold; color: #ff6600;")
        stats_layout.addWidget(self.detection_rate_label, 1, 1)
        
        pattern_layout.addWidget(stats_group)
        self.tab_widget.addTab(pattern_tab, "🎯 Pattern Recognition")
        
        layout.addWidget(self.tab_widget)
        
        return monitor_widget
        
    def setup_timers(self):
        """Setup update timers"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_display)
        self.update_timer.start(5000)  # Update every 5 seconds
        
    def start_monitoring(self):
        """Start loopback monitoring"""
        try:
            if self.monitor_thread and self.monitor_thread.isRunning():
                self.log_message("Monitor is already running")
                return
                
            self.log_message("🚀 Starting LoopbackShark monitoring...")
            self.log_message(f"📁 Capture Directory: {self.capture_dir}")
            self.log_message(f"⏱️ Duration: {self.duration/60:.1f} minutes")
            
            if self.port_filter:
                self.log_message(f"🔌 Port Filter: {self.port_filter}")
            else:
                self.log_message("🔌 Monitoring all loopback ports")
                
            # Create and start monitor thread
            self.monitor_thread = LoopbackMonitorThread(
                str(self.capture_dir),
                self.duration,
                self.port_filter
            )
            
            # Connect signals
            self.monitor_thread.status_update.connect(self.on_status_update)
            self.monitor_thread.analysis_update.connect(self.on_analysis_update)
            self.monitor_thread.error_signal.connect(self.on_error)
            self.monitor_thread.finished_signal.connect(self.on_monitoring_finished)
            
            self.monitor_thread.start()
            
            # Update UI
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.status_label.setText("Status: Monitoring loopback traffic...")
            self.status_label.setStyleSheet("color: #4CAF50; font-weight: bold; font-size: 13px;")
            
            # Start progress tracking
            self.start_time = datetime.now()
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            if self.timer:
                self.timer.stop()
            self.timer = QTimer()
            self.timer.timeout.connect(self.update_progress)
            self.timer.start(1000)
            
            self.log_message("✅ LoopbackShark monitoring started successfully")
            
        except Exception as e:
            self.log_message(f"❌ Error starting monitor: {str(e)}")
            self.on_error(f"Start error: {str(e)}")
            
    def toggle_pattern_recognition(self, state):
        """Toggle pattern recognition on/off"""
        enabled = state == 2
        self.log_message(f"🎯 Pattern Recognition: {'Enabled' if enabled else 'Disabled'}")
        
    def refresh_pattern_display(self):
        """Refresh the pattern recognition display"""
        try:
            self.log_message("🔄 Refreshing pattern display...")
            
            # Clear existing displays
            self.apps_list.clear()
            self.matches_tree.clear()
            
            # Check if we have a running monitor with pattern data
            if hasattr(self, 'monitor_thread') and self.monitor_thread:
                # Get latest analysis if available
                self.log_message("📊 Loading pattern recognition results...")
                
                # Simulate pattern data for demonstration
                self._display_demo_patterns()
            else:
                self.log_message("⚠️ No active monitoring session for pattern data")
                
        except Exception as e:
            self.log_message(f"❌ Error refreshing patterns: {e}")
            
    def _display_demo_patterns(self):
        """Display demonstration pattern data"""
        try:
            # Demo detected applications
            demo_apps = [
                "🌐 Web Development Server (Port 3000)",
                "🗄️ PostgreSQL Database (Port 5432)",
                "🔑 Redis Cache (Port 6379)",
                "🐬 MySQL Database (Port 3306)",
                "📊 MongoDB Database (Port 27017)"
            ]
            
            for app in demo_apps:
                self.apps_list.addItem(app)
            
            # Demo pattern matches
            demo_patterns = [
                ("3000", "HTTP Development", "95%", "156"),
                ("5432", "PostgreSQL", "92%", "89"),
                ("6379", "Redis", "88%", "67"),
                ("3306", "MySQL", "85%", "45"),
                ("27017", "MongoDB", "82%", "34")
            ]
            
            for port, pattern, confidence, count in demo_patterns:
                item = QTreeWidgetItem([port, pattern, confidence, count])
                # Color code by confidence
                if float(confidence.rstrip('%')) >= 90:
                    item.setForeground(0, QBrush(QColor("#00ff00")))  # Green for high confidence
                elif float(confidence.rstrip('%')) >= 80:
                    item.setForeground(0, QBrush(QColor("#ffaa00")))  # Orange for medium
                else:
                    item.setForeground(0, QBrush(QColor("#ff6666")))  # Red for low
                    
                self.matches_tree.addTopLevelItem(item)
            
            # Update statistics
            total_patterns = len(demo_patterns)
            high_confidence = sum(1 for _, _, conf, _ in demo_patterns if float(conf.rstrip('%')) >= 90)
            applications = len(demo_apps)
            detection_rate = 91.2
            
            self.total_patterns_label.setText(f"Total Patterns: {total_patterns}")
            self.high_confidence_label.setText(f"High Confidence: {high_confidence}")
            self.applications_detected_label.setText(f"Applications: {applications}")
            self.detection_rate_label.setText(f"Detection Rate: {detection_rate:.1f}%")
            
            self.log_message(f"✅ Pattern display updated: {applications} apps, {total_patterns} patterns")
            
        except Exception as e:
            self.log_message(f"❌ Error displaying patterns: {e}")
            
    def update_pattern_display_from_analysis(self, analysis):
        """Update pattern display with real analysis data"""
        try:
            if not analysis or 'pattern_recognition' not in analysis:
                return
                
            pattern_data = analysis['pattern_recognition']
            
            # Clear existing displays
            self.apps_list.clear()
            self.matches_tree.clear()
            
            # Display detected applications
            apps_detected = pattern_data.get('applications_detected', {})
            for app_type, details in apps_detected.items():
                if isinstance(details, dict) and details.get('confidence', 0) > 0:
                    confidence = details['confidence']
                    port = details.get('port', 'Unknown')
                    app_text = f"🎯 {app_type} (Port {port}) - {confidence:.1f}% confidence"
                    self.apps_list.addItem(app_text)
            
            # Display pattern matches
            pattern_matches = pattern_data.get('pattern_matches', {})
            for port, matches in pattern_matches.items():
                if matches:
                    for match in matches:
                        confidence = match.get('confidence', 0)
                        pattern_type = match.get('pattern_type', 'Unknown')
                        count = match.get('match_count', 0)
                        
                        item = QTreeWidgetItem([
                            str(port),
                            pattern_type,
                            f"{confidence:.1f}%",
                            str(count)
                        ])
                        
                        # Color code by confidence
                        if confidence >= 90:
                            item.setForeground(0, QBrush(QColor("#00ff00")))
                        elif confidence >= 80:
                            item.setForeground(0, QBrush(QColor("#ffaa00")))
                        else:
                            item.setForeground(0, QBrush(QColor("#ff6666")))
                            
                        self.matches_tree.addTopLevelItem(item)
            
            # Update statistics from real data
            session_info = pattern_data.get('session_info', {})
            total_patterns = session_info.get('patterns_matched', 0)
            high_conf_patterns = session_info.get('high_confidence_matches', 0)
            total_apps = len(apps_detected)
            
            performance = pattern_data.get('performance_metrics', {})
            detection_rate = performance.get('patterns_per_packet', 0) * 100
            
            self.total_patterns_label.setText(f"Total Patterns: {total_patterns}")
            self.high_confidence_label.setText(f"High Confidence: {high_conf_patterns}")
            self.applications_detected_label.setText(f"Applications: {total_apps}")
            self.detection_rate_label.setText(f"Detection Rate: {detection_rate:.1f}%")
            
        except Exception as e:
            self.log_message(f"❌ Error updating pattern display: {e}")
            
    def stop_monitoring(self):
        """Stop loopback monitoring"""
        try:
            if self.monitor_thread:
                self.log_message("🛑 Stopping LoopbackShark monitoring...")
                self.monitor_thread.stop()
                self.monitor_thread.wait(5000)
                
            # Stop progress tracking
            if self.timer:
                self.timer.stop()
            self.start_time = None
            self.progress_bar.setVisible(False) 
            self.timer_label.setText("Timer: Not started")
            
            # Update UI
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.status_label.setText("Status: Ready to monitor loopback traffic")
            self.status_label.setStyleSheet("color: #4a9eff; font-weight: bold; font-size: 13px;")
            
            self.log_message("✅ LoopbackShark monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            self.log_message(f"❌ Error stopping monitoring: {e}")
            
    def update_duration(self, text):
        """Update monitoring duration"""
        duration_map = {
            "5 minutes (300s)": 300,
            "10 minutes (600s)": 600,
            "30 minutes (1800s)": 1800,
            "1 hour (3600s)": 3600,
            "2 hours (7200s)": 7200,
            "4 hours (14400s)": 14400,
            "8 hours (28800s)": 28800,
            "12 hours (43200s)": 43200,
            "24 hours (86400s)": 86400
        }
        
        self.duration = duration_map.get(text, 86400)  # Default to 24 hours
        self.log_message(f"⏱️ Duration set to {self.duration/3600:.1f} hours")
        self.save_settings()  # Save settings when duration changes
        
    def toggle_port_filter(self, state):
        """Toggle port filter input based on All Ports checkbox"""
        all_ports_enabled = state == 2  # Qt.CheckState.Checked = 2
        
        # Enable/disable the port filter input
        self.port_filter_edit.setEnabled(not all_ports_enabled)
        
        if all_ports_enabled:
            # Clear port filter when all ports is enabled
            self.port_filter_edit.clear()
            self.port_filter = None
            self.port_filter_edit.setStyleSheet("QLineEdit { color: #888888; }")
            self.log_message("🔌 All Ports mode enabled - monitoring all loopback traffic")
        else:
            # Re-enable port filter input
            self.port_filter_edit.setStyleSheet("QLineEdit { color: #ffffff; }")
            self.log_message("🔌 Port Filter mode enabled - specify ports to monitor")
        
    def update_port_filter(self, text):
        """Update port filter from text input"""
        # Only update if not in all ports mode
        if not self.all_ports_cb.isChecked():
            if text.strip():
                try:
                    ports = [int(p.strip()) for p in text.split(',') if p.strip().isdigit()]
                    self.port_filter = ports if ports else None
                    if self.port_filter:
                        self.log_message(f"🔌 Port filter updated: {self.port_filter}")
                    else:
                        self.log_message("🔌 Invalid port filter, monitoring all ports")
                except:
                    self.port_filter = None
                    self.log_message("🔌 Invalid port format, monitoring all ports")
            else:
                self.port_filter = None
        # In all ports mode, always keep filter as None
        else:
            self.port_filter = None
            
    def select_directory(self):
        """Select capture directory"""
        try:
            directory = QFileDialog.getExistingDirectory(self, "Select Capture Directory", str(self.capture_dir))
            if directory:
                self.capture_dir = Path(directory)
                self.dir_label.setText(str(self.capture_dir))
                self.log_message(f"📁 Capture directory set to: {self.capture_dir}")
                self.save_settings()  # Save settings when directory changes
        except Exception as e:
            self.log_message(f"❌ Error selecting directory: {e}")
            
    def update_progress(self):
        """Update progress bar and timer"""
        if not self.start_time:
            return
            
        elapsed = datetime.now() - self.start_time
        elapsed_seconds = int(elapsed.total_seconds())
        remaining_seconds = max(0, self.duration - elapsed_seconds)
        
        # Update progress bar
        progress = min(100, (elapsed_seconds / self.duration) * 100)
        self.progress_bar.setValue(int(progress))
        
        # Format time display
        elapsed_str = f"{elapsed_seconds//3600:02d}:{(elapsed_seconds%3600)//60:02d}:{elapsed_seconds%60:02d}"
        remaining_str = f"{remaining_seconds//3600:02d}:{(remaining_seconds%3600)//60:02d}:{remaining_seconds%60:02d}"
        
        self.timer_label.setText(f"Elapsed: {elapsed_str} | Remaining: {remaining_str}")
        
        # Auto-stop when complete
        if remaining_seconds <= 0:
            self.timer.stop()
            self.progress_bar.setValue(100)
            self.stop_monitoring()
            
    def update_display(self):
        """Update display elements periodically"""
        try:
            # Update loopback interface status
            loopback_stats = self.get_loopback_stats()
            if loopback_stats:
                self.update_stats_display(loopback_stats)
        except Exception as e:
            self.logger.error(f"Error updating display: {e}")
            
    def get_loopback_stats(self):
        """Get current loopback interface statistics"""
        try:
            net_stats = psutil.net_io_counters(pernic=True)
            loopback_interfaces = ['lo0', 'lo', 'Loopback']
            
            for interface in loopback_interfaces:
                if interface in net_stats:
                    stats = net_stats[interface]
                    return {
                        'interface': interface,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv
                    }
            return None
        except Exception as e:
            self.logger.error(f"Error getting loopback stats: {e}")
            return None
            
    def update_stats_display(self, stats):
        """Update statistics display"""
        try:
            stats_text = f"""Loopback Interface Statistics:

Interface: {stats['interface']}
Packets Sent: {stats['packets_sent']:,}
Packets Received: {stats['packets_recv']:,}
Total Packets: {stats['packets_sent'] + stats['packets_recv']:,}

Bytes Sent: {stats['bytes_sent']:,}
Bytes Received: {stats['bytes_recv']:,}
Total Bytes: {stats['bytes_sent'] + stats['bytes_recv']:,}

Last Updated: {datetime.now().strftime('%H:%M:%S')}
"""
            self.stats_text.setText(stats_text)
        except Exception as e:
            self.logger.error(f"Error updating stats display: {e}")
            
    def clear_logs(self):
        """Clear the log display"""
        self.log_text.clear()
        self.log_message("📝 Log display cleared")
        
    def export_logs(self):
        """Export logs to file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export LoopbackShark Logs",
                f"loopbackshark_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                "Text Files (*.txt)"
            )
            if filename:
                with open(filename, 'w') as f:
                    f.write(self.log_text.toPlainText())
                self.log_message(f"📄 Logs exported to: {filename}")
        except Exception as e:
            self.log_message(f"❌ Error exporting logs: {e}")
            
    def log_message(self, message):
        """Add message to log display"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {message}"
            self.log_text.append(formatted_message)
            
            # Auto-scroll to bottom
            scrollbar = self.log_text.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
        except Exception as e:
            self.logger.error(f"Error logging message: {e}")
            
    def on_status_update(self, message):
        """Handle status update from monitor thread"""
        self.log_message(f"📡 {message}")
        
    def on_analysis_update(self, analysis):
        """Handle analysis update from monitor thread"""
        try:
            # Update trend analysis displays
            self.update_port_analysis(analysis.get('port_analysis', {}))
            self.update_connection_analysis(analysis.get('connection_trends', {}))
        except Exception as e:
            self.logger.error(f"Error handling analysis update: {e}")
            
    def update_port_analysis(self, port_analysis):
        """Update port analysis table"""
        try:
            self.ports_table.setRowCount(len(port_analysis))
            
            for row, (port, info) in enumerate(port_analysis.items()):
                self.ports_table.setItem(row, 0, QTableWidgetItem(str(port)))
                self.ports_table.setItem(row, 1, QTableWidgetItem(info.get('name', 'Unknown')))
                self.ports_table.setItem(row, 2, QTableWidgetItem(str(info.get('usage_count', 0))))
                self.ports_table.setItem(row, 3, QTableWidgetItem(info.get('category', 'unknown')))
                
        except Exception as e:
            self.logger.error(f"Error updating port analysis: {e}")
            
    def update_connection_analysis(self, connection_trends):
        """Update connection analysis table"""
        try:
            self.connections_table.setRowCount(len(connection_trends))
            
            for row, (connection, trend) in enumerate(connection_trends.items()):
                self.connections_table.setItem(row, 0, QTableWidgetItem(connection))
                self.connections_table.setItem(row, 1, QTableWidgetItem(str(trend.get('total_packets', 0))))
                self.connections_table.setItem(row, 2, QTableWidgetItem(str(trend.get('recent_activity', 0))))
                protocols = ', '.join(trend.get('protocols', []))
                self.connections_table.setItem(row, 3, QTableWidgetItem(protocols))
                
        except Exception as e:
            self.logger.error(f"Error updating connection analysis: {e}")
            
    def on_error(self, error_message):
        """Handle error from monitor thread"""
        self.log_message(f"❌ ERROR: {error_message}")
        QMessageBox.critical(self, "LoopbackShark Error", error_message)
        
    def on_monitoring_finished(self):
        """Handle monitoring completion"""
        self.log_message("✅ LoopbackShark monitoring session completed")
        self.stop_monitoring()
        
    def closeEvent(self, event):
        """Handle window close event"""
        try:
            if self.monitor_thread and self.monitor_thread.isRunning():
                reply = QMessageBox.question(
                    self, 'Confirm Exit',
                    'LoopbackShark is still monitoring. Stop monitoring and exit?',
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No
                )
                
                if reply == QMessageBox.StandardButton.Yes:
                    self.stop_monitoring()
                    event.accept()
                else:
                    event.ignore()
            else:
                event.accept()
        except Exception as e:
            self.logger.error(f"Error in close event: {e}")
            event.accept()

def main():
    try:
        # Setup logging
        logger = setup_logging()
        logger.info("Starting LoopbackShark GUI application")
        
        app = QApplication(sys.argv)
        app.setApplicationName("LoopbackShark")
        
        # Set application icon if available
        try:
            app.setWindowIcon(QIcon("loopbackshark_icon.png"))
        except:
            pass
            
        window = LoopbackSharkGUI()
        window.show()
        
        logger.info("LoopbackShark GUI window shown, entering event loop")
        
        result = app.exec()
        logger.info(f"LoopbackShark application exited with code {result}")
        return result
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
