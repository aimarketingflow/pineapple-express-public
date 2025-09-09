#!/usr/bin/env python3
"""
BSSID Blacklist Management Dialog
GUI interface for managing router-specific attack blocking
"""

import sys
import os
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from bssid_blacklist_manager import BSSIDBlacklistManager
except ImportError:
    BSSIDBlacklistManager = None

class BSSIDBlacklistDialog(QDialog):
    """Dialog for managing BSSID blacklist"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🚫 BSSID Blacklist Manager")
        self.setModal(True)
        self.setFixedSize(800, 600)
        
        # Initialize blacklist manager
        if BSSIDBlacklistManager:
            self.blacklist_manager = BSSIDBlacklistManager()
        else:
            self.blacklist_manager = None
        
        self.init_ui()
        self.load_blacklist()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🚫 BSSID Blacklist Manager")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #d32f2f;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Description
        desc = QLabel("Block specific router BSSIDs to prevent attacks from known malicious devices")
        desc.setStyleSheet("color: #666; font-size: 14px; padding: 10px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        # Add new BSSID section
        add_group = QGroupBox("➕ Add New BSSID to Blacklist")
        add_layout = QHBoxLayout()
        
        self.bssid_input = QLineEdit()
        self.bssid_input.setPlaceholderText("Enter BSSID (e.g., AA:BB:CC:DD:EE:FF)")
        self.bssid_input.textChanged.connect(self.validate_bssid_input)
        add_layout.addWidget(self.bssid_input)
        
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Reason (optional)")
        add_layout.addWidget(self.reason_input)
        
        self.add_button = QPushButton("🚫 Add to Blacklist")
        self.add_button.setEnabled(False)
        self.add_button.clicked.connect(self.add_bssid)
        self.add_button.setStyleSheet("""
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
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        add_layout.addWidget(self.add_button)
        
        add_group.setLayout(add_layout)
        layout.addWidget(add_group)
        
        # Current blacklist table
        list_group = QGroupBox("📋 Current Blacklisted BSSIDs")
        list_layout = QVBoxLayout()
        
        # Stats
        self.stats_label = QLabel("Loading blacklist...")
        self.stats_label.setStyleSheet("font-weight: bold; color: #d32f2f; padding: 5px;")
        list_layout.addWidget(self.stats_label)
        
        # Table
        self.blacklist_table = QTableWidget()
        self.blacklist_table.setColumnCount(3)
        self.blacklist_table.setHorizontalHeaderLabels(["BSSID", "Added", "Actions"])
        self.blacklist_table.horizontalHeader().setStretchLastSection(True)
        self.blacklist_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        list_layout.addWidget(self.blacklist_table)
        
        list_group.setLayout(list_layout)
        layout.addWidget(list_group)
        
        # Test BSSIDs section
        test_group = QGroupBox("🧪 Pre-loaded Test BSSIDs")
        test_layout = QVBoxLayout()
        
        test_info = QLabel("These BSSIDs are automatically added for testing:")
        test_info.setStyleSheet("color: #666; font-style: italic;")
        test_layout.addWidget(test_info)
        
        test_bssids = [
            "02:12:34:DF:3E:AE",
            "00:30:44:5D:97:55", 
            "AC:91:9B:4C:ED:C2",
            "32:B4:B8:EB:D5:1B",
            "C4:EB:42:93:87:A7",
            "F8:55:CD:7B:0B:A0"
        ]
        
        test_list = QLabel("• " + "\n• ".join(test_bssids))
        test_list.setStyleSheet("font-family: monospace; color: #d32f2f; padding: 10px;")
        test_layout.addWidget(test_list)
        
        test_group.setLayout(test_layout)
        layout.addWidget(test_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.scan_button = QPushButton("🔍 Scan & Block Threats")
        self.scan_button.clicked.connect(self.scan_and_block)
        self.scan_button.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #ffa726;
            }
        """)
        button_layout.addWidget(self.scan_button)
        
        button_layout.addStretch()
        
        self.export_button = QPushButton("💾 Export Blacklist")
        self.export_button.clicked.connect(self.export_blacklist)
        button_layout.addWidget(self.export_button)
        
        close_button = QPushButton("✅ Close")
        close_button.clicked.connect(self.accept)
        close_button.setStyleSheet("""
            QPushButton {
                background-color: #4caf50;
                color: white;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #66bb6a;
            }
        """)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
    
    def validate_bssid_input(self):
        """Validate BSSID input format"""
        bssid = self.bssid_input.text().strip()
        
        if self.blacklist_manager and self.blacklist_manager.is_valid_bssid(bssid):
            self.bssid_input.setStyleSheet("border: 2px solid #4caf50;")
            self.add_button.setEnabled(True)
        else:
            self.bssid_input.setStyleSheet("border: 2px solid #f44336;" if bssid else "")
            self.add_button.setEnabled(False)
    
    def add_bssid(self):
        """Add BSSID to blacklist"""
        if not self.blacklist_manager:
            QMessageBox.warning(self, "Error", "Blacklist manager not available")
            return
        
        bssid = self.bssid_input.text().strip()
        reason = self.reason_input.text().strip() or "Manual addition"
        
        if self.blacklist_manager.add_bssid(bssid, reason):
            QMessageBox.information(self, "✅ Success", f"Added {bssid} to blacklist")
            self.bssid_input.clear()
            self.reason_input.clear()
            self.load_blacklist()
        else:
            QMessageBox.warning(self, "❌ Error", f"Failed to add {bssid} to blacklist")
    
    def load_blacklist(self):
        """Load and display current blacklist"""
        if not self.blacklist_manager:
            self.stats_label.setText("❌ Blacklist manager not available")
            return
        
        summary = self.blacklist_manager.get_blacklist_summary()
        blocked_bssids = summary['blocked_bssids']
        
        self.stats_label.setText(f"🚫 {len(blocked_bssids)} BSSIDs currently blacklisted")
        
        # Update table
        self.blacklist_table.setRowCount(len(blocked_bssids))
        
        for i, bssid in enumerate(sorted(blocked_bssids)):
            # BSSID column
            bssid_item = QTableWidgetItem(bssid)
            bssid_item.setFont(QFont("monospace"))
            self.blacklist_table.setItem(i, 0, bssid_item)
            
            # Added column (placeholder)
            added_item = QTableWidgetItem("System")
            self.blacklist_table.setItem(i, 1, added_item)
            
            # Actions column
            remove_button = QPushButton("🗑️ Remove")
            remove_button.clicked.connect(lambda checked, b=bssid: self.remove_bssid(b))
            remove_button.setStyleSheet("""
                QPushButton {
                    background-color: #f44336;
                    color: white;
                    padding: 4px 8px;
                    border-radius: 3px;
                }
                QPushButton:hover {
                    background-color: #d32f2f;
                }
            """)
            self.blacklist_table.setCellWidget(i, 2, remove_button)
        
        # Resize columns
        self.blacklist_table.resizeColumnsToContents()
    
    def remove_bssid(self, bssid):
        """Remove BSSID from blacklist"""
        if not self.blacklist_manager:
            return
        
        reply = QMessageBox.question(self, "Confirm Removal",
            f"Remove {bssid} from blacklist?\n\n"
            f"This will allow traffic from this BSSID again.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            if self.blacklist_manager.remove_bssid(bssid):
                QMessageBox.information(self, "✅ Success", f"Removed {bssid} from blacklist")
                self.load_blacklist()
            else:
                QMessageBox.warning(self, "❌ Error", f"Failed to remove {bssid}")
    
    def scan_and_block(self):
        """Scan for networks and block any blacklisted BSSIDs"""
        if not self.blacklist_manager:
            QMessageBox.warning(self, "Error", "Blacklist manager not available")
            return
        
        self.scan_button.setEnabled(False)
        self.scan_button.setText("🔍 Scanning...")
        
        try:
            self.blacklist_manager.scan_and_block_threats()
            QMessageBox.information(self, "✅ Scan Complete", 
                "Network scan completed. Check logs for blocked threats.")
        except Exception as e:
            QMessageBox.warning(self, "❌ Scan Error", f"Error during scan: {e}")
        finally:
            self.scan_button.setEnabled(True)
            self.scan_button.setText("🔍 Scan & Block Threats")
    
    def export_blacklist(self):
        """Export blacklist to file"""
        if not self.blacklist_manager:
            QMessageBox.warning(self, "Error", "Blacklist manager not available")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export Blacklist", 
            f"bssid_blacklist_export_{QDateTime.currentDateTime().toString('yyyyMMdd_hhmmss')}.json",
            "JSON Files (*.json)")
        
        if filename:
            if self.blacklist_manager.export_blacklist(filename):
                QMessageBox.information(self, "✅ Export Success", 
                    f"Blacklist exported to:\n{filename}")
            else:
                QMessageBox.warning(self, "❌ Export Error", "Failed to export blacklist")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    dialog = BSSIDBlacklistDialog()
    dialog.show()
    sys.exit(app.exec())
