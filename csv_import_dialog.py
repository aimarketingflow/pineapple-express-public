#!/usr/bin/env python3
"""
CSV Import Dialog for BSSID Blacklist
Advanced CSV import interface with filtering and preview
"""

import sys
import os
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

# Add current directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from csv_import_manager import CSVImportManager
    from bssid_blacklist_manager import BSSIDBlacklistManager
except ImportError:
    CSVImportManager = None
    BSSIDBlacklistManager = None

class CSVImportDialog(QDialog):
    """Advanced CSV import dialog with filtering and preview"""
    
    def __init__(self, parent=None, blacklist_manager=None):
        super().__init__(parent)
        self.setWindowTitle("📂 Import BSSIDs from CSV")
        self.setModal(True)
        self.setFixedSize(1000, 700)
        
        self.blacklist_manager = blacklist_manager
        self.csv_manager = CSVImportManager() if CSVImportManager else None
        self.networks = []
        self.filtered_networks = []
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("📂 Import BSSIDs from CSV File")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #4caf50;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Description
        desc = QLabel("Import BSSIDs from WiFi Explorer CSV exports or other compatible formats")
        desc.setStyleSheet("color: #666; font-size: 14px; padding: 10px;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)
        
        # File selection
        file_group = QGroupBox("📁 File Selection")
        file_layout = QHBoxLayout()
        
        self.file_path_label = QLabel("No file selected")
        self.file_path_label.setStyleSheet("padding: 8px; background-color: #f5f5f5; border-radius: 5px;")
        file_layout.addWidget(self.file_path_label)
        
        self.browse_button = QPushButton("📁 Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        self.browse_button.setStyleSheet("""
            QPushButton {
                background-color: #2196f3;
                color: white;
                padding: 8px 16px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #42a5f5;
            }
        """)
        file_layout.addWidget(self.browse_button)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Import options
        options_group = QGroupBox("⚙️ Import Options")
        options_layout = QVBoxLayout()
        
        # Filter options
        filter_layout = QGridLayout()
        
        self.filter_open_networks = QCheckBox("Include Open/Unsecured Networks")
        self.filter_open_networks.setChecked(True)
        filter_layout.addWidget(self.filter_open_networks, 0, 0)
        
        self.filter_suspicious_names = QCheckBox("Include Suspicious Network Names")
        self.filter_suspicious_names.setChecked(True)
        filter_layout.addWidget(self.filter_suspicious_names, 0, 1)
        
        self.filter_hidden_networks = QCheckBox("Include Hidden Networks")
        self.filter_hidden_networks.setChecked(True)
        filter_layout.addWidget(self.filter_hidden_networks, 1, 0)
        
        self.exclude_known_vendors = QCheckBox("Exclude Trusted Vendors")
        self.exclude_known_vendors.setChecked(False)
        filter_layout.addWidget(self.exclude_known_vendors, 1, 1)
        
        options_layout.addLayout(filter_layout)
        
        # Vendor exclusion
        vendor_layout = QHBoxLayout()
        vendor_layout.addWidget(QLabel("Exclude Vendors:"))
        
        self.vendor_exclusions = QLineEdit()
        self.vendor_exclusions.setPlaceholderText("e.g., Apple, Google, Microsoft (comma-separated)")
        vendor_layout.addWidget(self.vendor_exclusions)
        
        options_layout.addLayout(vendor_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Preview section
        preview_group = QGroupBox("👁️ Import Preview")
        preview_layout = QVBoxLayout()
        
        # Stats
        self.stats_label = QLabel("Select a CSV file to see preview")
        self.stats_label.setStyleSheet("font-weight: bold; padding: 5px;")
        preview_layout.addWidget(self.stats_label)
        
        # Preview table
        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(5)
        self.preview_table.setHorizontalHeaderLabels(["Select", "BSSID", "Network Name", "Vendor", "Security"])
        self.preview_table.horizontalHeader().setStretchLastSection(True)
        self.preview_table.setMaximumHeight(300)
        self.preview_table.setAlternatingRowColors(True)
        self.preview_table.setSortingEnabled(True)
        self.preview_table.horizontalHeader().setSectionsClickable(True)
        preview_layout.addWidget(self.preview_table)
        
        preview_group.setLayout(preview_layout)
        layout.addWidget(preview_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.preview_button = QPushButton("👁️ Preview Import")
        self.preview_button.clicked.connect(self.preview_import)
        self.preview_button.setEnabled(False)
        self.preview_button.setStyleSheet("""
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
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        button_layout.addWidget(self.preview_button)
        
        button_layout.addStretch()
        
        self.import_button = QPushButton("📂 Import Selected")
        self.import_button.clicked.connect(self.import_selected)
        self.import_button.setEnabled(False)
        self.import_button.setStyleSheet("""
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
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        button_layout.addWidget(self.import_button)
        
        cancel_button = QPushButton("❌ Cancel")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                padding: 10px 20px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #ef5350;
            }
        """)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Apply dark theme
        self.apply_dark_theme()
    
    def apply_dark_theme(self):
        """Apply dark theme to dialog"""
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
            }
            QLineEdit {
                background-color: #3c3c3c;
                border: 2px solid #555;
                border-radius: 5px;
                padding: 8px;
                color: #ffffff;
            }
            QCheckBox {
                color: #ffffff;
                padding: 5px;
            }
            QLabel {
                color: #ffffff;
            }
            QTableWidget {
                background-color: #3c3c3c;
                gridline-color: #555;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #444;
                color: white;
                padding: 8px;
                font-weight: bold;
                border: 1px solid #555;
            }
        """)
    
    def browse_file(self):
        """Browse for CSV file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select CSV File", 
            "/Users/flowgirl/Documents/_MobileShield/PineappleExpress/_Chatlogs_Pineapple/",
            "CSV Files (*.csv);;All Files (*)")
        
        if file_path:
            self.file_path_label.setText(file_path)
            self.preview_button.setEnabled(True)
    
    def preview_import(self):
        """Preview the CSV import"""
        if not self.csv_manager:
            QMessageBox.warning(self, "Error", "CSV manager not available")
            return
        
        file_path = self.file_path_label.text()
        if file_path == "No file selected":
            return
        
        try:
            # Parse CSV file
            self.networks = self.csv_manager.parse_csv_file(file_path)
            
            # Apply filters
            filters = self.get_current_filters()
            self.filtered_networks = self.csv_manager.filter_networks(self.networks, filters)
            
            # Update stats
            summary = self.csv_manager.get_import_summary(self.filtered_networks)
            self.stats_label.setText(
                f"📊 Found {summary['total_networks']} networks "
                f"({summary['unique_bssids']} unique BSSIDs, "
                f"{summary['suspicious_count']} suspicious)"
            )
            
            # Update preview table
            self.update_preview_table()
            
            self.import_button.setEnabled(len(self.filtered_networks) > 0)
            
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Failed to parse CSV file:\n{e}")
    
    def get_current_filters(self):
        """Get current filter settings"""
        filters = {}
        
        # Security filters
        if self.filter_open_networks.isChecked():
            filters['security_types'] = ['Open', 'None', '']
        
        # Suspicious names
        if self.filter_suspicious_names.isChecked():
            filters['suspicious_names'] = True
        
        # Vendor exclusions
        vendor_text = self.vendor_exclusions.text().strip()
        if vendor_text and self.exclude_known_vendors.isChecked():
            vendors = [v.strip() for v in vendor_text.split(',') if v.strip()]
            filters['exclude_vendors'] = vendors
        
        return filters
    
    def update_preview_table(self):
        """Update the preview table with filtered networks"""
        # Disable sorting while updating to prevent crashes
        self.preview_table.setSortingEnabled(False)
        
        self.preview_table.setRowCount(len(self.filtered_networks))
        
        for i, network in enumerate(self.filtered_networks):
            # Checkbox - not sortable
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            self.preview_table.setCellWidget(i, 0, checkbox)
            
            # BSSID
            bssid_item = QTableWidgetItem(network['bssid'])
            bssid_item.setFont(QFont("monospace"))
            # Store original data for sorting
            bssid_item.setData(Qt.ItemDataRole.UserRole, network['bssid'])
            self.preview_table.setItem(i, 1, bssid_item)
            
            # Network Name
            name_item = QTableWidgetItem(network['name'])
            name_item.setData(Qt.ItemDataRole.UserRole, network['name'])
            self.preview_table.setItem(i, 2, name_item)
            
            # Vendor
            vendor_item = QTableWidgetItem(network['vendor'])
            vendor_item.setData(Qt.ItemDataRole.UserRole, network['vendor'])
            self.preview_table.setItem(i, 3, vendor_item)
            
            # Security
            security_item = QTableWidgetItem(network['security'])
            security_item.setData(Qt.ItemDataRole.UserRole, network['security'])
            
            # Color code security
            if 'Open' in network['security'] or not network['security']:
                security_item.setForeground(QColor("#f44336"))  # Red for open
            elif 'WPA3' in network['security']:
                security_item.setForeground(QColor("#4caf50"))  # Green for WPA3
            else:
                security_item.setForeground(QColor("#ff9800"))  # Orange for WPA2
            
            self.preview_table.setItem(i, 4, security_item)
        
        # Re-enable sorting after data is loaded
        self.preview_table.setSortingEnabled(True)
        
        # Resize columns
        self.preview_table.resizeColumnsToContents()
    
    def import_selected(self):
        """Import selected BSSIDs to blacklist"""
        if not self.blacklist_manager:
            QMessageBox.warning(self, "Error", "Blacklist manager not available")
            return
        
        selected_networks = []
        
        # Get selected networks
        for i in range(self.preview_table.rowCount()):
            checkbox = self.preview_table.cellWidget(i, 0)
            if checkbox and checkbox.isChecked():
                if i < len(self.filtered_networks):
                    selected_networks.append(self.filtered_networks[i])
        
        if not selected_networks:
            QMessageBox.warning(self, "No Selection", "Please select at least one network to import")
            return
        
        # Confirm import
        reply = QMessageBox.question(self, "Confirm Import",
            f"Import {len(selected_networks)} BSSIDs to blacklist?\n\n"
            f"This will block all traffic from these networks.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply != QMessageBox.StandardButton.Yes:
            return
        
        # Import networks
        imported_count = 0
                trusted_skipped += 1
                print(f"🛡️ Auto-excluded current network: {ssid} ({bssid}) - protecting connected WiFi")
                continue
            
            try:
                if self.blacklist_manager and self.blacklist_manager.add_bssid(bssid, reason):
                    imported_count += 1
                else:
                    failed_count += 1
            except Exception as e:
                failed_count += 1
                print(f"Failed to import {bssid}: {e}")
        
        result_message = f"Import Results:\nSuccessfully imported: {imported_count}\n"
        if failed_count > 0:
            result_message += f"Failed: {failed_count}\n"
        if trusted_skipped > 0:
            result_message += f"Auto-excluded current WiFi: {trusted_skipped} (protecting connected network)"
        
        if imported_count > 0 or trusted_skipped > 0:
            QMessageBox.information(self, "Import Complete", result_message)
            self.accept()
        else:
            QMessageBox.warning(self, "Import Failed",
                f"Failed to import any BSSIDs.\n"
                f"They may already be in the blacklist.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    dialog = CSVImportDialog()
    dialog.show()
    sys.exit(app.exec())
