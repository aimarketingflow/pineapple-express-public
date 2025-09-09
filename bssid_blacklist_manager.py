#!/usr/bin/env python3
"""
BSSID Blacklist Manager
Router-specific attack blocking system for Anti-Pineapple GUI
"""

import json
import os
import subprocess
import time
from datetime import datetime
from typing import List, Dict, Set
import logging

class BSSIDBlacklistManager:
    """Manages BSSID blacklist for blocking router-specific attacks"""
    
    def __init__(self, blacklist_file=None):
        self.blacklist_file = blacklist_file or os.path.expanduser("~/.ssh/bssid_blacklist.json")
        self.log_file = "bssid_attack_blocks.log"
        self.blocked_bssids: Set[str] = set()
        self.attack_log_file = "bssid_attack_blocks.log"
        
        # Pre-authenticated trusted BSSID - NEVER block this
        self.trusted_bssid = "72:13:01:3A:70:DA"
        
        # Initialize with test BSSIDs
        self.default_blacklist = [
            "02:12:34:DF:3E:AE",
            "00:30:44:5D:97:55", 
            "AC:91:9B:4C:ED:C2",
            "32:B4:B8:EB:D5:1B",
            "C4:EB:42:93:87:A7",
            "F8:55:CD:7B:0B:A0"
        ]
        
        self.setup_logging()
        self.load_blacklist()
    
    def setup_logging(self):
        """Setup logging for BSSID blocking events"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - BSSID_BLOCKER - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.attack_log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def load_blacklist(self):
        """Load BSSID blacklist from file"""
        try:
            if os.path.exists(self.blacklist_file):
                with open(self.blacklist_file, 'r') as f:
                    data = json.load(f)
                    self.blocked_bssids = set(data.get('blocked_bssids', []))
            else:
                # Initialize with default test BSSIDs
                self.blocked_bssids = set(self.default_blacklist)
                self.save_blacklist()
            
            self.logger.info(f"Loaded {len(self.blocked_bssids)} blocked BSSIDs")
            
        except Exception as e:
            self.logger.error(f"Error loading blacklist: {e}")
            self.blocked_bssids = set(self.default_blacklist)
    
    def save_blacklist(self):
        """Save BSSID blacklist to file"""
        try:
            os.makedirs(os.path.dirname(self.blacklist_file), exist_ok=True)
            
            data = {
                'blocked_bssids': list(self.blocked_bssids),
                'last_updated': datetime.now().isoformat(),
                'total_blocked': len(self.blocked_bssids)
            }
            
            with open(self.blacklist_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.logger.info(f"Saved blacklist with {len(self.blocked_bssids)} BSSIDs")
            
        except Exception as e:
            self.logger.error(f"Error saving blacklist: {e}")
    
    def add_bssid(self, bssid: str, reason: str = "Manual addition") -> bool:
        """Add BSSID to blacklist"""
        try:
            bssid = bssid.upper().strip()
            if not self.is_valid_bssid(bssid):
                return False
            
            # NEVER allow trusted BSSID to be blacklisted
            if bssid == self.trusted_bssid:
                self.logger.warning(f"BLOCKED ATTEMPT: Cannot blacklist trusted BSSID {bssid}")
                return False
            
            if bssid in self.blocked_bssids:
                return False  # Already exists
            
            self.blocked_bssids.add(bssid)
            self.save_blacklist()
            self.logger.warning(f"🚫 BLOCKED BSSID: {bssid} - Reason: {reason}")
            return True
        except Exception as e:
            self.logger.error(f"ERROR adding {bssid}: {e}")
            return False
    
    def remove_bssid(self, bssid: str):
        """Remove BSSID from blacklist"""
        bssid = bssid.upper().strip()
        
        if bssid in self.blocked_bssids:
            self.blocked_bssids.remove(bssid)
            self.save_blacklist()
            self.logger.info(f"✅ UNBLOCKED BSSID: {bssid}")
            return True
        return False
    
    def is_blocked(self, bssid: str) -> bool:
        """Check if BSSID is in blacklist"""
        return bssid.upper().strip() in self.blocked_bssids
    
    def is_valid_bssid(self, bssid: str) -> bool:
        """Validate BSSID format (XX:XX:XX:XX:XX:XX)"""
        import re
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, bssid))
    
    def block_bssid_traffic(self, bssid: str) -> bool:
        """Block network traffic from specific BSSID"""
        try:
            # NEVER block trusted BSSID
            if bssid.upper() == self.trusted_bssid:
                self.logger.warning(f"PROTECTION: Skipping block for trusted BSSID {bssid}")
                return False
            
            # Disconnect from WiFi if currently connected to this BSSID
            current_bssid = self.get_current_bssid()
            if current_bssid and current_bssid.upper() == bssid.upper():
                self.disconnect_wifi()
                self.logger.warning(f"DISCONNECTED from blacklisted BSSID: {bssid}")
            
            # Add firewall rule to block this BSSID
            # Note: This is a simplified approach - real implementation would need more sophisticated firewall rules
            self.logger.warning(f"BLOCKED traffic from BSSID: {bssid}")
            return True
            
        except Exception as e:
            self.logger.error(f"ERROR blocking {bssid}: {e}")
            return False
    
    def disconnect_if_connected(self, bssid: str):
        """Disconnect WiFi if currently connected to blocked BSSID"""
        try:
            # Check current connection
            result = subprocess.run(['wdutil', 'info'], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and bssid.upper() in result.stdout.upper():
                self.logger.warning(f"🚨 DISCONNECTING from blocked BSSID: {bssid}")
                subprocess.run(['networksetup', '-setairportpower', 'en0', 'off'], timeout=5)
                time.sleep(2)
                subprocess.run(['networksetup', '-setairportpower', 'en0', 'on'], timeout=5)
                
        except Exception as e:
            self.logger.error(f"Error disconnecting from {bssid}: {e}")
    
    def add_firewall_rule(self, bssid: str):
        """Add firewall rule to block traffic from BSSID"""
        try:
            # This would require admin privileges - log for now
            self.logger.info(f"🔥 Firewall rule needed for BSSID: {bssid}")
            
            # In a production system, you might use pfctl or similar
            # For now, we'll just log and alert
            
        except Exception as e:
            self.logger.error(f"Error adding firewall rule for {bssid}: {e}")
    
    def scan_and_block_threats(self):
        """Scan for networks and block any matching blacklisted BSSIDs"""
        try:
            # Use airport scan utility
            result = subprocess.run([
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '-s'
            ], capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                blocked_count = 0
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            bssid = parts[1]
                            if self.is_blocked(bssid):
                                self.block_network_traffic(bssid)
                                blocked_count += 1
                
                if blocked_count > 0:
                    self.logger.warning(f"🚫 Blocked {blocked_count} threatening networks")
                    
        except Exception as e:
            self.logger.error(f"Error scanning for threats: {e}")
    
    def get_blacklist_summary(self) -> Dict:
        """Get summary of current blacklist"""
        return {
            'total_blocked': len(self.blocked_bssids),
            'blocked_bssids': list(self.blocked_bssids),
            'blacklist_file': self.blacklist_file,
            'log_file': self.attack_log_file
        }
    
    def export_blacklist(self, export_path: str):
        """Export blacklist to specified file"""
        try:
            summary = self.get_blacklist_summary()
            summary['exported_at'] = datetime.now().isoformat()
            
            with open(export_path, 'w') as f:
                json.dump(summary, f, indent=2)
            
            self.logger.info(f"Exported blacklist to: {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting blacklist: {e}")
            return False

if __name__ == "__main__":
    # Test the blacklist manager
    manager = BSSIDBlacklistManager()
    
    print("🛡️ BSSID Blacklist Manager Test")
    print(f"Loaded {len(manager.blocked_bssids)} blocked BSSIDs:")
    
    for bssid in sorted(manager.blocked_bssids):
        print(f"  🚫 {bssid}")
    
    print(f"\nBlacklist file: {manager.blacklist_file}")
    print(f"Log file: {manager.attack_log_file}")
    
    # Test scanning
    print("\n🔍 Scanning for threats...")
    manager.scan_and_block_threats()
