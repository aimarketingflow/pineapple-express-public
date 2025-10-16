#!/usr/bin/env python3
"""
iPhone Hotspot Blocker Module
Integrated into Anti-Pineapple System
"""

import subprocess
import re
import time
from datetime import datetime
from PyQt6.QtCore import QThread, pyqtSignal


class HotspotBlockerThread(QThread):
    """Thread for monitoring and blocking iPhone hotspots"""
    hotspot_detected = pyqtSignal(str)  # SSID
    hotspot_blocked = pyqtSignal(str)   # SSID
    status_update = pyqtSignal(str)     # Status message
    
    def __init__(self):
        super().__init__()
        self.running = False
        self.enabled = False
        self.iphone_patterns = [
            r".*iPhone.*",      # Standard iPhone hotspot names
            r".*'s iPhone",     # Possessive iPhone names  
            r"iPhone \d+",      # iPhone with numbers
            r".*iOS.*",         # iOS devices
        ]
        self.blocked_networks = set()
        self.last_ssid = None
        
    def add_pattern(self, pattern):
        """Add custom hotspot pattern"""
        if pattern not in self.iphone_patterns:
            self.iphone_patterns.append(pattern)
    
    def remove_pattern(self, pattern):
        """Remove hotspot pattern"""
        if pattern in self.iphone_patterns:
            self.iphone_patterns.remove(pattern)
    
    def get_current_ssid(self):
        """Get the currently connected WiFi SSID"""
        try:
            interface = self.get_wifi_interface()
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout.strip()
            if "Current Wi-Fi Network:" in output:
                ssid = output.split("Current Wi-Fi Network:")[1].strip()
                return ssid if ssid else None
            elif "You are not associated with an AirPort network" in output:
                return None
            
            return None
        except Exception as e:
            self.status_update.emit(f"Error getting SSID: {e}")
            return None
    
    def is_apple_mac_address(self, bssid):
        """Check if MAC address (BSSID) belongs to Apple"""
        if not bssid:
            return False
        
        # Apple's registered MAC address prefixes (OUI - Organizationally Unique Identifier)
        apple_oui_prefixes = [
            '00:03:93', '00:05:02', '00:0a:27', '00:0a:95', '00:0d:93',
            '00:10:fa', '00:11:24', '00:13:e8', '00:14:51', '00:16:cb',
            '00:17:f2', '00:19:e3', '00:1b:63', '00:1c:b3', '00:1d:4f',
            '00:1e:52', '00:1e:c2', '00:1f:5b', '00:1f:f3', '00:21:e9',
            '00:22:41', '00:23:12', '00:23:32', '00:23:6c', '00:23:df',
            '00:24:36', '00:25:00', '00:25:4b', '00:25:bc', '00:26:08',
            '00:26:4a', '00:26:b0', '00:26:bb', '00:30:65', '00:3e:e1',
            '00:50:e4', '00:56:cd', '00:61:71', '00:88:65', '00:c6:10',
            '00:cd:fe', '00:d4:20', '00:f4:b9', '00:f7:6f', '04:0c:ce',
            '04:15:52', '04:1e:64', '04:26:65', '04:48:9a', '04:4b:ed',
            '04:54:53', '04:69:f8', '04:d3:cf', '04:db:56', '04:e5:36',
            '04:f1:3e', '04:f7:e4', '08:00:07', '08:66:98', '08:70:45',
            '08:74:02', '08:e6:89', '0c:3e:9f', '0c:4d:e9', '0c:74:c2',
            '0c:77:1a', '10:40:f3', '10:41:7f', '10:9a:dd', '10:dd:b1',
            '14:10:9f', '14:20:5e', '14:5a:05', '14:8f:c6', '14:99:e2',
            '14:bd:61', '18:20:32', '18:34:51', '18:3d:a2', '18:af:61',
            '18:e7:f4', '1c:1a:c0', '1c:36:bb', '1c:ab:a7', '1c:e6:2b',
            '20:3c:ae', '20:78:f0', '20:a2:e4', '20:ab:37', '20:c9:d0',
            '24:24:0e', '24:2b:a2', '24:5b:a7', '24:a0:74', '24:a2:e1',
            '24:ab:81', '24:f0:94', '24:f6:77', '28:37:37', '28:5a:eb',
            '28:6a:b8', '28:6a:ba', '28:a0:2b', '28:cf:da', '28:cf:e9',
            '28:e0:2c', '28:e1:4c', '28:ed:6a', '28:f0:76', '2c:1f:23',
            '2c:20:0b', '2c:33:11', '2c:36:f8', '2c:3a:fd', '2c:54:cf',
            '2c:61:f6', '2c:b4:3a', '2c:be:08', '2c:f0:a2', '2c:f0:ee',
            '30:10:e4', '30:35:ad', '30:63:6b', '30:90:ab', '30:f7:c5',
            '34:12:f9', '34:15:9e', '34:36:3b', '34:51:c9', '34:a3:95',
            '34:ab:37', '34:c0:59', '34:e2:fd', '38:0f:4a', '38:48:4c',
            '38:89:2c', '38:b5:4d', '38:c9:86', '3c:07:54', '3c:15:c2',
            '3c:2e:f9', '3c:a9:f4', '40:30:04', '40:33:1a', '40:3c:fc',
            '40:4d:7f', '40:6c:8f', '40:a6:d9', '40:b3:95', '40:cb:c0',
            '44:2a:60', '44:4c:0c', '44:d8:84', '44:fb:42', '48:43:7c',
            '48:60:bc', '48:74:6e', '48:a1:95', '48:d7:05', '48:e9:f1',
            '4c:32:75', '4c:57:ca', '4c:7c:5f', '4c:8d:79', '4c:b1:99',
            '50:32:37', '50:82:d5', '50:ea:d6', '54:26:96', '54:4e:90',
            '54:72:4f', '54:9f:13', '54:ae:27', '54:e4:3a', '58:1f:aa',
            '58:40:4e', '58:55:ca', '58:7f:57', '58:b0:35', '5c:59:48',
            '5c:5f:67', '5c:95:ae', '5c:96:9d', '5c:97:f3', '5c:f9:38',
            '60:33:4b', '60:69:44', '60:92:17', '60:c5:47', '60:d9:c7',
            '60:f8:1d', '60:fa:cd', '60:fb:42', '64:20:0c', '64:76:ba',
            '64:a3:cb', '64:b0:a6', '64:b9:e8', '64:e6:82', '68:5b:35',
            '68:96:7b', '68:9c:70', '68:a8:6d', '68:ab:1e', '68:d9:3c',
            '68:db:f5', '68:fe:f7', '6c:19:c0', '6c:3e:6d', '6c:40:08',
            '6c:4d:73', '6c:70:9f', '6c:72:20', '6c:94:66', '6c:96:cf',
            '6c:ab:31', '6c:c2:6b', '70:11:24', '70:14:a6', '70:3e:ac',
            '70:48:0f', '70:56:81', '70:73:cb', '70:81:eb', '70:a2:b3',
            '70:cd:60', '70:de:e2', '70:ec:e4', '74:1b:b2', '74:81:14',
            '74:e1:b6', '74:e2:f5', '78:31:c1', '78:3a:84', '78:52:1a',
            '78:67:d7', '78:7b:8a', '78:88:6d', '78:a3:e4', '78:ca:39',
            '78:d7:5f', '78:fd:94', '7c:01:91', '7c:04:d0', '7c:11:be',
            '7c:50:49', '7c:6d:62', '7c:6d:f8', '7c:c3:a1', '7c:c5:37',
            '7c:d1:c3', '7c:f0:5f', '80:00:6e', '80:49:71', '80:92:9f',
            '80:be:05', '80:d6:05', '80:e6:50', '84:38:35', '84:78:8b',
            '84:85:06', '84:89:ad', '84:fc:fe', '88:1f:a1', '88:53:95',
            '88:63:df', '88:66:5a', '88:cb:87', '88:e8:7f', '8c:00:6d',
            '8c:2d:aa', '8c:58:77', '8c:7c:92', '8c:85:90', '8c:8e:f2',
            '90:27:e4', '90:72:40', '90:84:0d', '90:8d:6c', '90:b0:ed',
            '90:b2:1f', '90:b9:31', '94:94:26', '94:bf:2d', '94:e9:6a',
            '94:f6:a3', '98:01:a7', '98:03:d8', '98:5a:eb', '98:b8:e3',
            '98:d6:bb', '98:e0:d9', '98:f0:ab', '98:fe:94', '9c:04:eb',
            '9c:20:7b', '9c:29:3f', '9c:35:eb', '9c:4f:da', '9c:84:bf',
            '9c:fc:e8', 'a0:18:28', 'a0:99:9b', 'a0:d7:95', 'a0:ed:cd',
            'a4:31:35', 'a4:5e:60', 'a4:67:06', 'a4:83:e7', 'a4:b1:97',
            'a4:c3:61', 'a4:d1:8c', 'a4:d9:31', 'a8:20:66', 'a8:5b:78',
            'a8:5c:2c', 'a8:66:7f', 'a8:86:dd', 'a8:88:08', 'a8:96:8a',
            'a8:be:27', 'a8:fa:d8', 'ac:1f:74', 'ac:29:3a', 'ac:3c:0b',
            'ac:61:ea', 'ac:7f:3e', 'ac:87:a3', 'ac:bc:32', 'ac:cf:5c',
            'ac:e4:b5', 'ac:fd:ce', 'b0:34:95', 'b0:48:7a', 'b0:65:bd',
            'b0:70:2d', 'b0:9f:ba', 'b0:ca:68', 'b4:18:d1', 'b4:8b:19',
            'b4:f0:ab', 'b4:f6:1c', 'b8:09:8a', 'b8:17:c2', 'b8:41:a4',
            'b8:44:d9', 'b8:53:ac', 'b8:63:4d', 'b8:78:2e', 'b8:c1:11',
            'b8:c7:5d', 'b8:e8:56', 'b8:f6:b1', 'b8:ff:61', 'bc:3b:af',
            'bc:52:b7', 'bc:54:2f', 'bc:67:1c', 'bc:6c:21', 'bc:92:6b',
            'bc:9f:ef', 'bc:a9:20', 'bc:d0:74', 'bc:ec:5d', 'c0:1a:da',
            'c0:25:a2', 'c0:33:5e', 'c0:63:94', 'c0:84:7d', 'c0:9a:d0',
            'c0:b6:58', 'c0:cc:f8', 'c0:ce:cd', 'c0:d0:12', 'c0:f2:fb',
            'c4:2c:03', 'c4:61:8b', 'c4:b3:01', 'c8:2a:14', 'c8:33:4b',
            'c8:69:cd', 'c8:6f:1d', 'c8:85:50', 'c8:89:f3', 'c8:b5:ad',
            'c8:bc:c8', 'c8:d0:83', 'c8:e0:eb', 'cc:08:8d', 'cc:20:e8',
            'cc:25:ef', 'cc:29:f5', 'cc:44:63', 'cc:4463', 'cc:78:5f',
            'cc:c7:60', 'd0:03:4b', 'd0:23:db', 'd0:25:98', 'd0:33:11',
            'd0:81:7a', 'd0:a6:37', 'd0:c5:f3', 'd0:d2:b0', 'd0:e1:40',
            'd4:61:9d', 'd4:9a:20', 'd4:a3:3d', 'd4:dc:cd', 'd4:f4:6f',
            'd8:00:4d', 'd8:1c:79', 'd8:30:62', 'd8:96:95', 'd8:9e:3f',
            'd8:a2:5e', 'd8:bb:2c', 'd8:cf:9c', 'd8:d1:cb', 'dc:2b:2a',
            'dc:2b:61', 'dc:37:18', 'dc:3b:48', 'dc:56:e7', 'dc:86:d8',
            'dc:9b:9c', 'dc:a4:ca', 'dc:a9:04', 'dc:d3:a2', 'dc:e4:cc',
            'e0:05:c5', 'e0:66:78', 'e0:ac:cb', 'e0:b5:2d', 'e0:b9:a5',
            'e0:c7:67', 'e0:c9:7a', 'e0:f5:c6', 'e0:f8:47', 'e4:25:e7',
            'e4:8b:7f', 'e4:9a:79', 'e4:c6:3d', 'e4:ce:8f', 'e4:e4:ab',
            'e8:04:0b', 'e8:06:88', 'e8:80:2e', 'e8:8d:28', 'ec:35:86',
            'ec:85:2f', 'f0:18:98', 'f0:24:75', 'f0:5c:19', 'f0:72:8c',
            'f0:98:9d', 'f0:99:b6', 'f0:b4:79', 'f0:c1:f1', 'f0:cb:a1',
            'f0:d1:a9', 'f0:db:e2', 'f0:dc:e2', 'f0:f6:1c', 'f4:0f:24',
            'f4:1b:a1', 'f4:37:b7', 'f4:5c:89', 'f4:f1:5a', 'f4:f9:51',
            'f8:1e:df', 'f8:27:93', 'f8:2d:7c', 'f8:95:c7', 'f8:cf:c5',
            'f8:d0:bd', 'f8:e9:4e', 'fc:25:3f', 'fc:2a:9c', 'fc:64:ba',
            'fc:e9:98', 'fc:fc:48'
        ]
        
        # Normalize BSSID format
        bssid_normalized = bssid.upper().replace('-', ':')
        bssid_prefix = ':'.join(bssid_normalized.split(':')[:3])
        
        return bssid_prefix in apple_oui_prefixes
    
    def is_iphone_hotspot(self, ssid, bssid=None):
        """Check if network is an iPhone hotspot using multiple detection methods"""
        if not ssid:
            return False
        
        # Method 1: SSID pattern matching
        for pattern in self.iphone_patterns:
            if re.match(pattern, ssid, re.IGNORECASE):
                return True
        
        # Method 2: Check if MAC address belongs to Apple
        if bssid and self.is_apple_mac_address(bssid):
            # If it's an Apple device, check for hotspot characteristics:
            # - Usually on 2.4GHz (channels 1-11)
            # - Often has strong signal (personal hotspot nearby)
            # - SSID doesn't match typical router patterns
            
            # Check if SSID looks like a personal hotspot (not a router)
            router_keywords = ['router', 'wifi', 'network', 'home', 'guest', 'office', 'linksys', 'netgear', 'tp-link', 'asus']
            is_router_like = any(keyword in ssid.lower() for keyword in router_keywords)
            
            if not is_router_like:
                # Likely a personal hotspot
                return True
        
        return False
    
    def get_wifi_interface(self):
        """Get the WiFi interface name (usually en0 or en1)"""
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            lines = result.stdout.split("\n")
            for i, line in enumerate(lines):
                if "Wi-Fi" in line or "AirPort" in line:
                    if i + 1 < len(lines):
                        device_line = lines[i + 1]
                        if "Device:" in device_line:
                            return device_line.split("Device:")[1].strip()
            
            return "en0"  # Default fallback
        except Exception:
            return "en0"
    
    def disconnect_wifi(self):
        """Disconnect from current WiFi network"""
        try:
            interface = self.get_wifi_interface()
            subprocess.run(
                ["networksetup", "-setairportpower", interface, "off"],
                check=True,
                capture_output=True,
                timeout=5
            )
            time.sleep(1)
            subprocess.run(
                ["networksetup", "-setairportpower", interface, "on"],
                check=True,
                capture_output=True,
                timeout=5
            )
            self.status_update.emit("Disconnected from WiFi")
            return True
        except Exception as e:
            self.status_update.emit(f"Error disconnecting: {e}")
            return False
    
    def block_hotspot(self, ssid):
        """Block iPhone hotspot"""
        try:
            self.hotspot_detected.emit(ssid)
            self.disconnect_wifi()
            self.blocked_networks.add(ssid)
            self.hotspot_blocked.emit(ssid)
            self.status_update.emit(f"🚫 BLOCKED: {ssid}")
            return True
        except Exception as e:
            self.status_update.emit(f"Error blocking: {e}")
            return False
    
    def scan_nearby_networks(self):
        """Scan for nearby WiFi networks with detailed info (active scanning)"""
        try:
            interface = self.get_wifi_interface()
            # Use airport utility for scanning
            airport_path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            
            result = subprocess.run(
                [airport_path, interface, "scan"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            networks = []
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        ssid = parts[0]
                        bssid = parts[1] if len(parts) > 1 else ""
                        rssi = parts[2] if len(parts) > 2 else "0"
                        channel = parts[3] if len(parts) > 3 else ""
                        
                        if ssid and ssid != self.last_ssid:
                            networks.append({
                                'ssid': ssid,
                                'bssid': bssid,
                                'rssi': rssi,
                                'channel': channel
                            })
            
            return networks
        except Exception as e:
            # Fallback: try system_profiler for more detailed info
            try:
                result = subprocess.run(
                    ['system_profiler', 'SPAirPortDataType'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                networks = []
                current_network = {}
                
                for line in result.stdout.split('\n'):
                    line_stripped = line.strip()
                    
                    if 'SSID:' in line_stripped:
                        if current_network and 'ssid' in current_network:
                            networks.append(current_network)
                        current_network = {'ssid': line_stripped.split('SSID:')[1].strip()}
                    elif 'BSSID:' in line_stripped and current_network:
                        current_network['bssid'] = line_stripped.split('BSSID:')[1].strip()
                    elif 'RSSI:' in line_stripped and current_network:
                        current_network['rssi'] = line_stripped.split('RSSI:')[1].strip()
                    elif 'Channel:' in line_stripped and current_network:
                        current_network['channel'] = line_stripped.split('Channel:')[1].strip()
                
                if current_network and 'ssid' in current_network:
                    networks.append(current_network)
                
                return networks
            except Exception:
                return []
    
    def run(self):
        """Monitor for iPhone hotspots with active scanning"""
        self.running = True
        self.status_update.emit("Hotspot blocker started - Active scanning enabled")
        
        while self.running:
            try:
                if self.enabled:
                    # Check current connection
                    current_ssid = self.get_current_ssid()
                    
                    if current_ssid and current_ssid != self.last_ssid:
                        self.last_ssid = current_ssid
                        
                        if self.is_iphone_hotspot(current_ssid):
                            if current_ssid not in self.blocked_networks:
                                self.block_hotspot(current_ssid)
                        else:
                            self.status_update.emit(f"Connected: {current_ssid}")
                    
                    # Active scan for nearby hotspots (every 10 seconds)
                    if int(time.time()) % 10 == 0:
                        nearby_networks = self.scan_nearby_networks()
                        for network in nearby_networks:
                            # Handle both dict and string formats
                            if isinstance(network, dict):
                                ssid = network.get('ssid', '')
                                bssid = network.get('bssid', '')
                            else:
                                ssid = network
                                bssid = None
                            
                            if self.is_iphone_hotspot(ssid, bssid):
                                if ssid not in self.blocked_networks:
                                    detection_method = "MAC address" if bssid and self.is_apple_mac_address(bssid) else "SSID pattern"
                                    self.status_update.emit(f"⚠️ WARNING: iPhone hotspot '{ssid}' detected nearby! (Method: {detection_method})")
                                    self.blocked_networks.add(ssid)
                                    self.hotspot_detected.emit(ssid)
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                self.status_update.emit(f"Monitor error: {e}")
                time.sleep(5)
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.status_update.emit("Hotspot blocker stopped")
