# 📡 Monitor Tab - How It Works

## Overview
The Monitor tab is the real-time network surveillance center of StealthShark. It continuously scans for WiFi networks and identifies potential threats.

## 🎯 Main Features

### 1. **Real-Time Network Scanning**
- Continuously scans for all WiFi networks in range
- Updates every 5 seconds (configurable in Settings)
- Shows live signal strength and security status

### 2. **Network Table Display**
The table shows 4 key columns:

| Column | Description |
|--------|-------------|
| **SSID** | Network name (e.g., "MyHomeNetwork", "Starbucks WiFi") |
| **BSSID** | Hardware MAC address of the access point (e.g., "AA:BB:CC:DD:EE:FF") |
| **Signal** | Signal strength in dBm (e.g., -45 dBm = strong, -80 dBm = weak) |
| **Status** | Security status: ✅ Safe, ⚠️ Suspicious, 🚨 Threat, 🛡️ Protected |

### 3. **Threat Detection Logic**

#### 🛡️ Protected Networks (Green)
- Networks in your trusted list
- Your current connected network (auto-protected)
- Marked with "TRUSTED" status
- **Never blocked automatically**

#### ✅ Safe Networks (White/Default)
- Normal networks with standard security
- WPA2/WPA3 encryption
- Unique SSIDs
- No suspicious patterns

#### ⚠️ Suspicious Networks (Yellow)
- Open networks (no password)
- Networks with common names like "Free WiFi", "Public"
- Duplicate SSIDs (multiple networks with same name)
- Weak security protocols

#### 🚨 Threat Networks (Red)
- **Pineapple Attack Detected**: Same SSID as your trusted network but different BSSID
- Networks matching known attack patterns
- BSSIDs in the blacklist
- **Automatically blocked** if auto-block is enabled

### 4. **Control Buttons**

#### 🔍 Scan Networks
- Performs immediate manual scan
- Updates the network table
- Useful for refreshing the view

#### ⏸️ Stop Monitoring / ▶️ Start Monitoring
- Toggle button to pause/resume continuous monitoring
- Stops background scanning when paused
- Resumes automatic 5-second interval when started

## 🔍 How Pineapple Detection Works

### The Attack Scenario
1. You connect to "MyHomeNetwork" (BSSID: AA:BB:CC:DD:EE:FF)
2. Attacker creates fake "MyHomeNetwork" (BSSID: XX:YY:ZZ:11:22:33)
3. Your device might accidentally connect to the fake one
4. Attacker can intercept your traffic

### StealthShark Protection
1. **Auto-Exclusion**: Your current network is automatically marked as trusted
2. **BSSID Verification**: Detects when same SSID has different BSSID
3. **Instant Alert**: Shows 🚨 threat indicator
4. **Auto-Block**: Adds malicious BSSID to blacklist
5. **Notification**: Popup alert warns you of the threat

## 📊 Network Status Colors

```
🛡️ PROTECTED (Green background)
   - Your trusted networks
   - Auto-protected current connection
   - Will never be blocked

✅ SAFE (Default)
   - Normal secure networks
   - No suspicious patterns
   - Standard WPA2/WPA3

⚠️ SUSPICIOUS (Yellow background)
   - Open networks
   - Common public names
   - Weak security
   - Requires manual review

🚨 THREAT (Red background)
   - Confirmed pineapple attack
   - Blacklisted BSSID
   - Duplicate SSID with different BSSID
   - Auto-blocked if enabled
```

## 🎬 Typical Usage Flow

### Normal Operation
1. Launch StealthShark
2. Monitor tab starts automatically
3. Your current network is auto-protected
4. Background scanning runs every 5 seconds
5. Table updates with nearby networks
6. All safe networks show ✅ status

### When Threat Detected
1. Suspicious network appears
2. System checks against blacklist
3. Verifies BSSID against known networks
4. If threat confirmed:
   - Shows 🚨 in Status column
   - Highlights row in red
   - Popup notification appears
   - Auto-adds to blacklist (if enabled)
   - Blocks traffic from that BSSID

### Manual Actions
- **Click on a network**: Select it for details
- **Right-click**: Context menu with options:
  - Add to blacklist
  - Mark as trusted
  - View details
  - Copy BSSID

## ⚙️ Configuration Options

### In Settings Tab
- **Scan Interval**: How often to scan (default: 5 seconds)
- **Auto-Block Threats**: Automatically blacklist detected threats
- **Threat Notifications**: Show popup alerts
- **Monitoring Duration**: How long to run (default: 6 hours)

## 🔒 Security Features

### Auto-Exclusion Protection
- Current network is **never** blocked
- Prevents accidental self-blocking
- Updates if you switch networks
- Shown with 🛡️ PROTECTED status

### Persistent Blacklist
- Blocked BSSIDs saved to `blacklist.json`
- Survives app restarts
- Syncs across devices (if using shared config)
- Can import/export via CSV

### Smart Detection
- Pattern matching for known attacks
- BSSID fingerprinting
- Signal strength analysis
- Temporal analysis (networks appearing/disappearing)

## 📝 Demo Mode Differences

In demo mode, the Monitor tab:
- Shows placeholder network data
- Doesn't perform actual WiFi scanning
- Uses sample BSSIDs and SSIDs
- Safe for screenshots/recordings
- All data is static

## 🎯 Best Practices

1. **Keep Monitoring Running**: Let it run in background
2. **Review Suspicious Networks**: Check yellow-flagged networks manually
3. **Update Blacklist**: Import threat lists from trusted sources
4. **Enable Auto-Block**: For automatic protection
5. **Check Regularly**: Glance at Monitor tab when connecting to new networks

## 🚨 What to Do When Threat Detected

1. **Don't Panic**: StealthShark has already blocked it
2. **Disconnect**: If you're on public WiFi, disconnect immediately
3. **Verify**: Check if it's a false positive
4. **Report**: Note the BSSID and location
5. **Update**: Share threat data with your team/community

---

**The Monitor tab is your real-time shield against WiFi attacks. It works silently in the background, protecting you 24/7.** 🦈🛡️
