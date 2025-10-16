# 📡 What Happens During Network Monitoring

## Overview
The monitoring system runs continuously in a background thread, scanning for WiFi networks every 5 seconds and analyzing them for threats.

## 🔄 Monitoring Cycle (Every 5 Seconds)

### 1. **Scan Initiation** 🔍
```
🔍 Scan #1 - 21:30:15
```
- Timestamp logged
- Scan counter incremented
- WiFi scan command executed

### 2. **Network Discovery** 📡
```
📡 Found 5 networks
```
- Scans all WiFi networks in range
- Parses SSID, BSSID, signal strength, channel, security
- Returns list of discovered networks

### 3. **Network Analysis** 🔬
For each network found, the system logs:
```
  • MyHomeNetwork       | AA:BB:CC:DD:EE:FF | -45dBm | 🛡️ PROTECTED
  • OfficeWiFi          | 11:22:33:44:55:66 | -62dBm | ✅ SAFE
  • Starbucks WiFi      | 77:88:99:AA:BB:CC | -75dBm | ⚠️ SUSPICIOUS
  • Neighbor_Network    | DD:EE:FF:00:11:22 | -68dBm | ✅ SAFE
  • xfinitywifi         | 33:44:55:66:77:88 | -80dBm | ⚠️ SUSPICIOUS
```

#### Status Determination:
- **🛡️ PROTECTED**: Matches your legitimate BSSID (auto-protected)
- **✅ SAFE**: Secure network (WPA2/WPA3), no suspicious patterns
- **⚠️ SUSPICIOUS**: Open network OR suspicious name patterns
- **🚨 THREAT**: Pineapple attack detected OR blacklisted BSSID

### 4. **Threat Detection** 🚨
If a threat is detected:
```
  🚨 THREAT DETECTED: MyHomeNetwork (XX:YY:ZZ:11:22:33)
```

**Threat Conditions:**
1. **Pineapple Attack**: Same SSID as protected network but different BSSID
2. **Suspicious + Open**: Network name contains "pineapple", "free wifi", "public" AND has no password
3. **Blacklisted**: BSSID is in the blacklist

### 5. **Table Update** 📊
- Updates the Monitor tab table with all networks
- Color codes rows based on status:
  - Green background: Protected
  - Red background: Threat
  - Yellow background: Suspicious
  - Default: Safe

### 6. **Scan Complete** ✅
```
✅ Scan complete. Next scan in 5 seconds...
```
- Waits 5 seconds
- Repeats cycle

## 📋 Verbose Log Output Example

```
🚀 Network monitoring started
🛡️ Protected network: MyHomeNetwork (AA:BB:CC:DD:EE:FF)
⏱️ Scan interval: 5 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔍 Scan #1 - 21:30:15
📡 Found 5 networks
  • MyHomeNetwork       | AA:BB:CC:DD:EE:FF | -45dBm | 🛡️ PROTECTED
  • OfficeWiFi          | 11:22:33:44:55:66 | -62dBm | ✅ SAFE
  • Starbucks WiFi      | 77:88:99:AA:BB:CC | -75dBm | ⚠️ SUSPICIOUS
  • Neighbor_Network    | DD:EE:FF:00:11:22 | -68dBm | ✅ SAFE
  • xfinitywifi         | 33:44:55:66:77:88 | -80dBm | ⚠️ SUSPICIOUS
✅ Scan complete. Next scan in 5 seconds...

🔍 Scan #2 - 21:30:20
📡 Found 6 networks
  • MyHomeNetwork       | AA:BB:CC:DD:EE:FF | -45dBm | 🛡️ PROTECTED
  • MyHomeNetwork       | XX:YY:ZZ:11:22:33 | -50dBm | 🚨 THREAT
  🚨 THREAT DETECTED: MyHomeNetwork (XX:YY:ZZ:11:22:33)
  • OfficeWiFi          | 11:22:33:44:55:66 | -62dBm | ✅ SAFE
  • Starbucks WiFi      | 77:88:99:AA:BB:CC | -75dBm | ⚠️ SUSPICIOUS
  • Neighbor_Network    | DD:EE:FF:00:11:22 | -68dBm | ✅ SAFE
  • xfinitywifi         | 33:44:55:66:77:88 | -80dBm | ⚠️ SUSPICIOUS
✅ Scan complete. Next scan in 5 seconds...
```

## 🎯 What Gets Logged

### Startup Logs
```
🚀 Network monitoring started
🛡️ Protected network: [Your Network] ([Your BSSID])
⏱️ Scan interval: 5 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Per-Scan Logs
```
🔍 Scan #[N] - [HH:MM:SS]
📡 Found [N] networks
  • [SSID] | [BSSID] | [Signal]dBm | [Status]
✅ Scan complete. Next scan in 5 seconds...
```

### Threat Logs
```
🚨 THREAT DETECTED: [SSID] ([BSSID])
```

### Error Logs
```
❌ Monitor error: [Error message]
⚠️ Scan failed: [Reason]
```

## 🔍 Demo Mode Behavior

In demo mode, the monitor:
1. **Returns 5 sample networks** instead of real WiFi scan
2. **Shows realistic data**:
   - MyHomeNetwork (Protected)
   - OfficeWiFi (Safe)
   - Starbucks WiFi (Suspicious - Open)
   - Neighbor_Network (Safe)
   - xfinitywifi (Suspicious - Open)
3. **Logs all activity** to the Monitoring Log
4. **Updates every 5 seconds** with same data
5. **Safe for screenshots** - no real network exposure

## 🧪 Testing the Monitor

### Manual Test
1. Launch demo mode: `./launch_demo.sh`
2. Go to **Monitor tab**
3. Watch the **Monitoring Log (Verbose)** section
4. You should see:
   - Startup messages
   - Scan #1, #2, #3... every 5 seconds
   - 5 networks listed each time
   - Status indicators for each network

### What You Should See

**Network Table:**
| SSID | BSSID | Signal | Status |
|------|-------|--------|--------|
| MyHomeNetwork | AA:BB:CC:DD:EE:FF | -45 dBm | 🛡️ Protected |
| OfficeWiFi | 11:22:33:44:55:66 | -62 dBm | ✅ Safe |
| Starbucks WiFi | 77:88:99:AA:BB:CC | -75 dBm | ⚠️ Suspicious |
| Neighbor_Network | DD:EE:FF:00:11:22 | -68 dBm | ✅ Safe |
| xfinitywifi | 33:44:55:66:77:88 | -80 dBm | ⚠️ Suspicious |

**Monitoring Log:**
- Green text on black background
- Scrolling log of all scan activity
- Updates every 5 seconds
- Shows detailed network information

**Threat Log:**
- Red text on black background
- Only shows when threats detected
- Logs BSSID and reason

## 🚨 When a Real Threat Appears

If someone creates a fake "MyHomeNetwork":

1. **Detection**:
   ```
   🔍 Scan #5 - 21:30:35
   📡 Found 6 networks
     • MyHomeNetwork     | AA:BB:CC:DD:EE:FF | -45dBm | 🛡️ PROTECTED
     • MyHomeNetwork     | XX:YY:ZZ:11:22:33 | -50dBm | 🚨 THREAT
     🚨 THREAT DETECTED: MyHomeNetwork (XX:YY:ZZ:11:22:33)
   ```

2. **Alert**:
   - Popup notification appears
   - Threat log updated
   - Row highlighted in red

3. **Auto-Block** (if enabled):
   - BSSID added to blacklist
   - Traffic blocked from that MAC address
   - Saved to `blacklist.json`

## 💡 Key Points

1. **Continuous**: Runs 24/7 in background
2. **Automatic**: No user interaction needed
3. **Verbose**: Logs everything for transparency
4. **Real-time**: 5-second scan interval
5. **Smart**: Auto-protects your current network
6. **Persistent**: Blacklist survives restarts

## 🎬 Perfect for Demos

The verbose logging makes it perfect for:
- **Screenshots**: Shows active monitoring
- **Videos**: Demonstrates real-time scanning
- **Presentations**: Clear, readable output
- **Training**: Users can see what's happening
- **Debugging**: Full visibility into scan process

---

**The monitoring system is always watching, always protecting.** 🦈🛡️
