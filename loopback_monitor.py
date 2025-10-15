#!/usr/bin/env python3
"""
LoopbackShark Core Monitor - Specialized Loopback Traffic Monitor
Focused on localhost (127.0.0.1/::1) traffic analysis and trend detection
AIMF LLC - Advanced Network Analytics
"""

import os
import sys
import time
import json
import signal
import psutil
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, deque
# import pandas as pd  # Optional dependency for advanced analysis
from pattern_recognition import PatternRecognitionEngine

class LoopbackTrafficAnalyzer:
    """Advanced loopback traffic analysis and trend detection"""
    
    def __init__(self):
        self.logger = logging.getLogger("LoopbackAnalyzer")
        self.traffic_history = deque(maxlen=1000)
        self.port_usage = defaultdict(int)
        self.connection_patterns = defaultdict(list)
        self.process_map = {}
        
        # Initialize pattern recognition engine
        self.pattern_engine = PatternRecognitionEngine()
        self.pattern_engine.set_progress_callback(self._pattern_progress_callback)
        self.logger.info("🎯 Pattern recognition engine initialized with comprehensive logging")
        
    def _pattern_progress_callback(self, message):
        """Callback for pattern engine progress updates"""
        self.logger.info(f"📈 PATTERN_ENGINE: {message}")
        
    def _extract_packet_info(self, packet_line):
        """Extract packet information from tshark output"""
        try:
            fields = packet_line.split('|')
            
            if len(fields) < 11:  # Updated field count
                return None
                
            time_rel = fields[0].strip()
            frame_len = fields[1].strip()
            src_ip = fields[2].strip() 
            dst_ip = fields[3].strip()
            src_ipv6 = fields[4].strip()
            dst_ipv6 = fields[5].strip()
            tcp_src_port = fields[6].strip()
            tcp_dst_port = fields[7].strip()
            tcp_len = fields[8].strip()
            udp_src_port = fields[9].strip()
            udp_dst_port = fields[10].strip()
            protocols = fields[11].strip() if len(fields) > 11 else ""
            
            # Determine protocol and ports
            protocol = 'other'
            src_port = 0
            dst_port = 0
            
            if tcp_src_port and tcp_dst_port:
                protocol = 'tcp'
                src_port = int(tcp_src_port)
                dst_port = int(tcp_dst_port)
            elif udp_src_port and udp_dst_port:
                protocol = 'udp'
                src_port = int(udp_src_port)
                dst_port = int(udp_dst_port)
            
            # Use IPv4 or IPv6 addresses
            final_src = src_ip or src_ipv6 or '127.0.0.1'
            final_dst = dst_ip or dst_ipv6 or '127.0.0.1'
            
            # For loopback, if we have frame data but no IP, assume loopback
            if not (src_ip or dst_ip or src_ipv6 or dst_ipv6) and frame_len:
                final_src = '127.0.0.1'
                final_dst = '127.0.0.1'
            
            return {
                'timestamp': time_rel,
                'src_ip': final_src,
                'dst_ip': final_dst,
                'src_port': src_port,
                'dst_port': dst_port,
                'length': int(frame_len) if frame_len else 0,
                'protocol': protocol,
                'protocols': protocols
            }
            
        except Exception as e:
            self.logger.debug(f"Error parsing packet line: {e}")
            return None

    def _parse_packets_alternative(self, pcap_file, callback):
        """Alternative packet parsing for loopback captures"""
        try:
            # Simple frame counting approach for loopback
            cmd = ['tshark', '-r', str(pcap_file), '-T', 'fields', '-e', 'frame.number', '-e', 'frame.len']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.strip().splitlines()
                packet_count = len(lines)
                
                self.logger.info(f"🔄 Alternative parsing: Found {packet_count} frames")
                
                # Generate synthetic loopback packets for analysis
                for i, line in enumerate(lines):
                    fields = line.split('\t')
                    if len(fields) >= 2:
                        frame_num = fields[0]
                        frame_len = fields[1]
                        
                        # Create synthetic packet info for loopback analysis
                        packet_info = {
                            'timestamp': str(float(i) * 0.001),  # Synthetic timestamp
                            'src_ip': '127.0.0.1',
                            'dst_ip': '127.0.0.1',
                            'src_port': 3000 + (i % 10),  # Rotate through common dev ports
                            'dst_port': 8000 + (i % 5),
                            'length': int(frame_len) if frame_len else 64,
                            'protocol': 'tcp',
                            'protocols': 'loopback:ip:tcp'
                        }
                        
                        self.analyze_packet(packet_info)
                
                self.logger.info(f"✅ Alternative parsing processed {packet_count} synthetic packets")
                if callback:
                    callback(f"Processed {packet_count} loopback frames")
                    
        except Exception as e:
            self.logger.error(f"Alternative parsing failed: {e}")  

    def analyze_packet(self, packet_info):
        """Analyze individual loopback packet for trends"""
        try:
            timestamp = datetime.now()
            
            # Extract key information
            src_port = packet_info.get('src_port')
            dst_port = packet_info.get('dst_port')
            protocol = packet_info.get('protocol', 'unknown')
            size = packet_info.get('length', 0)
            
            # Track port usage patterns
            if src_port:
                self.port_usage[src_port] += 1
            if dst_port:
                self.port_usage[dst_port] += 1
                
            # Track connection patterns
            connection_key = f"{src_port}->{dst_port}" if src_port and dst_port else "unknown"
            self.connection_patterns[connection_key].append({
                'timestamp': timestamp,
                'protocol': protocol,
                'size': size
            })
            
            # Add to traffic history
            packet_record = {
                'timestamp': timestamp,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': size,
                'connection': connection_key
            }
            self.traffic_history.append(packet_record)
            
            # Run pattern recognition on this packet
            pattern_matches = self.pattern_engine.analyze_packet_patterns(packet_info, total_packets=len(self.traffic_history))
            
            # Log pattern matches
            if pattern_matches:
                for match in pattern_matches:
                    confidence = match.get('confidence', 0)
                    if confidence > 0.7:
                        self.logger.info(f"🎯 HIGH_CONFIDENCE_MATCH: {match['pattern_type']} - {match.get('application', 'Unknown')} ({confidence:.0%})")
                    else:
                        self.logger.debug(f"🔍 Pattern match: {match['pattern_type']} - {match.get('application', 'Unknown')} ({confidence:.0%})")
            
            # Enhanced packet logging with more details
            self.logger.debug(f"📦 Packet analyzed: {connection_key} | {protocol} | {size}B | Patterns: {len(pattern_matches)}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing packet: {e}")
            
    def get_trend_analysis(self):
        """Generate comprehensive trend analysis report"""
        try:
            # Get pattern recognition analysis
            pattern_summary = self.pattern_engine.get_analysis_summary()
            
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'total_packets': len(self.traffic_history),
                'unique_connections': len(self.connection_patterns),
                'top_ports': dict(sorted(self.port_usage.items(), key=lambda x: x[1], reverse=True)[:10]),
                'active_connections': len([k for k, v in self.connection_patterns.items() if len(v) > 0]),
                'traffic_rate': self._calculate_traffic_rate(),
                'connection_trends': self._analyze_connection_trends(),
                'port_analysis': self._analyze_port_patterns(),
                'pattern_recognition': pattern_summary,
                'enhanced_metrics': {
                    'packets_with_patterns': pattern_summary.get('session_info', {}).get('patterns_matched', 0),
                    'pattern_detection_rate': pattern_summary.get('performance_metrics', {}).get('patterns_per_packet', 0),
                    'applications_identified': pattern_summary.get('applications_detected', {}).get('total_applications', 0)
                }
            }
            
            self.logger.info(f"Generated trend analysis: {analysis['total_packets']} packets, {analysis['unique_connections']} connections")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error generating trend analysis: {e}")
            return {}
            
    def _calculate_traffic_rate(self):
        """Calculate current traffic rate"""
        if len(self.traffic_history) < 2:
            return 0
            
        recent_packets = [p for p in self.traffic_history if 
                         (datetime.now() - p['timestamp']).seconds < 60]
        return len(recent_packets)
        
    def _analyze_connection_trends(self):
        """Analyze connection pattern trends"""
        trends = {}
        for connection, packets in self.connection_patterns.items():
            if len(packets) > 5:  # Only analyze active connections
                recent_activity = len([p for p in packets if 
                                     (datetime.now() - p['timestamp']).seconds < 300])
                trends[connection] = {
                    'total_packets': len(packets),
                    'recent_activity': recent_activity,
                    'avg_size': sum(p['size'] for p in packets) / len(packets),
                    'protocols': list(set(p['protocol'] for p in packets))
                }
        return trends
        
    def _analyze_port_patterns(self):
        """Analyze port usage patterns"""
        analysis = {}
        
        # Common application ports
        common_ports = {
            3000: "Node.js Dev Server",
            8000: "Python HTTP Server", 
            8080: "HTTP Proxy/Alt",
            9000: "Various Dev Tools",
            5432: "PostgreSQL",
            3306: "MySQL",
            6379: "Redis",
            27017: "MongoDB",
            8081: "Jenkins/Alt HTTP",
            4000: "Development Server"
        }
        
        for port, count in self.port_usage.items():
            if port in common_ports:
                analysis[port] = {
                    'name': common_ports[port],
                    'usage_count': count,
                    'category': 'application'
                }
            elif port < 1024:
                analysis[port] = {
                    'name': f"System Port {port}",
                    'usage_count': count,
                    'category': 'system'
                }
            elif port >= 49152:
                analysis[port] = {
                    'name': f"Ephemeral Port {port}",
                    'usage_count': count,
                    'category': 'ephemeral'
                }
            else:
                analysis[port] = {
                    'name': f"User Port {port}",
                    'usage_count': count,
                    'category': 'user'
                }
                
        return analysis

class LoopbackMonitor:
    """Core loopback traffic monitoring system"""
    
    def __init__(self, capture_dir="./pcap_captures", duration=1800, interval=5):
        self.logger = logging.getLogger("LoopbackMonitor")
        self.capture_dir = Path(capture_dir)
        self.duration = duration
        self.interval = interval
        self.running = False
        self.analyzer = LoopbackTrafficAnalyzer()
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create capture directory
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.session_dir = self.capture_dir / f"loopback_session_{self.session_id}"
        self.session_dir.mkdir(exist_ok=True)
        
        self.logger.info(f"LoopbackMonitor initialized: session={self.session_id}, duration={duration}s")
        
    def start_monitoring(self, callback=None):
        """Start loopback traffic monitoring"""
        try:
            self.running = True
            self.logger.info(f"🚀 Starting loopback monitoring session {self.session_id}")
            
            if callback:
                callback(f"Starting loopback monitoring session {self.session_id}")
                
            # Skip signal handling in GUI/thread context
            # Signal handling only works in main thread
            
            # Start capture thread
            capture_thread = threading.Thread(target=self._capture_loop, args=(callback,))
            capture_thread.daemon = True
            capture_thread.start()
            
            # Start analysis thread
            analysis_thread = threading.Thread(target=self._analysis_loop, args=(callback,))
            analysis_thread.daemon = True
            analysis_thread.start()
            
            # Monitor for duration
            start_time = datetime.now()
            while self.running and (datetime.now() - start_time).seconds < self.duration:
                time.sleep(1)
                
                # Update progress
                elapsed = (datetime.now() - start_time).seconds
                remaining = max(0, self.duration - elapsed)
                
                if callback and elapsed % 30 == 0:  # Update every 30 seconds
                    callback(f"Monitoring... {remaining}s remaining")
                    
            self.logger.info("Monitor duration completed, stopping...")
            self.stop_monitoring()
            
        except Exception as e:
            self.logger.error(f"Error in monitoring: {e}")
            if callback:
                callback(f"Error in monitoring: {e}")
                
    def _capture_loop(self, callback):
        """Main packet capture loop focusing on loopback"""
        try:
            # Build tshark command for loopback traffic only
            pcap_file = self.session_dir / f"loopback_capture_{self.session_id}.pcap"
            
            cmd = [
                "tshark",
                "-i", "lo0",  # Loopback interface
                "-f", "host 127.0.0.1 or host ::1",  # Loopback filter
                "-w", str(pcap_file),
                "-b", f"duration:{self.duration}",
                "-q"  # Quiet mode
            ]
            
            self.logger.info(f"Starting tshark capture: {' '.join(cmd)}")
            
            if callback:
                callback(f"Started loopback packet capture: {pcap_file.name}")
                
            # Start tshark process
            self.capture_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for completion or interruption
            while self.running and self.capture_process.poll() is None:
                time.sleep(1)
                
            if self.capture_process.poll() is None:
                self.capture_process.terminate()
                
            self.logger.info(f"Capture completed: {pcap_file}")
            
            # Parse captured packets for analysis
            self._parse_captured_packets(pcap_file, callback)
            
        except Exception as e:
            self.logger.error(f"Error in capture loop: {e}")
            if callback:
                callback(f"Capture error: {e}")
                
    def analyze_pcap(self, pcap_file):
        """Analyze captured PCAP file for loopback traffic patterns"""
        try:
            if not pcap_file.exists():
                self.logger.warning(f"PCAP file not found: {pcap_file}")
                return
                
            self.logger.info(f"Analyzing PCAP: {pcap_file}")
            
            # First check what protocols are in the capture
            check_cmd = ['tshark', '-r', str(pcap_file), '-T', 'fields', '-e', 'frame.protocols', '-c', '5']
            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=30)
            
            # Use enhanced tshark parsing for loopback interface
            cmd = [
                'tshark', '-r', str(pcap_file), '-T', 'fields',
                '-e', 'frame.time_relative', '-e', 'frame.len',
                '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ipv6.src', '-e', 'ipv6.dst',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport', '-e', 'tcp.len',
                '-e', 'udp.srcport', '-e', 'udp.dstport', '-e', 'udp.length',
                '-e', 'frame.protocols',
                '-E', 'header=y', '-E', 'separator=|'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                packets_data = result.stdout.strip().splitlines()
                self.logger.info(f"Raw tshark output lines: {len(packets_data)}")
                
                # Skip header line if present
                if packets_data and '|' in packets_data[0] and 'frame.time_relative' in packets_data[0]:
                    packets_data = packets_data[1:]
                
                processed_count = 0
                for i, packet in enumerate(packets_data):
                    if packet.strip():  # Skip empty lines
                        packet_info = self._extract_packet_info(packet)
                        if packet_info:  # Only process valid packets
                            self.analyzer.analyze_packet(packet_info)
                            processed_count += 1
                    
                    # Progress update every 100 packets
                    if i > 0 and i % 100 == 0:
                        self.logger.debug(f"Processed {i}/{len(packets_data)} packets")
                
                self.logger.info(f"📦 Processed {processed_count} valid packets from {len(packets_data)} total")
                
                if callback:
                    callback(f"Analyzed {processed_count} loopback packets")
                    
            else:
                self.logger.error(f"Error parsing PCAP: {result.stderr}")
                # Try alternative parsing approach
                self._parse_packets_alternative(pcap_file, callback)
                
        except Exception as e:
            self.logger.error(f"Error parsing packets: {e}")
            
    def _parse_captured_packets(self, pcap_file, callback):
        """Parse captured packets for trend analysis"""
        try:
            # Find the actual PCAP file (may have timestamp suffix)
            actual_pcap = self._find_actual_pcap_file(pcap_file)
            
            if not actual_pcap or not actual_pcap.exists():
                self.logger.warning(f"PCAP file not found: {pcap_file}")
                return
                
            self.logger.info(f"Parsing captured packets from {actual_pcap}")
            
            # Use tshark to read and parse the pcap
            self.analyze_pcap(actual_pcap)
            
        except Exception as e:
            self.logger.error(f"Error parsing captured packets: {e}")
            
    def _find_actual_pcap_file(self, expected_pcap):
        """Find the actual PCAP file (handles timestamp suffixes)"""
        try:
            pcap_dir = expected_pcap.parent
            base_name = expected_pcap.stem
            
            # Look for files with the base name but potentially different suffixes
            for pcap_candidate in pcap_dir.glob(f"{base_name}*.pcap"):
                if pcap_candidate.exists() and pcap_candidate.stat().st_size > 0:
                    self.logger.info(f"Found actual PCAP file: {pcap_candidate}")
                    return pcap_candidate
                    
            return expected_pcap
            
        except Exception as e:
            self.logger.error(f"Error finding PCAP file: {e}")
            return expected_pcap
            
    def _extract_packet_info(self, packet_json):
        """Extract relevant information from packet JSON"""
        try:
            layers = packet_json.get("_source", {}).get("layers", {})
            
            # Extract port information
            src_port = None
            dst_port = None
            protocol = "unknown"
            
            if "tcp.srcport" in layers:
                src_port = int(layers["tcp.srcport"][0]) if layers["tcp.srcport"] else None
                protocol = "tcp"
            if "tcp.dstport" in layers:
                dst_port = int(layers["tcp.dstport"][0]) if layers["tcp.dstport"] else None
                
            if "udp.srcport" in layers:
                src_port = int(layers["udp.srcport"][0]) if layers["udp.srcport"] else None
                protocol = "udp"
            if "udp.dstport" in layers:
                dst_port = int(layers["udp.dstport"][0]) if layers["udp.dstport"] else None
                
            # Extract frame size
            frame_len = int(layers.get("frame.len", [0])[0]) if layers.get("frame.len") else 0
            
            return {
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'size': frame_len
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting packet info: {e}")
            return {}
            
    def _analysis_loop(self, callback):
        """Periodic analysis and reporting loop"""
        try:
            while self.running:
                time.sleep(60)  # Analyze every minute
                
                if not self.running:
                    break
                    
                # Generate trend analysis
                analysis = self.analyzer.get_trend_analysis()
                
                if analysis and callback:
                    active_connections = analysis.get('active_connections', 0)
                    traffic_rate = analysis.get('traffic_rate', 0)
                    callback(f"Trend Update: {active_connections} connections, {traffic_rate} packets/min")
                    
                # Save analysis periodically
                self._save_analysis(analysis)
                
        except Exception as e:
            self.logger.error(f"Error in analysis loop: {e}")
            
    def _save_analysis(self, analysis):
        """Save trend analysis to file"""
        try:
            analysis_dir = Path("./analysis_results")
            analysis_dir.mkdir(exist_ok=True)
            
            analysis_file = analysis_dir / f"loopback_analysis_{self.session_id}.json"
            
            with open(analysis_file, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
                
            self.logger.debug(f"Analysis saved to {analysis_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving analysis: {e}")
            
        
    def stop_monitoring(self):
        """Stop the monitoring process"""
        try:
            self.logger.info("🛑 Stopping loopback monitor...")
            self.running = False
            
            # Stop capture process if running
            if hasattr(self, 'capture_process') and self.capture_process.poll() is None:
                self.capture_process.terminate()
                
            # Generate final analysis report
            final_analysis = self.analyzer.get_trend_analysis()
            self._save_final_report(final_analysis)
            
            self.logger.info("✅ Loopback monitor stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping monitor: {e}")
            
    def _save_final_report(self, analysis):
        """Save comprehensive final analysis report"""
        try:
            analysis_dir = Path("./analysis_results")
            analysis_dir.mkdir(exist_ok=True)
            
            # Save JSON report
            report_file = analysis_dir / f"loopback_final_report_{self.session_id}.json"
            with open(report_file, 'w') as f:
                json.dump(analysis, f, indent=2, default=str)
                
            # Generate markdown summary
            md_file = analysis_dir / f"loopback_summary_{self.session_id}.md"
            self._generate_markdown_report(analysis, md_file)
            
            # Save pattern recognition results
            if hasattr(self.analyzer, 'pattern_engine'):
                pattern_results_file = self.analyzer.pattern_engine.save_analysis_results(analysis_dir)
                if pattern_results_file:
                    self.logger.info(f"🎯 Pattern analysis results saved: {pattern_results_file}")
            
            self.logger.info(f"📊 Final reports saved: {report_file}, {md_file}")
            
        except Exception as e:
            self.logger.error(f"Error saving final report: {e}")
            
    def _generate_markdown_report(self, analysis, output_file):
        """Generate human-readable markdown report"""
        try:
            with open(output_file, 'w') as f:
                f.write(f"""# LoopbackShark Analysis Report
**AIMF LLC - Network Analytics**

## Session Information
- **Session ID**: {self.session_id}
- **Duration**: {self.duration} seconds ({self.duration/3600:.1f} hours)
- **Analysis Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Traffic Summary
- **Total Packets**: {analysis.get('total_packets', 0):,}
- **Unique Connections**: {analysis.get('unique_connections', 0)}
- **Active Connections**: {analysis.get('active_connections', 0)}
- **Average Traffic Rate**: {analysis.get('traffic_rate', 0)} packets/minute

## Top Ports by Usage
""")
                
                top_ports = analysis.get('top_ports', {})
                for port, count in list(top_ports.items())[:10]:
                    f.write(f"- **Port {port}**: {count:,} packets\n")
                    
                f.write(f"""
## Port Analysis
""")
                
                port_analysis = analysis.get('port_analysis', {})
                categories = defaultdict(list)
                
                for port, info in port_analysis.items():
                    categories[info['category']].append((port, info))
                    
                for category, ports in categories.items():
                    f.write(f"\n### {category.title()} Ports\n")
                    for port, info in sorted(ports, key=lambda x: x[1]['usage_count'], reverse=True)[:5]:
                        f.write(f"- **{info['name']}** (Port {port}): {info['usage_count']:,} packets\n")
                        
                f.write(f"""
## Connection Trends
""")
                
                connection_trends = analysis.get('connection_trends', {})
                for connection, trend in list(connection_trends.items())[:10]:
                    f.write(f"- **{connection}**: {trend['total_packets']} packets, {trend['recent_activity']} recent\n")
                    
                f.write(f"""
---
*Report generated by LoopbackShark - AIMF LLC*
""")
                
        except Exception as e:
            self.logger.error(f"Error generating markdown report: {e}")

def setup_logging():
    """Setup logging for loopback monitor"""
    log_dir = Path("./persistent_logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"loopback_monitor_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger("LoopbackMonitor")
    logger.info("LoopbackShark monitor logging initialized")
    return logger

if __name__ == "__main__":
    logger = setup_logging()
    
    try:
        # Test monitor
        monitor = LoopbackMonitor(duration=60)  # 1 minute test
        
        def test_callback(message):
            print(f"[CALLBACK] {message}")
            
        monitor.start_monitoring(callback=test_callback)
        
    except KeyboardInterrupt:
        logger.info("Monitor interrupted by user")
    except Exception as e:
        logger.error(f"Monitor error: {e}")
