#!/usr/bin/env python3
"""
LoopbackShark Pattern Analyzer - Historical Pattern Recognition
Analyzes StealthShark historical loopback captures to identify common patterns
AIMF LLC - Advanced Network Analytics
"""

import os
import sys
import json
import glob
import subprocess
import logging
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict, Counter
import statistics

class HistoricalPatternAnalyzer:
    """Analyzes historical StealthShark loopback captures for pattern recognition"""
    
    def __init__(self, stealthshark_root=None):
        if stealthshark_root is None:
            # Auto-detect StealthShark root directory
            current_dir = Path(__file__).parent
            stealthshark_root = current_dir.parent
        self.logger = logging.getLogger("PatternAnalyzer")
        self.stealthshark_root = Path(stealthshark_root)
        self.capture_dir = self.stealthshark_root / "pcap_captures"
        self.patterns_dir = Path("./pattern_templates")
        self.patterns_dir.mkdir(exist_ok=True)
        
        # Pattern storage
        self.port_patterns = defaultdict(list)
        self.time_patterns = defaultdict(list)
        self.application_signatures = defaultdict(list)
        self.connection_behaviors = defaultdict(list)
        
        self.logger.info(f"Historical Pattern Analyzer initialized for: {self.stealthshark_root}")
        
    def find_loopback_captures(self, days_back=14):
        """Find all loopback capture files from the past N days"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_back)
            loopback_files = []
            
            # Search for loopback pcap files
            pcap_pattern = str(self.capture_dir / "*/loopback/*.pcap")
            found_files = glob.glob(pcap_pattern)
            
            self.logger.info(f"Found {len(found_files)} potential loopback capture files")
            
            for file_path in found_files:
                try:
                    # Extract date from filename (format: YYYYMMDD_HHMMSS)
                    filename = Path(file_path).name
                    if "-ch-loopback.pcap" in filename:
                        date_str = filename.split("-ch-loopback.pcap")[0]
                        file_date = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                        
                        if file_date >= cutoff_date:
                            file_size = Path(file_path).stat().st_size
                            if file_size > 0:  # Only include non-empty files
                                loopback_files.append({
                                    'path': file_path,
                                    'date': file_date,
                                    'size': file_size
                                })
                                
                except Exception as e:
                    self.logger.warning(f"Could not parse date from {filename}: {e}")
                    
            self.logger.info(f"Found {len(loopback_files)} valid loopback captures from last {days_back} days")
            return sorted(loopback_files, key=lambda x: x['date'])
            
        except Exception as e:
            self.logger.error(f"Error finding loopback captures: {e}")
            return []
            
    def analyze_pcap_file(self, file_path):
        """Analyze a single PCAP file for loopback patterns"""
        try:
            self.logger.info(f"Analyzing PCAP: {file_path}")
            
            # Use tshark to extract loopback traffic details
            cmd = [
                "tshark", "-r", file_path,
                "-Y", "ip.src==127.0.0.1 or ip.dst==127.0.0.1",  # Loopback filter
                "-T", "json",
                "-e", "frame.time_relative",
                "-e", "tcp.srcport", "-e", "tcp.dstport",
                "-e", "udp.srcport", "-e", "udp.dstport",
                "-e", "frame.protocols", "-e", "frame.len",
                "-e", "tcp.flags", "-e", "tcp.stream"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                self.logger.warning(f"tshark failed for {file_path}: {result.stderr}")
                return {}
                
            if not result.stdout.strip():
                self.logger.info(f"No loopback traffic found in {file_path}")
                return {}
                
            # Parse JSON output
            packets = json.loads(result.stdout) if result.stdout else []
            
            patterns = {
                'total_packets': len(packets),
                'ports': set(),
                'protocols': set(),
                'connections': set(),
                'timestamps': [],
                'packet_sizes': [],
                'tcp_flags': [],
                'streams': set()
            }
            
            for packet in packets:
                try:
                    layers = packet.get("_source", {}).get("layers", {})
                    
                    # Extract timing
                    if "frame.time_relative" in layers:
                        time_rel = float(layers["frame.time_relative"][0])
                        patterns['timestamps'].append(time_rel)
                    
                    # Extract ports
                    src_port = None
                    dst_port = None
                    
                    if "tcp.srcport" in layers:
                        src_port = int(layers["tcp.srcport"][0])
                        patterns['ports'].add(src_port)
                    if "tcp.dstport" in layers:
                        dst_port = int(layers["tcp.dstport"][0])
                        patterns['ports'].add(dst_port)
                        
                    if "udp.srcport" in layers:
                        src_port = int(layers["udp.srcport"][0])
                        patterns['ports'].add(src_port)
                    if "udp.dstport" in layers:
                        dst_port = int(layers["udp.dstport"][0])
                        patterns['ports'].add(dst_port)
                    
                    # Extract protocols
                    if "frame.protocols" in layers:
                        protocol_chain = layers["frame.protocols"][0]
                        patterns['protocols'].add(protocol_chain)
                        
                    # Extract frame size
                    if "frame.len" in layers:
                        size = int(layers["frame.len"][0])
                        patterns['packet_sizes'].append(size)
                        
                    # Extract TCP flags
                    if "tcp.flags" in layers:
                        flags = layers["tcp.flags"][0]
                        patterns['tcp_flags'].append(flags)
                        
                    # Extract TCP stream
                    if "tcp.stream" in layers:
                        stream = int(layers["tcp.stream"][0])
                        patterns['streams'].add(stream)
                        
                    # Create connection tuple
                    if src_port and dst_port:
                        connection = f"{src_port}->{dst_port}"
                        patterns['connections'].add(connection)
                        
                except Exception as e:
                    self.logger.warning(f"Error parsing packet: {e}")
                    continue
                    
            # Convert sets to lists for JSON serialization
            for key in ['ports', 'protocols', 'connections', 'streams']:
                patterns[key] = list(patterns[key])
                
            self.logger.info(f"Extracted patterns: {patterns['total_packets']} packets, {len(patterns['ports'])} unique ports")
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error analyzing PCAP {file_path}: {e}")
            return {}
            
    def generate_pattern_templates(self, historical_data):
        """Generate pattern templates from historical analysis"""
        try:
            self.logger.info("Generating pattern templates from historical data...")
            
            # Aggregate data across all files
            all_ports = []
            all_connections = []
            all_protocols = []
            port_frequency = Counter()
            connection_frequency = Counter()
            protocol_frequency = Counter()
            
            for file_data in historical_data:
                patterns = file_data.get('patterns', {})
                if patterns:
                    all_ports.extend(patterns.get('ports', []))
                    all_connections.extend(patterns.get('connections', []))
                    all_protocols.extend(patterns.get('protocols', []))
                    
                    # Count frequencies
                    for port in patterns.get('ports', []):
                        port_frequency[port] += 1
                    for conn in patterns.get('connections', []):
                        connection_frequency[conn] += 1
                    for proto in patterns.get('protocols', []):
                        protocol_frequency[proto] += 1
            
            # Generate templates
            templates = {
                'metadata': {
                    'generated': datetime.now().isoformat(),
                    'analysis_period_days': 14,
                    'files_analyzed': len(historical_data),
                    'total_patterns_found': len(all_ports)
                },
                'common_ports': self._identify_common_ports(port_frequency),
                'application_signatures': self._create_application_signatures(port_frequency, connection_frequency),
                'connection_patterns': self._analyze_connection_patterns(connection_frequency),
                'protocol_patterns': self._analyze_protocol_patterns(protocol_frequency),
                'behavioral_patterns': self._identify_behavioral_patterns(historical_data),
                'anomaly_thresholds': self._calculate_anomaly_thresholds(historical_data)
            }
            
            # Save templates
            template_file = self.patterns_dir / "loopback_pattern_templates.json"
            with open(template_file, 'w') as f:
                json.dump(templates, f, indent=2, default=str)
                
            self.logger.info(f"Pattern templates saved to: {template_file}")
            return templates
            
        except Exception as e:
            self.logger.error(f"Error generating pattern templates: {e}")
            return {}
            
    def _identify_common_ports(self, port_frequency, min_occurrences=2):
        """Identify commonly used ports"""
        common_ports = {}
        
        # Known application port mappings
        known_apps = {
            3000: "Node.js Development Server",
            8000: "Python HTTP Server",
            8080: "HTTP Proxy/Alternative",
            9000: "Development Tools",
            3001: "React Development Server",
            4000: "Development Server",
            5000: "Flask Development Server",
            8081: "Jenkins/Alternative HTTP",
            3306: "MySQL Database",
            5432: "PostgreSQL Database",
            6379: "Redis Database",
            27017: "MongoDB Database",
            8443: "HTTPS Alternative",
            9090: "Monitoring Tools"
        }
        
        for port, count in port_frequency.most_common():
            if count >= min_occurrences:
                common_ports[port] = {
                    'frequency': count,
                    'application': known_apps.get(port, f"Unknown Port {port}"),
                    'category': self._categorize_port(port),
                    'confidence': min(100, (count / max(port_frequency.values())) * 100)
                }
                
        return common_ports
        
    def _categorize_port(self, port):
        """Categorize port by range"""
        if port < 1024:
            return "system"
        elif port < 5000:
            return "application"
        elif port < 32768:
            return "user"
        else:
            return "ephemeral"
            
    def _create_application_signatures(self, port_freq, conn_freq):
        """Create application signature patterns"""
        signatures = {}
        
        # Development server signatures
        dev_ports = [3000, 3001, 8000, 8080, 9000, 4000, 5000]
        dev_signature = {
            'name': 'Development Servers',
            'ports': [p for p in dev_ports if p in port_freq],
            'pattern_type': 'development',
            'indicators': ['frequent_connections', 'http_traffic', 'websocket_upgrades']
        }
        if dev_signature['ports']:
            signatures['development_servers'] = dev_signature
            
        # Database signatures
        db_ports = [3306, 5432, 6379, 27017]
        db_signature = {
            'name': 'Database Services',
            'ports': [p for p in db_ports if p in port_freq],
            'pattern_type': 'database',
            'indicators': ['persistent_connections', 'regular_queries', 'connection_pooling']
        }
        if db_signature['ports']:
            signatures['database_services'] = db_signature
            
        return signatures
        
    def _analyze_connection_patterns(self, connection_frequency):
        """Analyze connection patterns"""
        patterns = {}
        
        for connection, frequency in connection_frequency.most_common(10):
            try:
                src, dst = connection.split('->')
                src_port, dst_port = int(src), int(dst)
                
                patterns[connection] = {
                    'frequency': frequency,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'direction': self._classify_connection_direction(src_port, dst_port),
                    'likely_application': self._guess_application_from_ports(src_port, dst_port)
                }
            except:
                continue
                
        return patterns
        
    def _classify_connection_direction(self, src_port, dst_port):
        """Classify connection direction based on port types"""
        if dst_port < 1024:
            return "to_system_service"
        elif dst_port in [3000, 8000, 8080, 9000]:
            return "to_dev_server"
        elif dst_port in [3306, 5432, 6379, 27017]:
            return "to_database"
        elif src_port > 32768:
            return "from_client"
        else:
            return "unknown"
            
    def _guess_application_from_ports(self, src_port, dst_port):
        """Guess application based on port combination"""
        if dst_port == 3000:
            return "Node.js Development"
        elif dst_port == 8080:
            return "HTTP Proxy/Development"
        elif dst_port in [3306, 5432, 6379, 27017]:
            return "Database Connection"
        elif dst_port == 8000:
            return "Python HTTP Server"
        else:
            return "Unknown Application"
            
    def _analyze_protocol_patterns(self, protocol_frequency):
        """Analyze protocol usage patterns"""
        patterns = {}
        
        for protocol, frequency in protocol_frequency.most_common():
            patterns[protocol] = {
                'frequency': frequency,
                'percentage': (frequency / sum(protocol_frequency.values())) * 100,
                'classification': self._classify_protocol(protocol)
            }
            
        return patterns
        
    def _classify_protocol(self, protocol_chain):
        """Classify protocol chain"""
        if 'http' in protocol_chain.lower():
            return 'web_traffic'
        elif 'tcp' in protocol_chain.lower():
            return 'tcp_application'
        elif 'udp' in protocol_chain.lower():
            return 'udp_application'
        else:
            return 'other'
            
    def _identify_behavioral_patterns(self, historical_data):
        """Identify behavioral patterns from timing and frequency"""
        behaviors = {}
        
        # Analyze timing patterns
        all_timestamps = []
        packet_counts = []
        
        for file_data in historical_data:
            patterns = file_data.get('patterns', {})
            if patterns.get('timestamps'):
                all_timestamps.extend(patterns['timestamps'])
                packet_counts.append(patterns.get('total_packets', 0))
                
        if packet_counts:
            behaviors['traffic_volume'] = {
                'avg_packets_per_session': statistics.mean(packet_counts),
                'median_packets_per_session': statistics.median(packet_counts),
                'max_packets_per_session': max(packet_counts),
                'sessions_analyzed': len(packet_counts)
            }
            
        return behaviors
        
    def _calculate_anomaly_thresholds(self, historical_data):
        """Calculate thresholds for anomaly detection"""
        thresholds = {}
        
        # Port usage thresholds
        all_ports = []
        packet_counts = []
        
        for file_data in historical_data:
            patterns = file_data.get('patterns', {})
            if patterns:
                all_ports.extend(patterns.get('ports', []))
                packet_counts.append(patterns.get('total_packets', 0))
                
        if packet_counts:
            thresholds['packet_volume'] = {
                'normal_range': [
                    max(0, statistics.mean(packet_counts) - 2 * statistics.stdev(packet_counts)) if len(packet_counts) > 1 else 0,
                    statistics.mean(packet_counts) + 2 * statistics.stdev(packet_counts) if len(packet_counts) > 1 else max(packet_counts)
                ],
                'high_activity_threshold': statistics.mean(packet_counts) + statistics.stdev(packet_counts) if len(packet_counts) > 1 else max(packet_counts)
            }
            
        if all_ports:
            unique_ports = len(set(all_ports))
            thresholds['port_diversity'] = {
                'normal_port_count': unique_ports,
                'unusual_threshold': unique_ports * 2  # Flag if 2x more ports than usual
            }
            
        return thresholds
        
    def run_analysis(self, days_back=14):
        """Run complete historical pattern analysis"""
        try:
            self.logger.info(f"Starting historical pattern analysis for last {days_back} days...")
            
            # Find all loopback captures
            loopback_files = self.find_loopback_captures(days_back)
            
            if not loopback_files:
                self.logger.warning("No loopback capture files found for analysis")
                return {}
                
            # Analyze each file
            historical_data = []
            
            for file_info in loopback_files:
                self.logger.info(f"Processing: {file_info['path']}")
                patterns = self.analyze_pcap_file(file_info['path'])
                
                historical_data.append({
                    'file_info': file_info,
                    'patterns': patterns
                })
                
            # Generate pattern templates
            templates = self.generate_pattern_templates(historical_data)
            
            # Save analysis results
            analysis_file = self.patterns_dir / "historical_analysis_results.json"
            with open(analysis_file, 'w') as f:
                json.dump(historical_data, f, indent=2, default=str)
                
            self.logger.info(f"Historical analysis complete. Results saved to {analysis_file}")
            return templates
            
        except Exception as e:
            self.logger.error(f"Error in historical analysis: {e}")
            return {}

def setup_pattern_logging():
    """Setup logging for pattern analysis"""
    log_dir = Path("./persistent_logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"pattern_analysis_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    logger = logging.getLogger("PatternAnalyzer")
    logger.info("Pattern analysis logging initialized")
    return logger

def main():
    """Main pattern analysis entry point"""
    logger = setup_pattern_logging()
    
    try:
        print("🔍 LoopbackShark Historical Pattern Analysis")
        print("AIMF LLC - Advanced Network Analytics")
        print("")
        
        analyzer = HistoricalPatternAnalyzer()
        templates = analyzer.run_analysis(days_back=14)
        
        if templates:
            print(f"✅ Pattern analysis complete!")
            print(f"📊 Found patterns for {len(templates.get('common_ports', {}))} common ports")
            print(f"🎯 Identified {len(templates.get('application_signatures', {}))} application signatures")
            print(f"📁 Templates saved to: ./pattern_templates/")
        else:
            print("⚠️ No patterns could be extracted from historical data")
            
    except Exception as e:
        logger.error(f"Pattern analysis failed: {e}")
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
