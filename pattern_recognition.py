#!/usr/bin/env python3
"""
LoopbackShark Pattern Recognition Engine
Advanced pattern matching with comprehensive logging and progress tracking
AIMF LLC - Advanced Network Analytics
"""

import json
import logging
import time
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime, timedelta

class PatternRecognitionEngine:
    """Advanced pattern recognition with detailed logging and progress tracking"""
    
    def __init__(self):
        self.logger = logging.getLogger("PatternEngine")
        self.patterns = {}
        self.simple_patterns = {}
        self.matched_patterns = []
        self.confidence_scores = {}
        self.progress_callback = None
        
        # Performance tracking
        self.analysis_start_time = None
        self.packets_analyzed = 0
        self.patterns_matched = 0
        
        self.logger.info("🎯 Pattern Recognition Engine initialized")
        self.load_pattern_templates()
        
    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback
        self.logger.info("📊 Progress callback registered")
        
    def _log_progress(self, message, percent_complete=None):
        """Log progress with detailed information"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if percent_complete is not None:
            progress_msg = f"[{timestamp}] 📈 {percent_complete:.1f}% | {message}"
        else:
            progress_msg = f"[{timestamp}] 🔍 {message}"
            
        self.logger.info(progress_msg)
        
        if self.progress_callback:
            self.progress_callback(progress_msg)
            
    def load_pattern_templates(self):
        """Load pattern templates with detailed logging"""
        try:
            self._log_progress("Loading pattern templates...")
            
            patterns_dir = Path("./pattern_templates")
            
            # Load comprehensive patterns
            template_file = patterns_dir / "loopback_pattern_templates.json"
            if template_file.exists():
                with open(template_file, 'r') as f:
                    self.patterns = json.load(f)
                self._log_progress(f"Loaded comprehensive patterns: {len(self.patterns.get('port_classifications', {}))} port definitions")
            else:
                self.logger.warning("⚠️ Comprehensive pattern file not found, using defaults")
                
            # Load simple patterns
            simple_file = patterns_dir / "simple_port_patterns.json"
            if simple_file.exists():
                with open(simple_file, 'r') as f:
                    self.simple_patterns = json.load(f)
                self._log_progress(f"Loaded simple patterns: {len(self.simple_patterns.get('common_ports', []))} common ports")
            else:
                self.logger.warning("⚠️ Simple pattern file not found, creating defaults")
                self._create_default_patterns()
                
            self._log_progress("✅ Pattern templates loaded successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error loading pattern templates: {e}")
            self._create_default_patterns()
            
    def _create_default_patterns(self):
        """Create default patterns if files don't exist"""
        self._log_progress("Creating default pattern templates...")
        
        self.simple_patterns = {
            "common_ports": [3000, 8000, 8080, 9000, 3306, 5432, 6379],
            "development_ports": [3000, 3001, 8000, 8080, 9000],
            "database_ports": [3306, 5432, 6379, 27017],
            "port_names": {
                3000: "Node.js Dev Server",
                8000: "Python HTTP Server", 
                8080: "HTTP Proxy/Alt",
                9000: "Development Tools",
                3306: "MySQL",
                5432: "PostgreSQL",
                6379: "Redis"
            }
        }
        
        self.patterns = {
            "behavioral_signatures": {
                "development_server": {"confidence": 0.8},
                "database_activity": {"confidence": 0.9}
            }
        }
        
        self._log_progress("✅ Default patterns created")
        
    def analyze_packet_patterns(self, packet_data, total_packets=None):
        """Analyze packet data for pattern matches with progress tracking"""
        try:
            if not self.analysis_start_time:
                self.analysis_start_time = datetime.now()
                self._log_progress("🚀 Starting pattern analysis session...")
                
            # Extract packet information
            src_port = packet_data.get('src_port')
            dst_port = packet_data.get('dst_port')
            protocol = packet_data.get('protocol', 'unknown')
            size = packet_data.get('size', 0)
            
            self.packets_analyzed += 1
            
            # Log progress every 100 packets
            if self.packets_analyzed % 100 == 0:
                elapsed = (datetime.now() - self.analysis_start_time).total_seconds()
                rate = self.packets_analyzed / elapsed if elapsed > 0 else 0
                
                if total_packets:
                    percent = (self.packets_analyzed / total_packets) * 100
                    self._log_progress(f"Analyzed {self.packets_analyzed}/{total_packets} packets ({rate:.1f} pkt/sec)", percent)
                else:
                    self._log_progress(f"Analyzed {self.packets_analyzed} packets ({rate:.1f} pkt/sec)")
                    
            # Pattern matching
            matches = []
            
            # Port-based pattern matching
            if dst_port:
                port_match = self._match_port_pattern(dst_port)
                if port_match:
                    matches.append(port_match)
                    self.logger.debug(f"🎯 Port pattern match: {dst_port} -> {port_match['application']}")
                    
            # Behavioral pattern matching
            behavior_match = self._match_behavioral_pattern(src_port, dst_port, protocol, size)
            if behavior_match:
                matches.extend(behavior_match)
                
            # Store matches
            if matches:
                self.patterns_matched += len(matches)
                self.matched_patterns.extend(matches)
                
                # Log significant matches
                for match in matches:
                    if match.get('confidence', 0) > 0.7:
                        self._log_progress(f"High confidence match: {match['pattern_type']} ({match['confidence']:.0%})")
                        
            return matches
            
        except Exception as e:
            self.logger.error(f"❌ Error in pattern analysis: {e}")
            return []
            
    def _match_port_pattern(self, port):
        """Match port against known patterns"""
        try:
            # Check simple patterns first
            if port in self.simple_patterns.get('common_ports', []):
                port_name = self.simple_patterns.get('port_names', {}).get(port, f"Port {port}")
                
                # Determine category
                if port in self.simple_patterns.get('development_ports', []):
                    category = "development"
                    confidence = 0.85
                elif port in self.simple_patterns.get('database_ports', []):
                    category = "database" 
                    confidence = 0.90
                else:
                    category = "application"
                    confidence = 0.70
                    
                return {
                    'pattern_type': 'port_identification',
                    'port': port,
                    'application': port_name,
                    'category': category,
                    'confidence': confidence,
                    'timestamp': datetime.now().isoformat()
                }
                
            # Check comprehensive patterns
            port_classifications = self.patterns.get('port_classifications', {})
            if str(port) in port_classifications:
                port_info = port_classifications[str(port)]
                return {
                    'pattern_type': 'port_identification',
                    'port': port,
                    'application': port_info.get('app', f'Port {port}'),
                    'category': port_info.get('category', 'unknown'),
                    'confidence': 0.80,
                    'risk_level': port_info.get('risk', 'low'),
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error in port pattern matching: {e}")
            
        return None
        
    def _match_behavioral_pattern(self, src_port, dst_port, protocol, size):
        """Match behavioral patterns"""
        matches = []
        
        try:
            # Development server pattern
            if dst_port in [3000, 3001, 8000, 8080, 9000]:
                if protocol == 'tcp' and size > 100:
                    matches.append({
                        'pattern_type': 'behavioral_development_server',
                        'behavior': 'development_server_activity',
                        'indicators': ['development_port', 'tcp_traffic', 'meaningful_payload'],
                        'confidence': 0.75,
                        'details': f'Development traffic to port {dst_port}',
                        'timestamp': datetime.now().isoformat()
                    })
                    
            # Database connection pattern
            if dst_port in [3306, 5432, 6379, 27017]:
                matches.append({
                    'pattern_type': 'behavioral_database',
                    'behavior': 'database_connection',
                    'indicators': ['database_port', 'persistent_connection'],
                    'confidence': 0.85,
                    'details': f'Database connection to port {dst_port}',
                    'timestamp': datetime.now().isoformat()
                })
                
            # High frequency connection pattern
            if src_port and src_port > 32768:  # Ephemeral port
                matches.append({
                    'pattern_type': 'behavioral_client_connection',
                    'behavior': 'ephemeral_port_usage',
                    'indicators': ['ephemeral_source_port'],
                    'confidence': 0.60,
                    'details': f'Client connection from ephemeral port {src_port}',
                    'timestamp': datetime.now().isoformat()
                })
                
        except Exception as e:
            self.logger.error(f"Error in behavioral pattern matching: {e}")
            
        return matches
        
    def get_analysis_summary(self):
        """Generate comprehensive analysis summary with detailed logging"""
        try:
            self._log_progress("📊 Generating analysis summary...")
            
            elapsed_time = 0
            if self.analysis_start_time:
                elapsed_time = (datetime.now() - self.analysis_start_time).total_seconds()
                
            # Aggregate pattern matches
            pattern_counts = Counter()
            confidence_levels = defaultdict(list)
            applications_detected = set()
            
            for match in self.matched_patterns:
                pattern_counts[match['pattern_type']] += 1
                confidence_levels[match['pattern_type']].append(match['confidence'])
                
                if 'application' in match:
                    applications_detected.add(match['application'])
                    
            # Calculate average confidences
            avg_confidences = {}
            for pattern_type, confidences in confidence_levels.items():
                avg_confidences[pattern_type] = sum(confidences) / len(confidences) if confidences else 0
                
            summary = {
                'session_info': {
                    'analysis_start': self.analysis_start_time.isoformat() if self.analysis_start_time else None,
                    'analysis_duration_seconds': round(elapsed_time, 2),
                    'packets_analyzed': self.packets_analyzed,
                    'patterns_matched': self.patterns_matched,
                    'analysis_rate_pps': round(self.packets_analyzed / elapsed_time, 2) if elapsed_time > 0 else 0
                },
                'pattern_summary': {
                    'total_pattern_matches': len(self.matched_patterns),
                    'unique_pattern_types': len(pattern_counts),
                    'pattern_type_distribution': dict(pattern_counts),
                    'average_confidence_by_type': avg_confidences
                },
                'applications_detected': {
                    'total_applications': len(applications_detected),
                    'applications': list(applications_detected)
                },
                'detailed_matches': self.matched_patterns[-10:],  # Last 10 matches
                'performance_metrics': {
                    'packets_per_second': round(self.packets_analyzed / elapsed_time, 2) if elapsed_time > 0 else 0,
                    'patterns_per_packet': round(self.patterns_matched / self.packets_analyzed, 3) if self.packets_analyzed > 0 else 0,
                    'high_confidence_matches': len([m for m in self.matched_patterns if m.get('confidence', 0) > 0.8])
                }
            }
            
            self._log_progress(f"✅ Analysis complete: {self.packets_analyzed} packets, {self.patterns_matched} patterns matched")
            self._log_progress(f"🎯 Detected {len(applications_detected)} applications with {len(pattern_counts)} pattern types")
            
            return summary
            
        except Exception as e:
            self.logger.error(f"❌ Error generating analysis summary: {e}")
            return {}
            
    def save_analysis_results(self, output_dir="./analysis_results"):
        """Save analysis results with comprehensive logging"""
        try:
            self._log_progress("💾 Saving analysis results...")
            
            output_path = Path(output_dir)
            output_path.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Save detailed results
            results_file = output_path / f"pattern_analysis_{timestamp}.json"
            summary = self.get_analysis_summary()
            
            with open(results_file, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
                
            self._log_progress(f"✅ Results saved to: {results_file}")
            
            # Save human-readable summary
            summary_file = output_path / f"pattern_summary_{timestamp}.md"
            self._generate_markdown_summary(summary, summary_file)
            
            self._log_progress(f"✅ Summary saved to: {summary_file}")
            
            return results_file
            
        except Exception as e:
            self.logger.error(f"❌ Error saving analysis results: {e}")
            return None
            
    def _generate_markdown_summary(self, summary, output_file):
        """Generate human-readable markdown summary"""
        try:
            with open(output_file, 'w') as f:
                f.write(f"""# LoopbackShark Pattern Analysis Report
**AIMF LLC - Advanced Network Analytics**

## Analysis Session
- **Duration**: {summary['session_info']['analysis_duration_seconds']} seconds
- **Packets Analyzed**: {summary['session_info']['packets_analyzed']:,}
- **Patterns Matched**: {summary['session_info']['patterns_matched']:,}
- **Analysis Rate**: {summary['session_info']['analysis_rate_pps']:.1f} packets/second

## Pattern Detection Summary
- **Total Pattern Matches**: {summary['pattern_summary']['total_pattern_matches']:,}
- **Unique Pattern Types**: {summary['pattern_summary']['unique_pattern_types']}
- **High Confidence Matches**: {summary['performance_metrics']['high_confidence_matches']}

## Applications Detected
""")
                
                for app in summary['applications_detected']['applications']:
                    f.write(f"- {app}\n")
                    
                f.write(f"""
## Pattern Type Distribution
""")
                
                for pattern_type, count in summary['pattern_summary']['pattern_type_distribution'].items():
                    avg_conf = summary['pattern_summary']['average_confidence_by_type'].get(pattern_type, 0)
                    f.write(f"- **{pattern_type}**: {count} matches (avg confidence: {avg_conf:.1%})\n")
                    
                f.write(f"""
## Performance Metrics
- **Processing Rate**: {summary['performance_metrics']['packets_per_second']:.1f} packets/second
- **Pattern Density**: {summary['performance_metrics']['patterns_per_packet']:.3f} patterns/packet

---
*Generated by LoopbackShark Pattern Recognition Engine - AIMF LLC*
""")
                
        except Exception as e:
            self.logger.error(f"Error generating markdown summary: {e}")
            
    def reset_analysis(self):
        """Reset analysis state with logging"""
        self._log_progress("🔄 Resetting pattern analysis state...")
        
        self.matched_patterns.clear()
        self.confidence_scores.clear()
        self.packets_analyzed = 0
        self.patterns_matched = 0
        self.analysis_start_time = None
        
        self._log_progress("✅ Analysis state reset")
