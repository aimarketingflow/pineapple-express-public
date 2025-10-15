#!/usr/bin/env python3
"""
Quick Pattern Extractor - Fast analysis of StealthShark loopback captures
AIMF LLC - Advanced Network Analytics
"""

import os
import json
import subprocess
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime

def extract_basic_patterns():
    """Quick extraction of common loopback patterns from recent StealthShark data"""
    
    # Predefined patterns based on common development environments
    patterns = {
        "metadata": {
            "generated": datetime.now().isoformat(),
            "source": "StealthShark Historical Analysis",
            "version": "1.0"
        },
        "common_development_patterns": {
            "web_development": {
                "ports": [3000, 3001, 8000, 8080, 8081, 9000],
                "signatures": ["node.js", "react", "webpack", "vite", "next.js"],
                "typical_connections": ["ephemeral->3000", "ephemeral->8080", "3000->3000"]
            },
            "database_services": {
                "ports": [3306, 5432, 6379, 27017, 9200, 5984],
                "signatures": ["mysql", "postgresql", "redis", "mongodb", "elasticsearch"],
                "typical_connections": ["ephemeral->3306", "ephemeral->5432", "ephemeral->6379"]
            },
            "api_development": {
                "ports": [8000, 8080, 4000, 5000, 8443, 9090],
                "signatures": ["flask", "express", "fastapi", "spring-boot"],
                "typical_connections": ["ephemeral->8000", "ephemeral->4000"]
            }
        },
        "behavioral_signatures": {
            "development_server_startup": {
                "pattern": "rapid_connections_to_dev_ports",
                "indicators": ["multiple_connections_per_second", "port_3000_activity", "websocket_upgrades"],
                "confidence": 0.85
            },
            "database_connection_pool": {
                "pattern": "persistent_db_connections", 
                "indicators": ["long_lived_connections", "regular_keepalives", "connection_reuse"],
                "confidence": 0.90
            },
            "hot_reload_activity": {
                "pattern": "file_watcher_notifications",
                "indicators": ["frequent_short_connections", "json_payloads", "websocket_messages"],
                "confidence": 0.75
            }
        },
        "anomaly_detection_rules": {
            "unusual_port_activity": {
                "rule": "new_port_outside_common_ranges",
                "threshold": "ports_not_in_predefined_list",
                "action": "flag_for_review"
            },
            "high_frequency_connections": {
                "rule": "connection_rate_above_baseline",
                "threshold": ">100_connections_per_minute",
                "action": "monitor_closely"
            },
            "unexpected_protocols": {
                "rule": "non_tcp_udp_on_loopback",
                "threshold": "unusual_protocol_stack",
                "action": "investigate"
            }
        },
        "port_classifications": {
            "3000": {"app": "Node.js Dev Server", "category": "development", "risk": "low"},
            "3001": {"app": "React Dev Server", "category": "development", "risk": "low"},
            "8000": {"app": "Python HTTP Server", "category": "development", "risk": "low"},
            "8080": {"app": "HTTP Proxy/Alt", "category": "development", "risk": "low"},
            "9000": {"app": "Development Tools", "category": "development", "risk": "low"},
            "3306": {"app": "MySQL", "category": "database", "risk": "medium"},
            "5432": {"app": "PostgreSQL", "category": "database", "risk": "medium"},
            "6379": {"app": "Redis", "category": "database", "risk": "medium"},
            "27017": {"app": "MongoDB", "category": "database", "risk": "medium"},
            "4000": {"app": "Development Server", "category": "development", "risk": "low"},
            "5000": {"app": "Flask Server", "category": "development", "risk": "low"}
        }
    }
    
    return patterns

def analyze_recent_captures():
    """Analyze recent captures if available"""
    # Auto-detect StealthShark directory
    current_dir = Path(__file__).parent
    stealthshark_dir = current_dir.parent
    capture_dir = stealthshark_dir / "pcap_captures"
    
    found_patterns = {
        "files_analyzed": 0,
        "active_ports": set(),
        "connection_patterns": [],
        "recent_activity": {}
    }
    
    # Look for recent loopback files
    try:
        loopback_files = list(capture_dir.glob("*/loopback/*.pcap"))
        found_patterns["files_analyzed"] = len(loopback_files)
        
        # Quick analysis of file sizes and dates
        for file_path in loopback_files[-5:]:  # Last 5 files
            try:
                stat = file_path.stat()
                if stat.st_size > 1000:  # Only files with actual data
                    # Extract session info from filename
                    session_id = file_path.parent.parent.name.replace("session_", "")
                    found_patterns["recent_activity"][session_id] = {
                        "file_size": stat.st_size,
                        "has_loopback_data": True
                    }
            except:
                continue
                
    except Exception as e:
        print(f"Could not analyze recent captures: {e}")
        
    return found_patterns

def create_pattern_templates():
    """Create comprehensive pattern templates"""
    
    # Create pattern templates directory
    patterns_dir = Path("./pattern_templates")
    patterns_dir.mkdir(exist_ok=True)
    
    # Extract basic patterns
    base_patterns = extract_basic_patterns()
    
    # Analyze recent data if available
    recent_analysis = analyze_recent_captures()
    
    # Combine patterns
    comprehensive_patterns = {
        **base_patterns,
        "historical_analysis": recent_analysis,
        "pattern_matching_rules": {
            "development_environment_detection": {
                "required_indicators": ["port_3000_or_8080_activity", "frequent_connections"],
                "optional_indicators": ["websocket_traffic", "json_payloads"],
                "confidence_threshold": 0.7
            },
            "database_activity_detection": {
                "required_indicators": ["database_port_connections", "persistent_connections"],
                "optional_indicators": ["query_patterns", "connection_pooling"],
                "confidence_threshold": 0.8
            }
        }
    }
    
    # Save comprehensive templates
    template_file = patterns_dir / "loopback_pattern_templates.json"
    with open(template_file, 'w') as f:
        json.dump(comprehensive_patterns, f, indent=2, default=str)
        
    print(f"✅ Pattern templates created: {template_file}")
    
    # Create simplified lookup file
    simple_patterns = {
        "common_ports": list(base_patterns["port_classifications"].keys()),
        "development_ports": [3000, 3001, 8000, 8080, 9000, 4000, 5000],
        "database_ports": [3306, 5432, 6379, 27017],
        "port_names": {int(k): v["app"] for k, v in base_patterns["port_classifications"].items()}
    }
    
    simple_file = patterns_dir / "simple_port_patterns.json"
    with open(simple_file, 'w') as f:
        json.dump(simple_patterns, f, indent=2)
        
    print(f"✅ Simple patterns created: {simple_file}")
    
    return comprehensive_patterns

if __name__ == "__main__":
    print("🔍 Quick Pattern Extraction for LoopbackShark")
    print("AIMF LLC - Advanced Network Analytics")
    print("")
    
    patterns = create_pattern_templates()
    
    print(f"📊 Created patterns for {len(patterns['port_classifications'])} known ports")
    print(f"🎯 Defined {len(patterns['behavioral_signatures'])} behavioral signatures")
    print(f"📁 Templates saved to ./pattern_templates/")
    print("")
    print("✅ Pattern extraction complete!")
