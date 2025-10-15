#!/usr/bin/env python3
"""
LoopbackShark CLI - Command Line Interface for Loopback Traffic Monitoring
AIMF LLC - Advanced Network Analytics
"""

import os
import sys
import argparse
import signal
import time
import logging
from datetime import datetime
from pathlib import Path

# Import our loopback monitor
from loopback_monitor import LoopbackMonitor, setup_logging

class LoopbackSharkCLI:
    """Command line interface for LoopbackShark"""
    
    def __init__(self):
        self.logger = logging.getLogger("LoopbackSharkCLI")
        self.monitor = None
        self.interrupted = False
        
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print(f"\n🛑 Received signal {signum}, stopping LoopbackShark...")
        self.interrupted = True
        if self.monitor:
            self.monitor.stop_monitoring()
        sys.exit(0)
        
    def run_diagnostic(self):
        """Run diagnostic test mode"""
        print("🔍 Running LoopbackShark diagnostic test...")
        
        # Check dependencies
        dependencies = ['tshark', 'python3']
        for dep in dependencies:
            try:
                import subprocess
                result = subprocess.run(['which', dep], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ {dep}: {result.stdout.strip()}")
                else:
                    print(f"❌ {dep}: Not found")
            except Exception as e:
                print(f"❌ Error checking {dep}: {e}")
                
        # Check loopback interface
        try:
            import psutil
            net_stats = psutil.net_io_counters(pernic=True)
            loopback_interfaces = ['lo0', 'lo', 'Loopback']
            
            found_loopback = False
            for interface in loopback_interfaces:
                if interface in net_stats:
                    stats = net_stats[interface]
                    print(f"✅ Loopback interface {interface}: {stats.packets_sent + stats.packets_recv} total packets")
                    found_loopback = True
                    break
                    
            if not found_loopback:
                print("❌ No loopback interface found")
                
        except Exception as e:
            print(f"❌ Error checking loopback interface: {e}")
            
        # Test short capture
        print("🧪 Testing 10-second loopback capture...")
        try:
            test_monitor = LoopbackMonitor(duration=10, capture_dir="./test_capture")
            
            def test_callback(message):
                print(f"[TEST] {message}")
                
            test_monitor.start_monitoring(callback=test_callback)
            print("✅ Diagnostic test completed successfully")
            
        except Exception as e:
            print(f"❌ Diagnostic test failed: {e}")
            
    def run_monitor(self, args):
        """Run the main monitoring process"""
        try:
            print("🚀 Starting LoopbackShark CLI Monitor")
            print(f"📁 Output Directory: {args.output_dir}")
            print(f"⏱️ Duration: {args.duration} seconds ({args.duration/3600:.1f} hours)")
            
            if args.port_filter:
                ports = [int(p.strip()) for p in args.port_filter.split(',')]
                print(f"🔌 Port Filter: {ports}")
            else:
                print("🔌 Monitoring all loopback ports")
                
            if args.protocol != 'all':
                print(f"📡 Protocol Filter: {args.protocol}")
                
            # Create output directory
            output_path = Path(args.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Setup signal handlers
            self.setup_signal_handlers()
            
            # Create monitor
            self.monitor = LoopbackMonitor(
                capture_dir=str(output_path),
                duration=args.duration
            )
            
            # Progress callback
            def progress_callback(message):
                if args.debug:
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"[{timestamp}] {message}")
                else:
                    # Simple progress indicator
                    print(".", end="", flush=True)
                    
            print("🔄 Monitoring started (press Ctrl+C to stop)...")
            
            # Start monitoring
            start_time = datetime.now()
            self.monitor.start_monitoring(callback=progress_callback)
            
            if not self.interrupted:
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                print(f"\n✅ Monitoring completed in {duration:.1f} seconds")
                print(f"📊 Analysis results saved to: {output_path}")
                
                # Generate summary log
                self.generate_summary_log(args, output_path, start_time, end_time)
                
        except KeyboardInterrupt:
            print("\n🛑 Monitoring interrupted by user")
        except Exception as e:
            print(f"\n❌ Error during monitoring: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
                
    def generate_summary_log(self, args, output_path, start_time, end_time):
        """Generate markdown summary log"""
        try:
            duration = (end_time - start_time).total_seconds()
            log_file = output_path / f"loopbackshark_session_log_{start_time.strftime('%Y%m%d_%H%M%S')}.md"
            
            with open(log_file, 'w') as f:
                f.write(f"""# LoopbackShark Session Log
**AIMF LLC - Network Analytics**

## Session Parameters
- **Start Time**: {start_time.strftime('%Y-%m-%d %H:%M:%S')}
- **End Time**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}
- **Duration**: {duration:.1f} seconds ({duration/3600:.2f} hours)
- **Output Directory**: {output_path}
- **Port Filter**: {args.port_filter or 'All ports'}
- **Protocol Filter**: {args.protocol}

## Runtime Statistics
- **Command**: {' '.join(sys.argv)}
- **PID**: {os.getpid()}
- **Working Directory**: {os.getcwd()}
- **Python Version**: {sys.version.split()[0]}

## Files Generated
- **PCAP Captures**: Check `pcap_captures/` subdirectory
- **Analysis Reports**: Check `analysis_results/` subdirectory
- **Session Logs**: Check `persistent_logs/` subdirectory

---
*Generated by LoopbackShark CLI - AIMF LLC*
""")
            
            print(f"📝 Session log saved: {log_file}")
            
        except Exception as e:
            print(f"❌ Error generating summary log: {e}")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="LoopbackShark - Specialized Loopback Traffic Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic 30-minute monitoring
  python3 cli_loopbackshark.py --duration 1800
  
  # Monitor specific ports with debug logging  
  python3 cli_loopbackshark.py --port-filter 3000,8080,9000 --debug
  
  # Full day monitoring with custom output directory
  python3 cli_loopbackshark.py --duration 86400 --output-dir ./daily_analysis
  
  # TCP-only monitoring for 2 hours
  python3 cli_loopbackshark.py --duration 7200 --protocol tcp
        """
    )
    
    parser.add_argument('--duration', '-d', type=int, default=1800,
                       help='Monitor duration in seconds (default: 1800 = 30 minutes)')
    
    parser.add_argument('--output-dir', '-o', type=str, default='./loopback_analysis',
                       help='Output directory for captures and analysis (default: ./loopback_analysis)')
    
    parser.add_argument('--port-filter', '-p', type=str,
                       help='Comma-separated list of ports to monitor (e.g., 3000,8080,9000)')
    
    parser.add_argument('--protocol', type=str, choices=['tcp', 'udp', 'all'], default='all',
                       help='Protocol filter (default: all)')
    
    parser.add_argument('--debug', action='store_true',
                       help='Enable verbose debug logging')
    
    parser.add_argument('--diagnostic', action='store_true',
                       help='Run diagnostic test mode')
    
    args = parser.parse_args()
    
    # Setup logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
        
    # Initialize CLI
    cli = LoopbackSharkCLI()
    
    try:
        if args.diagnostic:
            cli.run_diagnostic()
        else:
            cli.run_monitor(args)
            
    except Exception as e:
        print(f"❌ CRITICAL ERROR: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Setup logging
    setup_logging()
    main()
