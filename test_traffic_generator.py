#!/usr/bin/env python3
"""
LoopbackShark Test Traffic Generator
Generates test loopback traffic to demonstrate pattern recognition
AIMF LLC - Advanced Network Analytics
"""

import socket
import time
import threading
import json
import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler
import argparse

class DevServerSimulator:
    """Simulates development server traffic patterns"""
    
    def __init__(self, port=3000):
        self.port = port
        self.running = False
        
    def start_server(self):
        """Start a simple HTTP server on loopback"""
        try:
            print(f"🚀 Starting dev server simulator on localhost:{self.port}")
            server = HTTPServer(('127.0.0.1', self.port), SimpleHTTPRequestHandler)
            self.running = True
            
            # Run server in thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            return server
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return None

class DatabaseSimulator:
    """Simulates database connection patterns"""
    
    def __init__(self, port=5432):
        self.port = port
        
    def simulate_connections(self, count=10):
        """Simulate database connections"""
        print(f"💾 Simulating {count} database connections to port {self.port}")
        
        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                # Attempt connection to simulate database activity
                try:
                    sock.connect(('127.0.0.1', self.port))
                except:
                    pass  # Expected to fail, just generating traffic
                finally:
                    sock.close()
                    
                time.sleep(0.5)  # Brief pause between connections
                
            except Exception as e:
                continue

class HTTPClientSimulator:
    """Simulates HTTP client traffic"""
    
    def __init__(self, target_port=3000):
        self.target_port = target_port
        
    def generate_requests(self, count=20):
        """Generate HTTP requests to simulate development activity"""
        print(f"🌐 Generating {count} HTTP requests to localhost:{self.target_port}")
        
        for i in range(count):
            try:
                response = requests.get(f'http://127.0.0.1:{self.target_port}', timeout=1)
            except:
                pass  # Expected to fail if no server, just generating traffic
                
            time.sleep(0.2)  # Realistic request intervals

class RedisSimulator:
    """Simulates Redis-like key-value operations"""
    
    def __init__(self, port=6379):
        self.port = port
        
    def simulate_operations(self, count=15):
        """Simulate Redis operations"""
        print(f"🔑 Simulating {count} Redis operations on port {self.port}")
        
        for i in range(count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                
                try:
                    sock.connect(('127.0.0.1', self.port))
                    # Send fake Redis command
                    sock.send(b'*2\r\n$3\r\nGET\r\n$7\r\nmykey\r\n')
                    time.sleep(0.1)
                except:
                    pass
                finally:
                    sock.close()
                    
                time.sleep(0.3)
                
            except:
                continue

def run_development_simulation():
    """Run a comprehensive development environment simulation"""
    print("🔍 Starting LoopbackShark Development Environment Simulation")
    print("This will generate various types of loopback traffic for pattern testing")
    print("")
    
    # Start development server
    dev_server = DevServerSimulator(3000)
    server = dev_server.start_server()
    
    if server:
        time.sleep(1)  # Let server start
        
        # Generate different types of traffic
        simulators = [
            HTTPClientSimulator(3000),
            DatabaseSimulator(5432),
            DatabaseSimulator(3306),  # MySQL
            RedisSimulator(6379),
            DatabaseSimulator(27017)  # MongoDB
        ]
        
        # Run simulations in parallel
        threads = []
        
        # HTTP traffic
        thread1 = threading.Thread(target=simulators[0].generate_requests, args=(25,))
        threads.append(thread1)
        
        # Database connections
        for i, sim in enumerate(simulators[1:], 1):
            if hasattr(sim, 'simulate_connections'):
                thread = threading.Thread(target=sim.simulate_connections, args=(8,))
            else:
                thread = threading.Thread(target=sim.simulate_operations, args=(12,))
            threads.append(thread)
        
        # Start all traffic generators
        print("🚀 Starting traffic generators...")
        for thread in threads:
            thread.start()
            time.sleep(0.5)  # Stagger starts
            
        # Wait for completion
        for thread in threads:
            thread.join()
            
        print("✅ Traffic simulation complete")
        server.shutdown()
        
    else:
        print("⚠️ Running limited simulation without HTTP server")
        # Run database simulations only
        db_sim = DatabaseSimulator(5432)
        redis_sim = RedisSimulator(6379)
        
        db_sim.simulate_connections(10)
        redis_sim.simulate_operations(10)

def main():
    parser = argparse.ArgumentParser(description="Generate test traffic for LoopbackShark")
    parser.add_argument('--duration', '-d', type=int, default=30, 
                       help='Simulation duration in seconds')
    parser.add_argument('--intensity', '-i', choices=['light', 'medium', 'heavy'], 
                       default='medium', help='Traffic intensity')
    
    args = parser.parse_args()
    
    print(f"🎯 LoopbackShark Traffic Generator")
    print(f"Duration: {args.duration} seconds | Intensity: {args.intensity}")
    print(f"💡 TIP: Run LoopbackShark monitoring in another terminal!")
    print("")
    
    # Adjust traffic based on intensity
    if args.intensity == 'light':
        count_multiplier = 0.5
    elif args.intensity == 'heavy':
        count_multiplier = 2.0
    else:
        count_multiplier = 1.0
    
    start_time = time.time()
    
    while time.time() - start_time < args.duration:
        run_development_simulation()
        
        remaining = args.duration - (time.time() - start_time)
        if remaining > 5:
            print(f"⏱️ Continuing simulation... {remaining:.0f}s remaining")
            time.sleep(2)
        else:
            break
    
    print("🏁 Traffic generation complete")

if __name__ == "__main__":
    main()
