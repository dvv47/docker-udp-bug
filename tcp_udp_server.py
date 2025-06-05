#!/usr/bin/env python3
"""
Combined TCP Server + UDP Client for Docker UDP Bug Testing

This program replaces the socat-based TCP server and netcat-based UDP client
with a single Python implementation that:
1. Listens for TCP connections from containers
2. Sends UDP messages to the container (triggered by TCP connections)
3. Logs all activities for debugging
"""

import socket
import threading
import time
import sys
import argparse
import signal
import logging
from datetime import datetime


class TCPUDPServer:
    def __init__(self, tcp_port, udp_host, udp_port, log_file=None):
        self.tcp_port = tcp_port
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.running = True
        self.client_threads = []
        self.client_stop_flags = {}  # Dictionary to track stop flags for each thread
        
        # Setup logging
        self.setup_logging(log_file)
        
        # Create TCP server socket
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Create UDP client socket
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def setup_logging(self, log_file):
        """Setup logging to both file and console"""
        self.logger = logging.getLogger('tcp_udp_server')
        self.logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter('%(asctime)s: %(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file, 'a')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def log(self, message):
        """Log message with timestamp"""
        self.logger.info(message)
    
    def handle_client(self, client_socket, client_address):
        """Handle individual TCP client connection"""
        client_id = f"{client_address[0]}:{client_address[1]}"
        self.log(f"Client {client_id} connected, starting continuous UDP message loop")
        
        counter = 1
        
        try:
            while self.running:
                # Send UDP message to container
                udp_message = f"Hello World UDP {counter}"
                try:
                    self.udp_socket.sendto(udp_message.encode('utf-8'), (self.udp_host, self.udp_port))
                    self.log(f"Sent UDP message {counter} to {self.udp_host}:{self.udp_port}")
                except socket.error as e:
                    self.log(f"UDP send failed to {self.udp_host}:{self.udp_port}: {e}")
                
                counter += 1
                time.sleep(0.1)
                
        except Exception as e:
            self.log(f"Error handling client {client_id}: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            self.log(f"Client {client_id} disconnected, closing handler (thread {thread_id})")
    
    def stop_all_client_threads(self):
        """Stop all existing client threads"""
        if not self.client_threads:
            return
            
        self.log(f"Stopping {len(self.client_threads)} existing client threads")
        
        for thread in self.client_threads:
            thread.running = False
        
        # Clear the list - old threads will finish naturally
        old_count = len(self.client_threads)
        self.client_threads.clear()
        
        if old_count > 0:
            self.log(f"Cleared {old_count} client threads from list")
    
    def start_server(self):
        """Start the TCP server and listen for connections"""
        try:
            self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_socket.listen(5)
            self.log(f"TCP server listening on port {self.tcp_port}")
            self.log(f"Will send UDP messages to {self.udp_host}:{self.udp_port}")
            
            while self.running:
                try:
                    # Accept TCP connection
                    client_socket, client_address = self.tcp_socket.accept()
                    
                    # Start thread to handle client
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                    # Stop all previous client threads
                    self.stop_all_client_threads()
                    
                    # Add new client thread to list (replacing all previous ones)
                    self.client_threads = [client_thread]
                    self.log(f"New client thread started, previous threads stopped")
                    
                except socket.error as e:
                    if self.running:  # Only log if we're not shutting down
                        self.log(f"Error accepting connection: {e}")
                    else:
                        # Socket was closed during shutdown - this is expected
                        break
                        
        except Exception as e:
            self.log(f"Server error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup sockets and threads"""
        self.log("Cleaning up server resources...")
        self.running = False
        
        # Close sockets if not already closed
        try:
            if hasattr(self, 'tcp_socket'):
                self.tcp_socket.close()
        except:
            pass
            
        try:
            if hasattr(self, 'udp_socket'):
                self.udp_socket.close()
        except:
            pass
        
        # Wait for client threads to finish (with timeout)
        for thread in self.client_threads:
            if thread.is_alive():
                thread.join(timeout=1.0)
        
        self.log("Server cleanup completed")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.log(f"Received signal {signum}, shutting down server...")
        self.running = False
        # Close the TCP socket to break out of accept() call
        try:
            self.tcp_socket.shutdown(socket.SHUT_RDWR)
            self.tcp_socket.close()
        except:
            pass
        # Force exit after cleanup
        self.cleanup()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='Combined TCP Server + UDP Client for Docker Bug Testing')
    parser.add_argument('--tcp-port', type=int, default=11002,
                        help='TCP server port (default: 11002)')
    parser.add_argument('--udp-host', type=str, required=True,
                        help='UDP target host (container IP)')
    parser.add_argument('--udp-port', type=int, default=54603,
                        help='UDP target port (default: 54603)')
    parser.add_argument('--log-file', type=str,
                        help='Log file path (optional)')
    
    args = parser.parse_args()
    
    # Create server instance
    server = TCPUDPServer(args.tcp_port, args.udp_host, args.udp_port, args.log_file)
    
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, server.signal_handler)
    signal.signal(signal.SIGTERM, server.signal_handler)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        server.log("Interrupted by user")
    except Exception as e:
        server.log(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 