#!/usr/bin/env python3
"""
TCP Server + UDP Client for Docker UDP Bug Testing
- Accepts one TCP connection at a time
- Sends UDP messages while TCP connection is active
- Stops previous UDP traffic when new client connects
"""

import socket
import threading
import time
import sys
import argparse
import signal


class ClientHandler:
    def __init__(self, client_socket, client_address, udp_socket, udp_host, udp_port):
        self.client_socket = client_socket
        self.client_address = client_address
        self.udp_socket = udp_socket
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.running = True
        self.thread = None
        
    def start(self):
        self.thread = threading.Thread(target=self._handle_client, daemon=True)
        self.thread.start()
        
    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            try:
                self.client_socket.close()
            except:
                pass
    
    def _handle_client(self):
        client_id = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"Client {client_id} connected, starting UDP loop")
        
        counter = 1
        try:
            while self.running:
                for i in range(10):
                    udp_message = f"Hello World UDP {counter}"
                    try:
                        self.udp_socket.sendto(udp_message.encode('utf-8'), (self.udp_host, self.udp_port))
                        print(f"UDP message {counter} sent to {self.udp_host}:{self.udp_port}")
                    except socket.error as e:
                        print(f"UDP send failed: {e}")
                    counter += 1
                time.sleep(5.0)
                
        except Exception as e:
            if self.running:
                print(f"Client error: {e}")
        finally:
            try:
                self.client_socket.close()
            except:
                pass
            print(f"Client {client_id} disconnected")


class TCPUDPServer:
    def __init__(self, tcp_port, udp_host, udp_port):
        self.tcp_port = tcp_port
        self.udp_host = udp_host
        self.udp_port = udp_port
        self.running = True
        self.current_client_handler = None
        
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    def _stop_current_client(self):
        if self.current_client_handler:
            print("Stopping current client")
            self.current_client_handler.stop()
            self.current_client_handler = None
    
    def start_server(self):
        try:
            self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
            self.tcp_socket.listen(5)
            print(f"TCP server listening on port {self.tcp_port}")
            print(f"Will send UDP to {self.udp_host}:{self.udp_port}")
            
            while self.running:
                try:
                    client_socket, client_address = self.tcp_socket.accept()
                    
                    self._stop_current_client()
                    
                    self.current_client_handler = ClientHandler(
                        client_socket, 
                        client_address,
                        self.udp_socket,
                        self.udp_host,
                        self.udp_port
                    )
                    
                    self.current_client_handler.start()
                    print(f"New client {client_address[0]}:{client_address[1]} accepted")
                    
                except socket.error as e:
                    if self.running:
                        print(f"Accept error: {e}")
                    else:
                        break
                        
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        print("Cleaning up...")
        self.running = False
        self._stop_current_client()
        
        try:
            self.tcp_socket.close()
        except:
            pass
            
        try:
            self.udp_socket.close()
        except:
            pass
        
        print("Cleanup completed")
    
    def signal_handler(self, signum, frame):
        print(f"Received signal {signum}, shutting down...")
        self.running = False
        try:
            self.tcp_socket.shutdown(socket.SHUT_RDWR)
            self.tcp_socket.close()
        except:
            pass
        self.cleanup()
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description='TCP Server + UDP Client for Docker Bug Testing')
    parser.add_argument('--tcp-port', type=int, default=11002, help='TCP server port')
    parser.add_argument('--udp-host', type=str, required=True, help='UDP target host')
    parser.add_argument('--udp-port', type=int, default=54603, help='UDP target port')
    
    args = parser.parse_args()
    
    server = TCPUDPServer(args.tcp_port, args.udp_host, args.udp_port)
    
    signal.signal(signal.SIGINT, server.signal_handler)
    signal.signal(signal.SIGTERM, server.signal_handler)
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("Interrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main() 