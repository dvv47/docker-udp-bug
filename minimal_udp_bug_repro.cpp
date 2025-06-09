// Docker UDP Forwarding Instability Reproduction
// Demonstrates Docker UDP forwarding failure with burst traffic patterns
//
// CRITICAL FINDING: Docker UDP forwarding becomes unstable with burst UDP traffic
// patterns EVEN when using proper socket destruction order (TCP first, then UDP).
// This suggests a fundamental issue with Docker's UDP forwarding mechanism
// when handling realistic burst traffic scenarios.
//
// SETUP: Python TCP/UDP server on HOST sends burst UDP traffic to container:
//   python3 tcp_udp_server.py --udp-host <container_ip>

#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <atomic>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <fstream>
#include <string>
#include <cstdlib>
#include <netdb.h>

namespace {
    constexpr uint16_t UDP_PORT = 54603;
    constexpr uint16_t TCP_PORT = 11002;
    constexpr const char* HOST_IP = "host.docker.internal";
}

struct TestConfig {
    int runtime_seconds = 15;
    std::string log_file_path = "";
    std::string tcp_host = HOST_IP;
};

class UdpServer {
private:
    int socket_fd = -1;
    std::thread worker_thread;
    std::atomic<bool> running{false};
    std::atomic<int> messages_received{0};
    std::string log_file_path;
    
public:
    UdpServer(const std::string& log_path) : log_file_path(log_path) {}
    
    ~UdpServer() {
        properCleanup();
    }
    
    bool start() {
        std::cout << "[UDP] Creating UDP server on port " << UDP_PORT << std::endl;
        
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd < 0) {
            std::cerr << "[UDP] socket() failed: " << strerror(errno) << std::endl;
            return false;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(UDP_PORT);
        
        if (bind(socket_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "[UDP] bind() failed: " << strerror(errno) << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
        
        std::cout << "[UDP] Successfully bound to port " << UDP_PORT << std::endl;
        
        // Set receive timeout
        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        
        running = true;
        worker_thread = std::thread([this]() {
            std::cout << "[UDP] Worker thread started - ready to receive burst traffic" << std::endl;
            
            char buffer[1024];
            struct sockaddr_in client_addr;
            socklen_t len;
            
            while (running.load()) {
                len = sizeof(client_addr);
                memset(&client_addr, 0, sizeof(client_addr));
                
                ssize_t received = recvfrom(socket_fd, buffer, sizeof(buffer) - 1, 0,
                                          reinterpret_cast<struct sockaddr*>(&client_addr), &len);
                
                if (!running.load()) break;
                
                if (received > 0) {
                    buffer[received] = '\0';
                    messages_received++;
                    
                    std::cout << "[UDP] Received: '" << buffer << "' (total: " << messages_received << ")" << std::endl;
                    
                    // Log to file for verification
                    std::ofstream log_file(log_file_path, std::ios::app);
                    if (log_file.is_open()) {
                        log_file << "MESSAGE=" << buffer << std::endl;
                        log_file.flush();
                    }
                } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (running.load()) {
                        std::cerr << "[UDP] recvfrom() error: " << strerror(errno) << std::endl;
                        break;
                    }
                }
            }
            
            std::cout << "[UDP] Worker thread ended. Total messages received: " << messages_received << std::endl;
        });
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }
    
    void properCleanup() {
        std::cout << "[UDP] === PROPER CLEANUP SEQUENCE ===" << std::endl;
        
        if (running.exchange(false)) {
            if (worker_thread.joinable()) {
                worker_thread.join();
            }
        }
        
        if (socket_fd != -1) {
            std::cout << "[UDP] Using proper shutdown() + close() sequence" << std::endl;
            shutdown(socket_fd, SHUT_RDWR);
            close(socket_fd);
            socket_fd = -1;
        }
        
        std::cout << "[UDP] Final message count: " << messages_received << std::endl;
    }
    
    int getMessageCount() const {
        return messages_received;
    }
};

class TcpClient {
private:
    int socket_fd = -1;
    std::string ip;
    uint16_t port;
    bool connected = false;
    
public:
    TcpClient(const std::string& ip_, uint16_t port_) : ip(ip_), port(port_) {}
    
    ~TcpClient() {
        properCleanup();
    }
    
    bool connect() {
        std::cout << "[TCP_CLIENT] Connecting to " << ip << ":" << port << std::endl;
        std::cout << "[TCP_CLIENT] This triggers Python server to send burst UDP traffic" << std::endl;
        
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            std::cerr << "[TCP_CLIENT] socket() failed: " << strerror(errno) << std::endl;
            return false;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        // Resolve hostname
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        int status = getaddrinfo(ip.c_str(), nullptr, &hints, &result);
        if (status != 0) {
            std::cerr << "[TCP_CLIENT] Failed to resolve '" << ip << "': " << gai_strerror(status) << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
        
        struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
        addr.sin_addr = addr_in->sin_addr;
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        std::cout << "[TCP_CLIENT] Resolved '" << ip << "' to " << ip_str << std::endl;
        
        freeaddrinfo(result);
        
        if (::connect(socket_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            connected = true;
            std::cout << "[TCP_CLIENT] ✓ Connected! Python server will now send burst UDP traffic" << std::endl;
            return true;
        } else {
            std::cerr << "[TCP_CLIENT] Connection failed: " << strerror(errno) << std::endl;
            std::cerr << "[TCP_CLIENT] Ensure Python TCP/UDP server is running on host" << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
    }
    
    bool isConnected() const {
        return connected;
    }
    
    void properCleanup() {
        if (socket_fd != -1) {
            std::cout << "[TCP_CLIENT] === PROPER CLEANUP SEQUENCE ===" << std::endl;
            std::cout << "[TCP_CLIENT] Using proper shutdown() + close() sequence" << std::endl;
            if (connected) {
                shutdown(socket_fd, SHUT_RDWR);
            }
            close(socket_fd);
            socket_fd = -1;
            connected = false;
        }
    }
};

TestConfig parseArgs(int argc, char* argv[]) {
    TestConfig config;
    
    for (int i = 1; i < argc; i++) {
        std::string arg(argv[i]);
        
        if (arg == "--runtime" && i + 1 < argc) {
            config.runtime_seconds = std::atoi(argv[i + 1]);
            i++;
        } else if (arg == "--log-file" && i + 1 < argc) {
            config.log_file_path = argv[i + 1];
            i++;
        } else if (arg == "--tcp-host" && i + 1 < argc) {
            config.tcp_host = argv[i + 1];
            i++;
        }
    }
    
    return config;
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);
    
    TestConfig config = parseArgs(argc, argv);
    
    if (config.log_file_path.empty()) {
        std::cerr << "Error: --log-file parameter is required" << std::endl;
        return 1;
    }
    
    std::cout << "=== Docker UDP Burst Traffic Instability Test ===" << std::endl;
    std::cout << "Purpose: Demonstrate Docker UDP forwarding instability with burst patterns" << std::endl;
    std::cout << "Runtime: " << config.runtime_seconds << "s" << std::endl;
    std::cout << "TCP Host: " << config.tcp_host << ":" << TCP_PORT << std::endl;
    std::cout << "\nCRITICAL: This test uses PROPER socket destruction order (TCP first, UDP second)" << std::endl;
    std::cout << "Yet Docker UDP forwarding may still fail due to burst traffic patterns!\n" << std::endl;
    
    try {
        // Create UDP server first
        auto udp_server = std::make_unique<UdpServer>(config.log_file_path);
        if (!udp_server->start()) {
            std::cerr << "Failed to start UDP server" << std::endl;
            return 1;
        }
        
        // Connect to host - this triggers burst UDP traffic from Python server
        auto tcp_client = std::make_unique<TcpClient>(config.tcp_host, TCP_PORT);
        if (!tcp_client->connect()) {
            std::cerr << "Failed to connect to Python TCP/UDP server" << std::endl;
            std::cerr << "Start it with: python3 tcp_udp_server.py --udp-host <container_ip>" << std::endl;
            return 1;
        }
        
        if (!tcp_client->isConnected()) {
            std::cerr << "TCP connection not established" << std::endl;
            return 1;
        }
        
        std::cout << "\n=== Running Test (Receiving Burst UDP Traffic) ===" << std::endl;
        std::cout << "✓ TCP connection established - Python server sending burst UDP traffic" << std::endl;
        std::cout << "✓ UDP server ready to receive burst patterns (10 msgs + 5s pause)" << std::endl;
        std::cout << "✓ Monitoring Docker UDP forwarding stability..." << std::endl;
        
        // Let the test run and collect burst UDP traffic
        std::this_thread::sleep_for(std::chrono::seconds(config.runtime_seconds));
        
        std::cout << "\n=== Cleanup Phase (PROPER Socket Destruction Order) ===" << std::endl;
        std::cout << "Using PROPER destruction sequence: TCP first, then UDP" << std::endl;
        std::cout << "This should work, but Docker may have been destabilized by burst traffic" << std::endl;
        
        // ALWAYS use proper cleanup order - TCP first, then UDP
        tcp_client->properCleanup();
        tcp_client.reset();
        
        udp_server->properCleanup();
        int final_count = udp_server->getMessageCount();
        udp_server.reset();
        
        std::cout << "\n=== Test Results ===" << std::endl;
        std::cout << "Socket destruction order: PROPER (TCP → UDP)" << std::endl;
        std::cout << "Total UDP messages received: " << final_count << std::endl;
        
        if (final_count > 0) {
            std::cout << "✓ Some UDP messages received - partial success" << std::endl;
        } else {
            std::cout << "✗ No UDP messages received - Docker UDP forwarding failed" << std::endl;
        }
        
        std::cout << "\nIMPORTANT: If this test fails repeatedly, it demonstrates that" << std::endl;
        std::cout << "Docker UDP forwarding is unstable with burst traffic patterns," << std::endl;
        std::cout << "even when applications use proper socket cleanup procedures." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
} 