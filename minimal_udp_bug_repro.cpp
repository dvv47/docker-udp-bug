// Docker UDP Bug Reproduction Test Case
// Minimal reproduction of Docker UDP forwarding bug caused by socket destruction order
//
// ROOT CAUSE: Docker bridge gets corrupted when UDP sockets are destroyed BEFORE TCP sockets
// The shutdown() vs close() pattern is less important than the destruction order!
//
// REPRODUCTION:
// 1. Create UDP server + successful TCP connection to HOST machine (through Docker bridge)
// 2. Destroy UDP socket FIRST (even with proper shutdown+close)
// 3. This corrupts Docker bridge, breaking UDP forwarding on next run
//
// SETUP: Run a TCP server on HOST machine first:
//   nc -l -p 11002   (or any TCP server on port 11002)

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
    constexpr uint16_t UDP_PORT = 54603;  // Reverted back to original port
    constexpr uint16_t TCP_PORT = 11002;
    constexpr const char* HOST_IP = "host.docker.internal";  // Docker's host IP
}

struct TestConfig {
    bool manual_cleanup = false;
    int runtime_seconds = 2;
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
    bool manual_cleanup_mode;
    
public:
    UdpServer(const std::string& log_path, bool manual_mode) 
        : log_file_path(log_path), manual_cleanup_mode(manual_mode) {}
    
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
            std::cout << "[UDP] Worker thread started" << std::endl;
            
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
                    
                    std::cout << "[UDP] Received: '" << buffer << "'" << std::endl;
                    
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
            
            std::cout << "[UDP] Worker thread ended" << std::endl;
        });
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return true;
    }
    
    void properCleanup() {
        std::cout << "[UDP] === PROPER CLEANUP ===" << std::endl;
        
        if (running.exchange(false)) {
            if (worker_thread.joinable()) {
                worker_thread.join();
            }
        }
        
        if (socket_fd != -1) {
            std::cout << "[UDP] shutdown() + close()" << std::endl;
            shutdown(socket_fd, SHUT_RDWR);  // PROPER: shutdown first
            close(socket_fd);
            socket_fd = -1;
        }
    }
};

class TcpClient {
private:
    int socket_fd = -1;
    std::string ip;
    uint16_t port;
    bool manual_cleanup_mode;
    bool connected = false;
    
public:
    TcpClient(const std::string& ip_, uint16_t port_, bool manual_mode) 
        : ip(ip_), port(port_), manual_cleanup_mode(manual_mode) {}
    
    ~TcpClient() {
        properCleanup();
    }
    
    bool connect() {
        std::cout << "[TCP_CLIENT] Attempting to connect to " << ip << ":" << port << std::endl;
        std::cout << "[TCP_CLIENT] This connection goes through Docker bridge - critical for bug reproduction!" << std::endl;
        
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            std::cerr << "[TCP_CLIENT] socket() failed: " << strerror(errno) << std::endl;
            return false;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        // Try to resolve hostname using getaddrinfo
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        int status = getaddrinfo(ip.c_str(), nullptr, &hints, &result);
        if (status != 0) {
            std::cerr << "[TCP_CLIENT] ✗ Failed to resolve hostname '" << ip << "': " << gai_strerror(status) << std::endl;
            close(socket_fd);
            socket_fd = -1;
            return false;
        }
        
        // Use the first result
        struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
        addr.sin_addr = addr_in->sin_addr;
        
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        std::cout << "[TCP_CLIENT] Resolved '" << ip << "' to " << ip_str << std::endl;
        
        freeaddrinfo(result);
        
        // Connect to host machine through Docker bridge
        if (::connect(socket_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == 0) {
            connected = true;
            std::cout << "[TCP_CLIENT] ✓ Successfully connected to " << ip << " (" << ip_str << "):" << port << std::endl;
            std::cout << "[TCP_CLIENT] ✓ Docker bridge connection established!" << std::endl;
            return true;
        } else {
            std::cerr << "[TCP_CLIENT] ✗ Connection failed to " << ip << " (" << ip_str << "):" << port << ": " << strerror(errno) << std::endl;
            std::cerr << "[TCP_CLIENT] ✗ Make sure TCP server is running on host machine:" << std::endl;
            std::cerr << "[TCP_CLIENT] ✗   nc -l -k -p " << port << "   (on host machine)" << std::endl;
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
            std::cout << "[TCP_CLIENT] shutdown() + close()" << std::endl;
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
        
        if (arg == "--manual-cleanup") {
            config.manual_cleanup = true;
        } else if (arg == "--runtime" && i + 1 < argc) {
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
    
    std::cout << "=== Docker UDP Bug Reproduction ===" << std::endl;
    std::cout << "Mode: " << (config.manual_cleanup ? "PROPER" : "BUGGY") << " destruction order" << std::endl;
    std::cout << "Runtime: " << config.runtime_seconds << "s" << std::endl;
    std::cout << "TCP Host: " << config.tcp_host << ":" << TCP_PORT << std::endl;
    std::cout << "\nIMPORTANT: Start TCP server on HOST machine first:" << std::endl;
    std::cout << "  nc -l -k -p " << TCP_PORT << "   (recommended)" << std::endl;
    std::cout << "  or: nc -l -p " << TCP_PORT << "   (single connection)" << std::endl;
    
    try {
        // Create UDP server
        auto udp_server = std::make_unique<UdpServer>(config.log_file_path, config.manual_cleanup);
        if (!udp_server->start()) {
            std::cerr << "Failed to start UDP server" << std::endl;
            return 1;
        }
        
        // Create TCP client and connect to HOST machine (through Docker bridge)
        std::unique_ptr<TcpClient> tcp_client = std::make_unique<TcpClient>(config.tcp_host, TCP_PORT, config.manual_cleanup);
        if (!tcp_client->connect()) {
            std::cerr << "Failed to establish TCP connection to host machine" << std::endl;
            std::cerr << "This connection is REQUIRED for bug reproduction!" << std::endl;
            return 1;
        }
        
        // Verify successful connection
        if (!tcp_client->isConnected()) {
            std::cerr << "TCP connection not established" << std::endl;
            return 1;
        }
        
        std::cout << "\n=== Running for " << config.runtime_seconds << "s ===" << std::endl;
        std::cout << "✓ TCP connection to host established (through Docker bridge)" << std::endl;
        std::cout << "✓ UDP server listening on port " << UDP_PORT << std::endl;
        std::cout << "Test UDP with: echo 'TEST' | nc -u localhost " << UDP_PORT << std::endl;
        
        std::this_thread::sleep_for(std::chrono::seconds(config.runtime_seconds));
        
        std::cout << "\n=== Cleanup Phase ===" << std::endl;
        
        if (config.manual_cleanup) {
            // PROPER: Clean up in correct order (TCP first, then UDP)
            std::cout << "PROPER ORDER: TCP first, then UDP" << std::endl;
            tcp_client->properCleanup();
            udp_server->properCleanup();
        } else {
            // BUGGY: Force UDP destruction BEFORE TCP destruction
            // This is the key factor that corrupts Docker bridge (regardless of cleanup method)
            std::cout << "BUGGY ORDER: Forcing UDP destruction FIRST" << std::endl;
            std::cout << "This will corrupt Docker bridge even with proper shutdown+close!" << std::endl;
            udp_server.reset();  // Force UDP destruction before TCP
            // tcp_client will be destroyed automatically at end of scope
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    if (config.manual_cleanup) {
        std::cout << "\n=== PROPER DESTRUCTION ORDER COMPLETED ===" << std::endl;
        std::cout << "TCP destroyed first, then UDP - Docker bridge should remain healthy" << std::endl;
    } else {
        std::cout << "\n=== BUGGY DESTRUCTION ORDER COMPLETED ===" << std::endl;
        std::cout << "UDP destroyed first - Docker bridge is likely corrupted!" << std::endl;
        std::cout << "Next run may fail to receive UDP packets" << std::endl;
    }
    
    return 0;
} 