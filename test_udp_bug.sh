#!/bin/bash
set -e

# ============================================================================
# Docker UDP Bug Reproduction Framework
# ============================================================================
# 
# 🚨 CRITICAL BUG DISCOVERY: Docker UDP Port Forwarding Corruption
#
# This script reproduces a critical Docker bug where destroying UDP sockets 
# before TCP sockets corrupts Docker's internal UDP port forwarding mechanism
# for the affected container.
#
# KEY EVIDENCE: Docker's host UDP socket binding disappears
# - Working:   udp UNCONN 0 0  *:54603  *:*  (visible in ss output)
# - Corrupted: UDP binding completely MISSING from ss output
#
# WSL2/Docker Desktop Architecture Notes:
# - iptables not available (normal) - Docker Desktop uses internal proxy
# - Port forwarding handled at Windows host level, not within WSL2 VM  
# - Primary evidence source: ss -tulpn output showing UDP socket bindings
# - Empty iptables files are EXPECTED and normal in this environment
#
# Timeline of Corruption:
# - PRE-test BUGGY_1:  UDP binding ✅ Present
# - DURING-test BUGGY_1: UDP binding ✅ Present  
# - POST-test BUGGY_1:  UDP binding ❌ MISSING! <- Corruption occurs here
# - All BUGGY_2 phases:  UDP binding ❌ Missing (persistent until restart)
#
# Recovery: Container restart is sufficient (docker restart container_name)
# ============================================================================

CONTAINER_NAME="udp_bug_test"
UDP_PORT=54603
TCP_PORT=11002
PROGRAM="minimal_udp_bug_repro"
LOG_DIR="$(pwd)/log"
DEBUG_DIR="$(pwd)/debug"
TCP_SERVER_PID=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${YELLOW}=== Docker UDP Bug Test with Debug Tools ===${NC}"
echo "Bug: UDP socket destruction before TCP sockets corrupts Docker UDP forwarding"
echo "Method: HOST-TO-CONTAINER UDP communication + CONTAINER-TO-HOST TCP connection"
echo "Server: Python-based TCP server with integrated UDP client"
echo

# Cleanup function
cleanup() {
    echo -e "\n${BLUE}Cleaning up...${NC}"
    
    # Stop Python TCP/UDP server
    if [ -n "$TCP_SERVER_PID" ] && kill -0 "$TCP_SERVER_PID" 2>/dev/null; then
        echo "  Stopping Python TCP/UDP server (PID: $TCP_SERVER_PID)..."
        
        # Send SIGTERM first
        kill -TERM "$TCP_SERVER_PID" 2>/dev/null || true
        
        # Wait up to 5 seconds for graceful shutdown
        local timeout=5
        while [ $timeout -gt 0 ] && kill -0 "$TCP_SERVER_PID" 2>/dev/null; do
            sleep 1
            ((timeout--))
        done
        
        # Force kill if still running
        if kill -0 "$TCP_SERVER_PID" 2>/dev/null; then
            echo "  Force killing Python server..."
            kill -KILL "$TCP_SERVER_PID" 2>/dev/null || true
            sleep 1
        fi
        
        # Clean up any remaining wait
        wait "$TCP_SERVER_PID" 2>/dev/null || true
    fi
    
    # Clean container processes
    if docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        docker exec "$CONTAINER_NAME" pkill -f "$PROGRAM" 2>/dev/null || true
    fi
    
    echo "  ✓ Cleanup completed"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Debug data collection functions
collect_host_debug_data() {
    local phase="$1"
    local timestamp="$2"
    
    # Generate timestamp if not provided (for backward compatibility)
    if [ -z "$timestamp" ]; then
        timestamp=$(date '+%Y%m%d_%H%M%S')
    fi
    
    local debug_subdir="$DEBUG_DIR/${phase}_${timestamp}"
    mkdir -p "$debug_subdir"
    
    echo "  [DEBUG] Collecting host debug data for phase: $phase"
    
    # Network configuration
    ip addr show > "$debug_subdir/ip_addr.txt" 2>/dev/null || true
    ip route show table all > "$debug_subdir/ip_routes.txt" 2>/dev/null || true
    ip link show > "$debug_subdir/ip_links.txt" 2>/dev/null || true
    
    # Bridge state
    if command -v bridge >/dev/null 2>&1; then
        bridge link show > "$debug_subdir/bridge_links.txt" 2>/dev/null || true
        bridge fdb show > "$debug_subdir/bridge_fdb.txt" 2>/dev/null || true
        bridge vlan show > "$debug_subdir/bridge_vlans.txt" 2>/dev/null || true
    fi
    
    # Docker networking (critical for WSL2/Docker Desktop)
    docker network ls > "$debug_subdir/docker_networks.txt" 2>/dev/null || true
    if docker network inspect bridge >/dev/null 2>&1; then
        docker network inspect bridge > "$debug_subdir/docker_bridge_inspect.json" 2>/dev/null || true
    fi
    
    # Docker system information (WSL2/Docker Desktop specific)
    docker system info > "$debug_subdir/docker_system_info.txt" 2>/dev/null || true
    docker version > "$debug_subdir/docker_version.txt" 2>/dev/null || true
    
    # WSL2/Docker Desktop Port Forwarding Analysis
    # NOTE: Docker Desktop in WSL2 doesn't use iptables for port forwarding
    # Instead, it uses internal userland proxy mechanisms
    echo "# Docker Desktop WSL2 Port Forwarding Analysis" > "$debug_subdir/port_forwarding_analysis.txt"
    echo "# iptables not available in Docker Desktop WSL2 - this is normal" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "# Port forwarding handled by Docker Desktop internal proxy" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
    
    # Docker userland proxy debugging (WSL2 specific)
    echo "# Docker userland proxy debugging:" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "# Docker Desktop uses Windows-side proxy processes for port forwarding" >> "$debug_subdir/port_forwarding_analysis.txt"
    
    # Check Docker container port mappings
    if docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Container port mappings (Docker's view):" >> "$debug_subdir/port_forwarding_analysis.txt"
        docker port "$CONTAINER_NAME" >> "$debug_subdir/port_forwarding_analysis.txt" 2>&1 || echo "# No port mappings found" >> "$debug_subdir/port_forwarding_analysis.txt"
        
        echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Container network settings:" >> "$debug_subdir/port_forwarding_analysis.txt"
        docker inspect "$CONTAINER_NAME" --format '{{.NetworkSettings.Ports}}' >> "$debug_subdir/port_forwarding_analysis.txt" 2>&1 || true
        
        echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Container network namespace (internal view):" >> "$debug_subdir/port_forwarding_analysis.txt"
        docker exec "$CONTAINER_NAME" ss -tulpn | grep ":$UDP_PORT" >> "$debug_subdir/port_forwarding_analysis.txt" 2>&1 || echo "# No internal UDP binding found" >> "$debug_subdir/port_forwarding_analysis.txt"
    fi
    
    # Docker proxy process analysis (WSL2 specific)
    echo "# Docker proxy processes:" >> "$debug_subdir/port_forwarding_analysis.txt"
    ps aux | grep -E "(docker-proxy|docker.*proxy)" >> "$debug_subdir/port_forwarding_analysis.txt" 2>/dev/null || echo "# No docker-proxy processes found" >> "$debug_subdir/port_forwarding_analysis.txt"
    
    # Critical: UDP port binding analysis (PRIMARY EVIDENCE for the bug)
    echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "# CRITICAL: UDP port $UDP_PORT binding status (primary bug evidence):" >> "$debug_subdir/port_forwarding_analysis.txt"
    ss -tulpn | grep ":$UDP_PORT" >> "$debug_subdir/port_forwarding_analysis.txt" 2>/dev/null || echo "# NO UDP port $UDP_PORT binding found - CORRUPTION DETECTED!" >> "$debug_subdir/port_forwarding_analysis.txt"
    
    # Docker network namespace information
    echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "# Docker container network information:" >> "$debug_subdir/port_forwarding_analysis.txt"
    if docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        docker inspect "$CONTAINER_NAME" --format '{{.NetworkSettings.IPAddress}}' >> "$debug_subdir/port_forwarding_analysis.txt" 2>/dev/null || true
        docker port "$CONTAINER_NAME" >> "$debug_subdir/port_forwarding_analysis.txt" 2>/dev/null || true
    fi
    
    # Connection tracking
    if command -v conntrack >/dev/null 2>&1; then
        conntrack -L > "$debug_subdir/conntrack_all.txt" 2>/dev/null || true
        conntrack -L -p udp > "$debug_subdir/conntrack_udp.txt" 2>/dev/null || true
        conntrack -L -p tcp > "$debug_subdir/conntrack_tcp.txt" 2>/dev/null || true
        conntrack -S > "$debug_subdir/conntrack_stats.txt" 2>/dev/null || true
    fi
    
    if [ -f /proc/net/nf_conntrack ]; then
        cat /proc/net/nf_conntrack > "$debug_subdir/proc_nf_conntrack.txt" 2>/dev/null || true
    fi
    
    # Network statistics
    cat /proc/net/netstat > "$debug_subdir/proc_netstat.txt" 2>/dev/null || true
    cat /proc/net/snmp > "$debug_subdir/proc_snmp.txt" 2>/dev/null || true
    cat /proc/net/sockstat > "$debug_subdir/proc_sockstat.txt" 2>/dev/null || true
    cat /proc/net/udp > "$debug_subdir/proc_net_udp.txt" 2>/dev/null || true
    cat /proc/net/tcp > "$debug_subdir/proc_net_tcp.txt" 2>/dev/null || true
    
    # Socket information
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn > "$debug_subdir/ss_all.txt" 2>/dev/null || true
        ss -u > "$debug_subdir/ss_udp.txt" 2>/dev/null || true
        ss -t > "$debug_subdir/ss_tcp.txt" 2>/dev/null || true
    fi
    
    if command -v netstat >/dev/null 2>&1; then
        netstat -tulpn > "$debug_subdir/netstat_all.txt" 2>/dev/null || true
        netstat -s > "$debug_subdir/netstat_stats.txt" 2>/dev/null || true
    fi
    
    # Process information
    ps aux > "$debug_subdir/ps_aux.txt" 2>/dev/null || true
    if command -v lsof >/dev/null 2>&1; then
        lsof -i > "$debug_subdir/lsof_network.txt" 2>/dev/null || true
        lsof -i:$UDP_PORT > "$debug_subdir/lsof_udp_port.txt" 2>/dev/null || true
        lsof -i:$TCP_PORT > "$debug_subdir/lsof_tcp_port.txt" 2>/dev/null || true
    fi
    
    # Legacy iptables checking (expected to be empty in WSL2)
    echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
    if command -v iptables >/dev/null 2>&1; then
        echo "# iptables available - collecting rules (expected to be minimal in WSL2)" >> "$debug_subdir/port_forwarding_analysis.txt"
        iptables -t nat -L -n -v --line-numbers > "$debug_subdir/iptables_nat.txt" 2>/dev/null || true
        iptables -t filter -L -n -v --line-numbers > "$debug_subdir/iptables_filter.txt" 2>/dev/null || true
        iptables -t mangle -L -n -v --line-numbers > "$debug_subdir/iptables_mangle.txt" 2>/dev/null || true
        iptables -t raw -L -n -v --line-numbers > "$debug_subdir/iptables_raw.txt" 2>/dev/null || true
        iptables-save > "$debug_subdir/iptables_save.txt" 2>/dev/null || true
    else
        echo "# iptables not available (normal for Docker Desktop WSL2)" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Docker Desktop uses Windows-side userland proxy for port forwarding" >> "$debug_subdir/port_forwarding_analysis.txt"
        
        # Create empty files for compatibility with analysis scripts
        touch "$debug_subdir/iptables_nat.txt"
        touch "$debug_subdir/iptables_filter.txt" 
        touch "$debug_subdir/iptables_mangle.txt"
        touch "$debug_subdir/iptables_raw.txt"
        touch "$debug_subdir/iptables_save.txt"
    fi
    
    echo "  [DEBUG] Host debug data saved to: $debug_subdir"
}

collect_container_debug_data() {
    local phase="$1"
    local timestamp="$2"
    
    # Generate timestamp if not provided (for backward compatibility)
    if [ -z "$timestamp" ]; then
        timestamp=$(date '+%Y%m%d_%H%M%S')
    fi
    
    local debug_subdir="$DEBUG_DIR/${phase}_${timestamp}"
    mkdir -p "$debug_subdir"
    
    echo "  [DEBUG] Collecting container debug data for phase: $phase"
    
    if ! docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "  [DEBUG] Container not running, skipping container debug collection"
        return 0
    fi
    
    # Container network namespace info
    docker exec "$CONTAINER_NAME" ip addr show > "$debug_subdir/container_ip_addr.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" ip route show > "$debug_subdir/container_ip_routes.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" ip link show > "$debug_subdir/container_ip_links.txt" 2>/dev/null || true
    
    # Container network statistics
    docker exec "$CONTAINER_NAME" cat /proc/net/netstat > "$debug_subdir/container_proc_netstat.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /proc/net/snmp > "$debug_subdir/container_proc_snmp.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /proc/net/sockstat > "$debug_subdir/container_proc_sockstat.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /proc/net/udp > "$debug_subdir/container_proc_net_udp.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" cat /proc/net/tcp > "$debug_subdir/container_proc_net_tcp.txt" 2>/dev/null || true
    
    # Container socket information
    docker exec "$CONTAINER_NAME" netstat -tulpn > "$debug_subdir/container_netstat.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" netstat -s > "$debug_subdir/container_netstat_stats.txt" 2>/dev/null || true
    docker exec "$CONTAINER_NAME" ss -tulpn > "$debug_subdir/container_ss.txt" 2>/dev/null || true
    
    # Container process information
    docker exec "$CONTAINER_NAME" ps aux > "$debug_subdir/container_ps.txt" 2>/dev/null || true
    
    # Container inspect
    docker inspect "$CONTAINER_NAME" > "$debug_subdir/container_inspect.json" 2>/dev/null || true
    
    echo "  [DEBUG] Container debug data saved to: $debug_subdir"
}

start_packet_capture() {
    local phase="$1"
    local timestamp="$2"
    
    # Generate timestamp if not provided (for backward compatibility)
    if [ -z "$timestamp" ]; then
        timestamp=$(date '+%Y%m%d_%H%M%S')
    fi
    
    local debug_subdir="$DEBUG_DIR/${phase}_${timestamp}"
    mkdir -p "$debug_subdir"
    
    echo "  [DEBUG] Starting packet capture for phase: $phase"
    
    # Capture on all interfaces
    tcpdump -i any -w "$debug_subdir/tcpdump_any.pcap" "udp port $UDP_PORT or tcp port $TCP_PORT" >/dev/null 2>&1 &
    local tcpdump_any_pid=$!
    
    # Capture on docker bridge
    tcpdump -i docker0 -w "$debug_subdir/tcpdump_docker0.pcap" >/dev/null 2>&1 &
    local tcpdump_docker_pid=$!
    
    # Capture on host interface
    local host_iface=$(ip route get 8.8.8.8 | head -1 | awk '{print $5}')
    if [ -n "$host_iface" ]; then
        tcpdump -i "$host_iface" -w "$debug_subdir/tcpdump_host.pcap" "udp port $UDP_PORT or tcp port $TCP_PORT" >/dev/null 2>&1 &
        local tcpdump_host_pid=$!
    fi
    
    # Store PIDs for later cleanup
    echo "$tcpdump_any_pid" > "$debug_subdir/tcpdump_pids.txt"
    echo "$tcpdump_docker_pid" >> "$debug_subdir/tcpdump_pids.txt"
    [ -n "$tcpdump_host_pid" ] && echo "$tcpdump_host_pid" >> "$debug_subdir/tcpdump_pids.txt"
    
    sleep 1  # Let tcpdump start
    echo "  [DEBUG] Packet capture started, PIDs saved to: $debug_subdir/tcpdump_pids.txt"
}

stop_packet_capture() {
    local phase="$1"
    
    echo "  [DEBUG] Stopping packet capture for phase: $phase"
    
    # Find the most recent tcpdump_pids.txt file for this phase
    local pids_file=$(find "$DEBUG_DIR" -name "tcpdump_pids.txt" -path "*${phase}*" | sort | tail -1)
    
    if [ -f "$pids_file" ]; then
        while read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
                sleep 0.5
            fi
        done < "$pids_file"
        echo "  [DEBUG] Packet capture stopped"
    else
        echo "  [DEBUG] No packet capture PIDs found"
    fi
}

# Enhanced setup container with debug tools
setup_container() {
    echo -e "${BLUE}Setting up container with debug tools...${NC}"
    
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo "  Found existing container, restarting..."
        docker restart "$CONTAINER_NAME" >/dev/null
        echo "  ✓ Container restarted"
    else
        echo "  Creating new container..."
        docker run -d --name "$CONTAINER_NAME" \
            --cap-add=NET_ADMIN \
            --cap-add=SYS_ADMIN \
            -p "$UDP_PORT:$UDP_PORT/udp" \
            -v "$(pwd):/workspace" \
            -w /workspace \
            ubuntu:24.04 sleep infinity >/dev/null
        echo "  ✓ Container created"
    fi

    echo "  Installing dependencies and debug tools..."
    docker exec "$CONTAINER_NAME" apt-get update -qq >/dev/null
    docker exec "$CONTAINER_NAME" apt-get install -y -qq \
        netcat-openbsd build-essential \
        tcpdump iproute2 net-tools \
        iptables conntrack \
        strace ltrace \
        procps psmisc \
        bridge-utils \
        ethtool \
        python3 \
        >/dev/null
    
    echo "  ✓ Container ready with debug tools"
}

stop_tcp_server() {
    # Check if port is already in use and clean it up
    if lsof -i:$TCP_PORT >/dev/null 2>&1; then
        echo "  Port $TCP_PORT is already in use, cleaning up..."
        
        # Get PIDs using the port
        local pids=$(lsof -ti:$TCP_PORT)
        if [ -n "$pids" ]; then
            echo "  Killing existing processes: $pids"
            echo "$pids" | xargs kill -TERM 2>/dev/null || true
            
            # Wait for processes to terminate
            sleep 2
            
            # Force kill if still running
            if lsof -i:$TCP_PORT >/dev/null 2>&1; then
                echo "  Force killing stubborn processes..."
                lsof -ti:$TCP_PORT | xargs kill -KILL 2>/dev/null || true
                sleep 1
            fi
        fi
        
        # Final check
        if lsof -i:$TCP_PORT >/dev/null 2>&1; then
            echo -e "${RED}✗ Could not free port $TCP_PORT${NC}"
            echo "Manual cleanup required: sudo lsof -ti:$TCP_PORT | xargs kill"
            exit 1
        fi
        
        echo "  ✓ Port $TCP_PORT cleaned up successfully"
    fi
}

# Start TCP server on host
start_tcp_server() {
    echo -e "${BLUE}Starting Python TCP/UDP server on host...${NC}"
    
    # Start Python TCP server with UDP client functionality
    echo "  Starting Python server that sends UDP messages to container when TCP clients connect..."
    
    # Make sure the Python script is executable
    chmod +x "$(pwd)/tcp_udp_server.py"
    
    # Start the Python server
    python3 "$(pwd)/tcp_udp_server.py" \
        --tcp-port "$TCP_PORT" \
        --udp-host "$HOST_IP" \
        --udp-port "$UDP_PORT" \
        >> "$LOG_DIR/tcp_server.log" 2>&1 &
    TCP_SERVER_PID=$!
    
    # Wait for server to be ready
    sleep 2
    for i in {1..10}; do
        if lsof -i:$TCP_PORT >/dev/null 2>&1; then
            echo "  ✓ Python TCP/UDP server ready (PID: $TCP_SERVER_PID)"
            echo "  ✓ Server listening on port $TCP_PORT"
            echo "  ✓ Will send UDP messages to $HOST_IP:$UDP_PORT"
            echo "  ✓ Will continuously send UDP messages to container until client disconnects"
            return 0
        fi
        sleep 0.5
    done
    
    echo -e "${RED}✗ Python TCP/UDP server failed to start${NC}"
    echo "Debug: Checking if server process is running..."
    if kill -0 "$TCP_SERVER_PID" 2>/dev/null; then
        echo "  Process is running but not listening on port"
        echo "  Python server log:"
        cat "$LOG_DIR/tcp_server.log" 2>/dev/null || echo "  (no log available)"
    else
        echo "  Process exited. Check Python server log:"
        cat "$LOG_DIR/tcp_server.log" 2>/dev/null || echo "  (no log available)"
    fi
    exit 1
}

# Detect host IP for container-to-host connections
detect_host_ip() {
    echo -e "${BLUE}Detecting host IP for Docker bridge...${NC}"
    
    # In WSL2, the Docker bridge gateway doesn't work for host connections
    # Use the host's actual IP address instead
    HOST_IP=$(hostname -I | awk '{print $1}')
    
    if [ -z "$HOST_IP" ]; then
        echo -e "${RED}✗ Could not detect host IP${NC}"
        exit 1
    fi
    
    echo "  ✓ Using host IP: $HOST_IP"
}

# Check host dependencies
if ! command -v nc >/dev/null 2>&1; then
    echo -e "${RED}✗ netcat (nc) not available on host${NC}"
    echo "Install with: sudo apt-get install netcat-openbsd"
    exit 1
fi

if ! command -v lsof >/dev/null 2>&1; then
    echo -e "${RED}✗ lsof not available on host${NC}"
    echo "Install with: sudo apt-get install lsof"
    exit 1
fi

# Check for Python 3 (required for TCP/UDP server)
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}✗ python3 not available${NC}"
    echo "Install with: sudo apt-get install python3"
    exit 1
else
    echo "  ✓ python3 available for TCP/UDP server"
fi

# Install debug tools on host if needed
install_host_debug_tools() {
    echo -e "${BLUE}Installing debug tools on host...${NC}"
    
    local tools_needed=""
    
    if ! command -v tcpdump >/dev/null 2>&1; then
        tools_needed="$tools_needed tcpdump"
    fi
    
    if ! command -v conntrack >/dev/null 2>&1; then
        tools_needed="$tools_needed conntrack"
    fi
    
    if ! command -v bridge >/dev/null 2>&1; then
        tools_needed="$tools_needed bridge-utils"
    fi
    
    if ! command -v ss >/dev/null 2>&1; then
        tools_needed="$tools_needed iproute2"
    fi
    
    if [ -n "$tools_needed" ]; then
        echo "  Installing missing tools:$tools_needed"
        sudo apt-get update -qq >/dev/null 2>&1 || true
        if sudo apt-get install -y -qq $tools_needed >/dev/null 2>&1; then
            echo "  ✓ Debug tools installed successfully"
        else
            echo -e "${YELLOW}⚠ Some debug tools installation failed, continuing anyway${NC}"
        fi
    else
        echo "  ✓ All debug tools already available"
    fi
}

# Setup
rm -rf "$LOG_DIR" "$DEBUG_DIR" && mkdir -p "$LOG_DIR" "$DEBUG_DIR"

# Install debug tools
install_host_debug_tools

# Check if advanced debugging is available (requires root)
ADVANCED_DEBUG_AVAILABLE=false
if [ "$EUID" -eq 0 ] && [ -f "$(pwd)/advanced_debug.sh" ]; then
    echo -e "${BLUE}Root privileges detected - enabling advanced kernel debugging${NC}"
    source "$(pwd)/advanced_debug.sh"
    
    # Setup advanced debugging tools
    if setup_ftrace && setup_ebpf_monitoring; then
        ADVANCED_DEBUG_AVAILABLE=true
        echo -e "${GREEN}  ✓ Advanced debugging tools configured${NC}"
    else
        echo -e "${YELLOW}  ⚠ Some advanced debugging tools failed to configure${NC}"
    fi
else
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}⚠ Not running as root - advanced kernel debugging disabled${NC}"
        echo "  For full debugging capabilities, run with: sudo ./test_udp_bug.sh"
    fi
    if [ ! -f "$(pwd)/advanced_debug.sh" ]; then
        echo -e "${YELLOW}⚠ Advanced debug script not found${NC}"
    fi
fi

# Detect correct host IP for Docker bridge connections
detect_host_ip

# Collect initial system state
echo -e "${BLUE}Collecting initial debug data...${NC}"
initial_timestamp=$(date '+%Y%m%d_%H%M%S')
collect_host_debug_data "initial" "$initial_timestamp"

if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
    start_advanced_monitoring "initial" "$CONTAINER_NAME"
fi

# Start TCP server FIRST (required for container TCP connections)
stop_tcp_server
start_tcp_server

# Then setup container
setup_container

# Collect post-setup debug data
post_setup_timestamp=$(date '+%Y%m%d_%H%M%S')
collect_host_debug_data "post_setup" "$post_setup_timestamp"
collect_container_debug_data "post_setup" "$post_setup_timestamp"

# Build program
echo -e "${BLUE}Building test program...${NC}"
docker exec "$CONTAINER_NAME" make clean >/dev/null
docker exec "$CONTAINER_NAME" make >/dev/null
echo "✓ Program built"

# Send UDP message from host to container
send_udp_message() {
    local test_msg="$1"
    echo "    [SEND] '$test_msg' from HOST to container"
    echo "$test_msg" | nc -u -w1 $HOST_IP "$UDP_PORT" 2>/dev/null
}

# Check if message was logged to file
check_message_logged() {
    local test_msg="$1"
    local log_file="$2"
    
    sleep 0.5  # Brief wait for file write
    
    if [ -f "$log_file" ] && grep -q "MESSAGE=$test_msg" "$log_file" 2>/dev/null; then
        echo "    [✓] Message found in log"
        return 0
    else
        echo "    [✗] Message NOT found in log"
        return 1
    fi
}

# Enhanced run test with debug data collection
run_test() {
    local test_name="$1"
    local cleanup_mode="$2"
    local server_runtime=15
    
    echo -e "${BLUE}Running $test_name (${cleanup_mode} cleanup)...${NC}"
    
    local log_file="$LOG_DIR/${test_name}.log"
    local container_log_file="/workspace/log/${test_name}.log"
    local server_log="$LOG_DIR/${test_name}_server.log"
    local container_server_log="/workspace/log/${test_name}_server.log"
    
    rm -f "$log_file" "$server_log"
    
    # Collect pre-test debug data and start packet capture
    echo "  [DEBUG] Collecting pre-test debug data..."
    local pre_test_timestamp=$(date '+%Y%m%d_%H%M%S')
    collect_host_debug_data "pre_test_${test_name}" "$pre_test_timestamp"
    collect_container_debug_data "pre_test_${test_name}" "$pre_test_timestamp"
    
    local test_timestamp=$(date '+%Y%m%d_%H%M%S')
    start_packet_capture "test_${test_name}" "$test_timestamp"
    
    if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
        start_advanced_monitoring "test_${test_name}" "$CONTAINER_NAME"
    fi
    
    # Start UDP server with TCP client connection
    echo "  Starting UDP server with TCP connection to host..."
    if [ "$cleanup_mode" = "manual" ]; then
        docker exec -d "$CONTAINER_NAME" bash -c \
            "/workspace/bin/$PROGRAM --manual-cleanup --runtime $server_runtime --log-file $container_log_file --tcp-host $HOST_IP > $container_server_log 2>&1"
    else
        docker exec -d "$CONTAINER_NAME" bash -c \
            "/workspace/bin/$PROGRAM --runtime $server_runtime --log-file $container_log_file --tcp-host $HOST_IP > $container_server_log 2>&1"
    fi
    
    # Wait for server to be ready
    for i in {1..20}; do
        if docker exec "$CONTAINER_NAME" netstat -tulnp 2>/dev/null | grep -q ":$UDP_PORT "; then
            break
        fi
        sleep 0.25
    done
    
    sleep 2  # Additional startup time for TCP connection
    
    # Collect during-test debug data
    echo "  [DEBUG] Collecting during-test debug data..."
    local during_test_timestamp=$(date '+%Y%m%d_%H%M%S')
    collect_host_debug_data "during_test_${test_name}" "$during_test_timestamp"
    collect_container_debug_data "during_test_${test_name}" "$during_test_timestamp"
    
    # Verify TCP connection was established
    echo "  Verifying TCP connection to host..."
    if grep -q "Successfully connected" "$LOG_DIR/${test_name}_server.log" 2>/dev/null; then
        echo "    [✓] TCP connection to host established"
    else
        echo "    [⚠] TCP connection status unclear - continuing test"
    fi
    
    # Test UDP communication
    local success_count=0
    local total_tests=3

    echo "  Testing UDP communication..."
    for test_num in $(seq 1 $total_tests); do
        local test_msg="TEST_${test_name}_${test_num}_$$"
        
        # Collect debug data before each UDP test
        if [ $test_num -eq 1 ]; then
            local before_udp_timestamp=$(date '+%Y%m%d_%H%M%S')
            collect_host_debug_data "before_udp_${test_name}" "$before_udp_timestamp"
        fi
        
        if send_udp_message "$test_msg" && check_message_logged "$test_msg" "$log_file"; then
            ((success_count++))
        fi
        sleep 0.5
    done
    
    echo "  Results: $success_count/$total_tests successful"
    
    # Wait for server to finish
    echo "  Waiting for server cleanup..."
    sleep $((server_runtime + 2))
    
    # Collect post-test debug data
    echo "  [DEBUG] Collecting post-test debug data..."
    local post_test_timestamp=$(date '+%Y%m%d_%H%M%S')
    collect_host_debug_data "post_test_${test_name}" "$post_test_timestamp"
    collect_container_debug_data "post_test_${test_name}" "$post_test_timestamp"
    
    # Stop packet capture
    stop_packet_capture "test_${test_name}"
    
    if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
        stop_advanced_monitoring "test_${test_name}" "$CONTAINER_NAME"
    fi
    
    # Cleanup any remaining processes
    docker exec "$CONTAINER_NAME" pkill -f "$PROGRAM" 2>/dev/null || true
    sleep 1
    
    # Collect final cleanup debug data
    local final_cleanup_timestamp=$(date '+%Y%m%d_%H%M%S')
    collect_host_debug_data "final_cleanup_${test_name}" "$final_cleanup_timestamp"
    collect_container_debug_data "final_cleanup_${test_name}" "$final_cleanup_timestamp"
    
    if [ $success_count -eq $total_tests ]; then
        echo -e "${GREEN}  ✓ PASS${NC}"
        return 0
    elif [ $success_count -ge 1 ]; then
        echo -e "${YELLOW}  ~ PARTIAL${NC}"
        return 0
    else
        echo -e "${RED}  ✗ FAIL${NC}"
        echo "  Debug: Check server log at $server_log"
        if [ -f "$server_log" ]; then
            echo "  Last 5 lines from server:"
            tail -5 "$server_log" 2>/dev/null | sed 's/^/    /' || echo "    (log unavailable)"
        fi
        return 1
    fi
}

# Ensure clean state
ensure_clean_state() {
    docker exec "$CONTAINER_NAME" pkill -f "$PROGRAM" 2>/dev/null || true
    sleep 2
}

echo

# Test 1: Proper destruction order
echo -e "${GREEN}=== TEST 1: Proper Destruction Order ===${NC}"
echo "Pattern: TCP destroyed first, then UDP - should NOT corrupt Docker bridge"

ensure_clean_state
if run_test "PROPER_1" "manual"; then
    TEST1_1="PASS"
else
    TEST1_1="FAIL"
fi

echo
sleep 3
ensure_clean_state

if run_test "PROPER_2" "manual"; then
    TEST1_2="PASS"
else
    TEST1_2="FAIL"
fi

echo
sleep 3
ensure_clean_state

# Test 2: Buggy destruction order
echo -e "${RED}=== TEST 2: Buggy Destruction Order ===${NC}"
echo "Pattern: UDP destroyed first - corrupts Docker bridge"

if run_test "BUGGY_1" "auto"; then
    TEST2_1="PASS"
else
    TEST2_1="FAIL"
fi

echo
sleep 3
ensure_clean_state

if run_test "BUGGY_2" "auto"; then
    TEST2_2="PASS"
else
    TEST2_2="FAIL"
fi

echo

# Collect final system state
echo -e "${BLUE}Collecting final debug data...${NC}"
final_timestamp=$(date '+%Y%m%d_%H%M%S')
collect_host_debug_data "final" "$final_timestamp"
collect_container_debug_data "final" "$final_timestamp"

if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
    stop_advanced_monitoring "final" "$CONTAINER_NAME"
fi

# Results Summary
echo -e "${BLUE}=== RESULTS ===${NC}"
echo "1. Proper Order #1:      $TEST1_1"
echo "2. Proper Order #2:      $TEST1_2"
echo "3. Buggy Order #1:       $TEST2_1"
echo "4. Buggy Order #2:       $TEST2_2"

echo
echo -e "${YELLOW}=== ANALYSIS ===${NC}"

# Check proper destruction order
if [ "$TEST1_1" = "PASS" ] && [ "$TEST1_2" = "PASS" ]; then
    echo -e "${GREEN}✅ Proper destruction order: Working correctly${NC}"
    echo "   Both runs succeeded → TCP-first destruction prevents corruption"
else
    echo -e "${RED}❌ Proper destruction order: Unexpected failure${NC}"
fi

# Check buggy destruction order
if [ "$TEST2_1" = "PASS" ] && [ "$TEST2_2" = "FAIL" ]; then
    echo -e "${RED}🎯 DOCKER UDP BUG CONFIRMED!${NC}"
    echo "   First run: SUCCESS → Docker bridge healthy"
    echo "   Second run: FAILED → Docker bridge corrupted by UDP-first destruction"
    echo "   Root cause: UDP socket destroyed before TCP socket corrupts Docker's bridge state"
elif [ "$TEST2_1" = "PASS" ] && [ "$TEST2_2" = "PASS" ]; then
    echo -e "${YELLOW}⚠ Docker UDP bug NOT reproduced${NC}"
    echo "   Both runs succeeded → Bug may not affect this Docker version"
else
    echo -e "${RED}❌ Buggy destruction order: Unexpected pattern${NC}"
fi

echo
echo -e "${BLUE}=== DEBUG DATA COLLECTED (WSL2/Docker Desktop) ===${NC}"
echo "  • Debug data location: $DEBUG_DIR/"
echo "  • PRIMARY EVIDENCE: port_forwarding_analysis.txt - UDP socket binding status"
echo "  • Packet captures: *.pcap files"
echo "  • Network state: *ip_*, *bridge_*, *docker_* files"
echo "  • Connection tracking: *conntrack_* files" 
echo "  • Docker system info: docker_system_info.txt, docker_version.txt"
echo "  • iptables files: *iptables_* (expected to be empty in WSL2)"
echo "  • Network statistics: *proc_* files"
echo "  • Socket states: ss_all.txt (CRITICAL - primary bug evidence)"
if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
    echo "  • Advanced debugging: $DEBUG_DIR/advanced/"
    echo "    - ftrace kernel function traces"
    echo "    - eBPF monitoring logs"
    echo "    - Kernel message logs"
    echo "    - Network namespace snapshots"
    echo "    - Connection tracking event logs"
fi
echo
echo -e "${YELLOW}=== WSL2/Docker Desktop Analysis Guide ===${NC}"
echo "  • Key Evidence File: debug/*/port_forwarding_analysis.txt"
echo "  • Look for: 'UDP port $UDP_PORT binding status' section"
echo "  • Bug confirmed if: UDP binding disappears between phases"
echo "  • Compare: during_test_BUGGY_1 vs post_test_BUGGY_1"
echo
echo "Investigation commands:"
echo "  • Check current UDP binding: ss -tulpn | grep \":$UDP_PORT\""
echo "  • Test current corruption: echo 'TEST' | nc -u localhost $UDP_PORT"
echo "  • Check UDP logs: cat $LOG_DIR/*_server.log"
echo "  • Check message logs: cat $LOG_DIR/*.log"
echo "  • Check Python TCP/UDP server log: cat $LOG_DIR/tcp_server.log"
echo "  • All logs: ls -la $LOG_DIR/"
echo "  • Debug data: ls -la $DEBUG_DIR/"
echo "  • Packet analysis: wireshark $DEBUG_DIR/*/tcpdump_*.pcap"
echo "  • Automated analysis: ./analyze_debug_data.sh"
echo "  • Find working phases: find debug -name ss_all.txt | xargs grep -l \"*:$UDP_PORT\""
echo "  • Compare states: diff debug/during_test_BUGGY_1_*/ss_all.txt debug/post_test_BUGGY_1_*/ss_all.txt"
if [ "$ADVANCED_DEBUG_AVAILABLE" = true ]; then
    echo "  • Advanced analysis: grep -r 'DROP\\|ERROR\\|FAIL' $DEBUG_DIR/advanced/"
    echo "  • ftrace analysis: less $DEBUG_DIR/advanced/ftrace_*.txt"
    echo "  • eBPF logs: less $DEBUG_DIR/advanced/ebpf_*.log"
fi
echo
echo -e "${RED}=== Recovery from Corruption ===${NC}"
echo "If UDP forwarding is corrupted (no udp *:$UDP_PORT in ss output):"
echo "  • Restart container: docker restart $CONTAINER_NAME (sufficient)"
echo "  • Or recreate container: docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
echo "  • Or restart Docker Desktop (overkill but works)"
echo "  • Or restart WSL2: wsl --shutdown (from Windows)"
echo
echo "Cleanup:"
echo "  • Remove container: docker rm -f $CONTAINER_NAME"
echo "  • Remove debug data: rm -rf $DEBUG_DIR $LOG_DIR" 