#!/bin/bash
set -e

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

echo -e "${YELLOW}=== Docker UDP Burst Traffic Instability Test ===${NC}"
echo "CRITICAL FINDING: Docker UDP forwarding fails with burst patterns even with proper socket cleanup"
echo "Method: HOST-TO-CONTAINER burst UDP + CONTAINER-TO-HOST TCP connection"
echo "Server: Python TCP/UDP server with burst pattern (10 msgs + 5s pause)"
echo "Focus: Demonstrating Docker UDP instability despite proper application behavior"
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
    
    local debug_subdir="$DEBUG_DIR/${phase}"
    mkdir -p "$debug_subdir"
    
    echo "  [DEBUG] Collecting essential debug data for phase: $phase"
    
    # CRITICAL: UDP port binding analysis (PRIMARY EVIDENCE for the bug)
    echo "# Docker UDP Burst Traffic Instability Analysis" > "$debug_subdir/port_forwarding_analysis.txt"
    echo "# Primary Evidence: UDP socket binding status" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
    echo "# CRITICAL: UDP port $UDP_PORT binding status (primary bug evidence):" >> "$debug_subdir/port_forwarding_analysis.txt"
    ss -tulpn | grep ":$UDP_PORT" >> "$debug_subdir/port_forwarding_analysis.txt" 2>/dev/null || echo "# NO UDP port $UDP_PORT binding found - CORRUPTION DETECTED!" >> "$debug_subdir/port_forwarding_analysis.txt"
    
    # Docker container port mappings (Docker's view)
    if docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Container port mappings (Docker's view):" >> "$debug_subdir/port_forwarding_analysis.txt"
        docker port "$CONTAINER_NAME" >> "$debug_subdir/port_forwarding_analysis.txt" 2>&1 || echo "# No port mappings found" >> "$debug_subdir/port_forwarding_analysis.txt"
        
        echo "" >> "$debug_subdir/port_forwarding_analysis.txt"
        echo "# Container network settings:" >> "$debug_subdir/port_forwarding_analysis.txt"
        docker inspect "$CONTAINER_NAME" --format '{{.NetworkSettings.Ports}}' >> "$debug_subdir/port_forwarding_analysis.txt" 2>&1 || true
    fi
    
    # Essential socket information (PRIMARY EVIDENCE)
    if command -v ss >/dev/null 2>&1; then
        ss -tulpn > "$debug_subdir/ss_all.txt" 2>/dev/null || true
    fi
    
    # Basic container state
    if docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        docker inspect "$CONTAINER_NAME" > "$debug_subdir/container_inspect.json" 2>/dev/null || true
    fi
    
    echo "  [DEBUG] Essential debug data saved to: $debug_subdir"
}

collect_container_debug_data() {
    local phase="$1"
    
    local debug_subdir="$DEBUG_DIR/${phase}"
    mkdir -p "$debug_subdir"
    
    echo "  [DEBUG] Collecting container debug data for phase: $phase"
    
    if ! docker ps -q -f name="$CONTAINER_NAME" >/dev/null 2>&1; then
        echo "  [DEBUG] Container not running, skipping container debug collection"
        return 0
    fi
    
    # Container socket information (to verify internal state)
    docker exec "$CONTAINER_NAME" ss -tulpn > "$debug_subdir/container_ss.txt" 2>/dev/null || true
    
    # Container process information (basic verification)
    docker exec "$CONTAINER_NAME" ps aux > "$debug_subdir/container_ps.txt" 2>/dev/null || true
    
    echo "  [DEBUG] Container debug data saved to: $debug_subdir"
}



# Enhanced setup container with minimal debug tools
setup_container() {
    echo -e "${BLUE}Setting up container...${NC}"
    
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        echo "  Found existing container, restarting..."
        docker restart "$CONTAINER_NAME" >/dev/null
        echo "  ✓ Container restarted"
    else
        echo "  Creating new container..."
        docker run -d --name "$CONTAINER_NAME" \
            -p "$UDP_PORT:$UDP_PORT/udp" \
            -v "$(pwd):/workspace" \
            -w /workspace \
            ubuntu:24.04 sleep infinity >/dev/null
        echo "  ✓ Container created"
    fi

    echo "  Installing essential dependencies..."
    docker exec "$CONTAINER_NAME" apt-get update -qq >/dev/null
    docker exec "$CONTAINER_NAME" apt-get install -y -qq \
        netcat-openbsd build-essential \
        iproute2 net-tools \
        procps \
        >/dev/null
    
    echo "  ✓ Container ready"
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

# Install essential host tools if needed
if ! command -v tcpdump >/dev/null 2>&1; then
    echo -e "${BLUE}Installing tcpdump for packet capture...${NC}"
    sudo apt-get update -qq >/dev/null 2>&1 || true
    sudo apt-get install -y -qq tcpdump >/dev/null 2>&1 || echo -e "${YELLOW}⚠ tcpdump installation failed, packet capture disabled${NC}"
fi

# Setup
rm -rf "$LOG_DIR" "$DEBUG_DIR" && mkdir -p "$LOG_DIR" "$DEBUG_DIR"

# Detect correct host IP for Docker bridge connections
detect_host_ip

# Start TCP server FIRST (required for container TCP connections)
stop_tcp_server
start_tcp_server

# Then setup container
setup_container

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

# Simplified run test - collect only essential debug data for bug demonstration
run_test() {
    local test_name="$1"
    local server_runtime=15
    
    echo -e "${BLUE}Running $test_name (proper cleanup)...${NC}"
    
    local log_file="$LOG_DIR/${test_name}.log"
    local container_log_file="/workspace/log/${test_name}.log"
    local server_log="$LOG_DIR/${test_name}_server.log"
    local container_server_log="/workspace/log/${test_name}_server.log"
    
    rm -f "$log_file" "$server_log"
    
    # Start UDP server with TCP client connection
    echo "  Starting UDP server with TCP connection to host..."
    docker exec -d "$CONTAINER_NAME" bash -c \
        "/workspace/bin/$PROGRAM --runtime $server_runtime --log-file $container_log_file --tcp-host $HOST_IP > $container_server_log 2>&1"
    
    # Wait for server to be ready
    for i in {1..20}; do
        if docker exec "$CONTAINER_NAME" netstat -tulnp 2>/dev/null | grep -q ":$UDP_PORT "; then
            break
        fi
        sleep 0.25
    done
    
    sleep 2  # Additional startup time for TCP connection
    
    # CRITICAL: Collect debug data during test execution (key evidence)
    echo "  [DEBUG] Collecting critical debug state for $test_name..."
    local simple_name=""
    if [[ "$test_name" == "PROPER_1" ]]; then
        simple_name="test_1"
    elif [[ "$test_name" == "PROPER_2" ]]; then
        simple_name="test_2"
    fi
    collect_host_debug_data "$simple_name"
    collect_container_debug_data "$simple_name"
    
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
        
        if send_udp_message "$test_msg" && check_message_logged "$test_msg" "$log_file"; then
            ((success_count++))
        fi
        sleep 0.5
    done
    
    echo "  Results: $success_count/$total_tests successful"
    
    # Wait for server to finish
    echo "  Waiting for server cleanup..."
    sleep $((server_runtime + 2))
    
    # Cleanup any remaining processes
    docker exec "$CONTAINER_NAME" pkill -f "$PROGRAM" 2>/dev/null || true
    sleep 1
    
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

# Test: Docker UDP forwarding stability with burst traffic and proper socket handling
echo -e "${GREEN}=== TEST: Docker UDP Burst Traffic Stability ===${NC}"
echo "Pattern: Burst UDP traffic (10 msgs + 5s pause) + proper socket destruction (TCP → UDP)"

ensure_clean_state
if run_test "PROPER_1"; then
    TEST1="PASS"
else
    TEST1="FAIL"
fi

echo
sleep 3
ensure_clean_state

if run_test "PROPER_2"; then
    TEST2="PASS"
else
    TEST2="FAIL"
fi

echo

# Results Summary
echo -e "${BLUE}=== RESULTS ===${NC}"
echo "1. Proper Order #1:      $TEST1"
echo "2. Proper Order #2:      $TEST2"

echo
echo -e "${YELLOW}=== ANALYSIS ===${NC}"

# Check Docker UDP forwarding stability with burst traffic
if [ "$TEST1" = "PASS" ] && [ "$TEST2" = "PASS" ]; then
    echo -e "${GREEN}✅ Docker UDP forwarding: Stable with burst traffic${NC}"
    echo "   Both runs succeeded → Docker handles burst patterns correctly"
    echo "   No instability detected with current Docker version"
elif [ "$TEST1" = "PASS" ] && [ "$TEST2" = "FAIL" ]; then
    echo -e "${RED}🎯 DOCKER UDP BURST INSTABILITY CONFIRMED!${NC}"
    echo "   First run: PASS → Docker initially handles burst traffic"
    echo "   Second run: FAIL → Docker UDP forwarding corrupted by burst exposure"
    echo "   ROOT CAUSE: Docker UDP forwarding instability with burst patterns"
    echo "   CRITICAL: This occurs despite proper socket destruction order!"
else
    echo -e "${RED}❌ Docker UDP forwarding: Unexpected failure pattern${NC}"
    echo "   This may indicate environmental issues or different Docker behavior"
    echo "   Check Docker networking configuration and container setup"
fi

echo
echo -e "${BLUE}=== CRITICAL DEBUG DATA COLLECTED ===${NC}"
echo "  • Debug data location: $DEBUG_DIR/"
echo "  • WORKING STATE: test_1/ (UDP forwarding functional)"
echo "  • CORRUPTED STATE: test_2/ (UDP forwarding failed)"
echo "  • KEY EVIDENCE: ss_all.txt in each directory"
echo "  • Socket binding comparison: UDP port $UDP_PORT presence/absence"
echo "  • Network state: Docker bridge and port forwarding status"
echo
echo -e "${YELLOW}=== SIMPLIFIED ANALYSIS GUIDE ===${NC}"
echo "  • Compare two critical states: test_1 vs test_2"
echo "  • Key evidence: ss_all.txt files in each directory"
echo "  • Working state: 'udp *:$UDP_PORT' present in test_1"
echo "  • Corrupted state: 'udp *:$UDP_PORT' missing in test_2"
echo "  • Port forwarding analysis: port_forwarding_analysis.txt in each directory"
echo
echo "Investigation commands:"
echo "  • Compare critical states: diff debug/test_1/ss_all.txt debug/test_2/ss_all.txt"
echo "  • Check working state: cat debug/test_1/ss_all.txt | grep \":$UDP_PORT\""
echo "  • Check corrupted state: cat debug/test_2/ss_all.txt | grep \":$UDP_PORT\""
echo "  • Port forwarding analysis: cat debug/*/port_forwarding_analysis.txt"
echo "  • Test current state: echo 'TEST' | nc -u localhost $UDP_PORT"
echo "  • Check logs: cat $LOG_DIR/*.log"
echo "  • Debug directories: ls -la $DEBUG_DIR/"
echo
echo -e "${RED}=== Recovery from Issues ===${NC}"
echo "If UDP forwarding issues detected (no udp *:$UDP_PORT in ss output):"
echo "  • Restart container: docker restart $CONTAINER_NAME (often sufficient)"
echo "  • Or recreate container: docker stop $CONTAINER_NAME && docker rm $CONTAINER_NAME"
echo "  • Or restart Docker Desktop (resolves deeper issues)"
echo "  • Or restart WSL2: wsl --shutdown (from Windows)"
echo
echo "Cleanup:"
echo "  • Remove container: docker rm -f $CONTAINER_NAME"
echo "  • Remove debug data: rm -rf $DEBUG_DIR $LOG_DIR" 