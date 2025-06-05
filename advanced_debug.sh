#!/bin/bash

# Advanced Kernel Debugging for Docker UDP Bug
# Uses ftrace, eBPF, and other advanced tools to trace kernel behavior

set -e

DEBUG_DIR="$(pwd)/debug"
ADVANCED_DEBUG_DIR="$DEBUG_DIR/advanced"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root (required for most kernel debugging)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}This script requires root privileges for kernel debugging${NC}"
    echo "Please run with sudo: sudo $0"
    exit 1
fi

mkdir -p "$ADVANCED_DEBUG_DIR"

echo -e "${BLUE}=== Advanced Kernel Debugging for UDP Bug ===${NC}"

# Setup ftrace for network debugging
setup_ftrace() {
    echo -e "${YELLOW}Setting up ftrace for network debugging...${NC}"
    
    local ftrace_dir="/sys/kernel/debug/tracing"
    
    # Check if ftrace is available
    if [ ! -d "$ftrace_dir" ]; then
        echo -e "${YELLOW}⚠ ftrace not available (debugfs not mounted or no permission)${NC}"
        echo "  Try: sudo mount -t debugfs debugfs /sys/kernel/debug"
        return 1
    fi
    
    # Check if tracing is writable
    if [ ! -w "$ftrace_dir/tracing_on" ]; then
        echo -e "${YELLOW}⚠ ftrace not writable (insufficient permissions)${NC}"
        return 1
    fi
    
    # Reset ftrace state
    echo 0 > "$ftrace_dir/tracing_on" 2>/dev/null || true
    echo > "$ftrace_dir/trace" 2>/dev/null || true
    
    # Set tracer to function tracer
    if [ -w "$ftrace_dir/current_tracer" ]; then
        echo "function" > "$ftrace_dir/current_tracer" 2>/dev/null || {
            echo -e "${YELLOW}⚠ Could not set function tracer, using default${NC}"
        }
    fi
    
    # Set buffer size (optional)
    if [ -w "$ftrace_dir/buffer_size_kb" ]; then
        echo 8192 > "$ftrace_dir/buffer_size_kb" 2>/dev/null || {
            echo -e "${YELLOW}⚠ Could not set buffer size${NC}"
        }
    fi
    
    # Set up function filters (with error handling)
    if [ -w "$ftrace_dir/set_ftrace_filter" ]; then
        echo -e "${BLUE}Setting up ftrace filters...${NC}"
        
        # Clear existing filters first
        echo > "$ftrace_dir/set_ftrace_filter" 2>/dev/null || true
        
        # Try to add filters one by one, ignoring failures
        local filters=(
            "nf_hook*"
            "netfilter*" 
            "udp_*"
            "tcp_*"
            "__nf_*"
            "br_handle*"
            "*conntrack*"
        )
        
        local successful_filters=0
        for filter in "${filters[@]}"; do
            if echo "$filter" >> "$ftrace_dir/set_ftrace_filter" 2>/dev/null; then
                ((successful_filters++))
                echo "    ✓ Added filter: $filter"
            else
                echo "    ⚠ Could not add filter: $filter (may not exist on this kernel)"
            fi
        done
        
        echo "    ✓ Successfully added $successful_filters filters"
    else
        echo -e "${YELLOW}⚠ Cannot set ftrace filters (not writable)${NC}"
    fi
    
    # Enable tracing
    if echo 1 > "$ftrace_dir/tracing_on" 2>/dev/null; then
        echo "  ✓ ftrace network debugging enabled"
        return 0
    else
        echo -e "${YELLOW}⚠ Could not enable ftrace${NC}"
        return 1
    fi
}

# Collect ftrace data
collect_ftrace_data() {
    local phase="$1"
    local ftrace_dir="/sys/kernel/debug/tracing"
    
    if [ -f "$ftrace_dir/trace" ]; then
        echo -e "${BLUE}Collecting ftrace data for phase: $phase${NC}"
        
        # Stop tracing briefly to collect data
        echo 0 > "$ftrace_dir/tracing_on"
        
        # Copy trace data
        cp "$ftrace_dir/trace" "$ADVANCED_DEBUG_DIR/ftrace_${phase}.txt"
        
        # Clear the buffer and restart
        echo > "$ftrace_dir/trace"
        echo 1 > "$ftrace_dir/tracing_on"
        
        echo "  ✓ ftrace data saved to: ftrace_${phase}.txt"
        return 0
    else
        echo -e "${YELLOW}⚠ ftrace data collection failed${NC}"
        return 1
    fi
}

# Setup eBPF monitoring (if available)
setup_ebpf_monitoring() {
    echo -e "${YELLOW}Setting up eBPF monitoring...${NC}"
    
    # Check if bpftrace is available
    if ! command -v bpftrace >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ bpftrace not available, skipping eBPF monitoring${NC}"
        echo "  Install with: apt-get install bpftrace"
        return 1
    fi
    
    # Test if eBPF is functional
    if ! bpftrace -e 'BEGIN { printf("eBPF test\\n"); exit(); }' >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ eBPF not functional (may need kernel headers or different permissions)${NC}"
        return 1
    fi
    
    # Create simplified eBPF scripts for monitoring
    cat > "$ADVANCED_DEBUG_DIR/monitor_udp_simple.bt" << 'EOF'
#!/usr/bin/env bpftrace

// Simple UDP socket monitoring
tracepoint:syscalls:sys_enter_socket
{
    if (args->family == 2 && args->type == 2) { // AF_INET && SOCK_DGRAM
        printf("%s: UDP socket creation: pid=%d comm=%s\\n", strftime("%H:%M:%S", nsecs), pid, comm);
    }
}

tracepoint:syscalls:sys_enter_bind
{
    printf("%s: Socket bind: pid=%d comm=%s fd=%d\\n", strftime("%H:%M:%S", nsecs), pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_close
{
    printf("%s: Socket close: pid=%d comm=%s fd=%d\\n", strftime("%H:%M:%S", nsecs), pid, comm, args->fd);
}

END
{
    printf("eBPF monitoring stopped\\n");
}
EOF

    cat > "$ADVANCED_DEBUG_DIR/monitor_network_simple.bt" << 'EOF'
#!/usr/bin/env bpftrace

// Simple network monitoring
tracepoint:syscalls:sys_enter_sendto
{
    printf("%s: sendto: pid=%d comm=%s fd=%d\\n", strftime("%H:%M:%S", nsecs), pid, comm, args->fd);
}

tracepoint:syscalls:sys_enter_recvfrom
{
    printf("%s: recvfrom: pid=%d comm=%s fd=%d\\n", strftime("%H:%M:%S", nsecs), pid, comm, args->fd);
}

// Monitor dropped packets (if available)
tracepoint:skb:kfree_skb
{
    printf("%s: packet dropped at: %s\\n", strftime("%H:%M:%S", nsecs), kstack);
}

END
{
    printf("Network monitoring stopped\\n");
}
EOF

    echo "  ✓ eBPF monitoring scripts created"
    return 0
}

# Start eBPF monitoring
start_ebpf_monitoring() {
    local phase="$1"
    
    if command -v bpftrace >/dev/null 2>&1; then
        echo -e "${BLUE}Starting eBPF monitoring for phase: $phase${NC}"
        
        # Start UDP socket monitoring
        if [ -f "$ADVANCED_DEBUG_DIR/monitor_udp_simple.bt" ]; then
            bpftrace "$ADVANCED_DEBUG_DIR/monitor_udp_simple.bt" > "$ADVANCED_DEBUG_DIR/ebpf_udp_${phase}.log" 2>&1 &
            local udp_pid=$!
            echo "$udp_pid" > "$ADVANCED_DEBUG_DIR/ebpf_udp_${phase}.pid"
        fi
        
        # Start network monitoring
        if [ -f "$ADVANCED_DEBUG_DIR/monitor_network_simple.bt" ]; then
            bpftrace "$ADVANCED_DEBUG_DIR/monitor_network_simple.bt" > "$ADVANCED_DEBUG_DIR/ebpf_network_${phase}.log" 2>&1 &
            local network_pid=$!
            echo "$network_pid" > "$ADVANCED_DEBUG_DIR/ebpf_network_${phase}.pid"
        fi
        
        sleep 1  # Let eBPF scripts start
        echo "  ✓ eBPF monitoring started"
        return 0
    else
        echo -e "${YELLOW}⚠ eBPF monitoring failed${NC}"
        return 1
    fi
}

# Stop eBPF monitoring
stop_ebpf_monitoring() {
    local phase="$1"
    
    echo -e "${BLUE}Stopping eBPF monitoring for phase: $phase${NC}"
    
    # Stop UDP monitoring
    if [ -f "$ADVANCED_DEBUG_DIR/ebpf_udp_${phase}.pid" ]; then
        local udp_pid=$(cat "$ADVANCED_DEBUG_DIR/ebpf_udp_${phase}.pid")
        if [ -n "$udp_pid" ] && kill -0 "$udp_pid" 2>/dev/null; then
            kill "$udp_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ADVANCED_DEBUG_DIR/ebpf_udp_${phase}.pid"
    fi
    
    # Stop network monitoring
    if [ -f "$ADVANCED_DEBUG_DIR/ebpf_network_${phase}.pid" ]; then
        local network_pid=$(cat "$ADVANCED_DEBUG_DIR/ebpf_network_${phase}.pid")
        if [ -n "$network_pid" ] && kill -0 "$network_pid" 2>/dev/null; then
            kill "$network_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ADVANCED_DEBUG_DIR/ebpf_network_${phase}.pid"
    fi
    
    echo "  ✓ eBPF monitoring stopped"
}

# Monitor kernel ring buffer for network-related messages
monitor_kernel_messages() {
    local phase="$1"
    
    echo -e "${BLUE}Monitoring kernel messages for phase: $phase${NC}"
    
    # Start dmesg monitoring in background
    dmesg -w | grep -i -E "(netfilter|conntrack|bridge|iptables|udp|drop)" > "$ADVANCED_DEBUG_DIR/kernel_messages_${phase}.log" &
    local dmesg_pid=$!
    echo "$dmesg_pid" > "$ADVANCED_DEBUG_DIR/dmesg_${phase}.pid"
    
    echo "  ✓ Kernel message monitoring started"
}

# Stop kernel message monitoring
stop_kernel_message_monitoring() {
    local phase="$1"
    
    echo -e "${BLUE}Stopping kernel message monitoring for phase: $phase${NC}"
    
    if [ -f "$ADVANCED_DEBUG_DIR/dmesg_${phase}.pid" ]; then
        local dmesg_pid=$(cat "$ADVANCED_DEBUG_DIR/dmesg_${phase}.pid")
        if [ -n "$dmesg_pid" ] && kill -0 "$dmesg_pid" 2>/dev/null; then
            kill "$dmesg_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ADVANCED_DEBUG_DIR/dmesg_${phase}.pid"
    fi
    
    echo "  ✓ Kernel message monitoring stopped"
}

# Monitor syscalls with strace
monitor_syscalls() {
    local phase="$1"
    local container_name="$2"
    
    if ! command -v strace >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ strace not available${NC}"
        return 1
    fi
    
    echo -e "${BLUE}Starting syscall monitoring for phase: $phase${NC}"
    
    # Get container PID
    local container_pid=$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null)
    if [ -z "$container_pid" ] || [ "$container_pid" = "0" ]; then
        echo -e "${YELLOW}⚠ Could not get container PID${NC}"
        return 1
    fi
    
    # Start strace in background
    strace -p "$container_pid" -f -e trace=network,close -o "$ADVANCED_DEBUG_DIR/strace_${phase}.log" >/dev/null 2>&1 &
    local strace_pid=$!
    echo "$strace_pid" > "$ADVANCED_DEBUG_DIR/strace_${phase}.pid"
    
    sleep 1  # Let strace start
    echo "  ✓ syscall monitoring started"
    return 0
}

# Stop syscall monitoring
stop_syscall_monitoring() {
    local phase="$1"
    
    echo -e "${BLUE}Stopping syscall monitoring for phase: $phase${NC}"
    
    if [ -f "$ADVANCED_DEBUG_DIR/strace_${phase}.pid" ]; then
        local strace_pid=$(cat "$ADVANCED_DEBUG_DIR/strace_${phase}.pid")
        if [ -n "$strace_pid" ] && kill -0 "$strace_pid" 2>/dev/null; then
            kill "$strace_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ADVANCED_DEBUG_DIR/strace_${phase}.pid"
    fi
    
    echo "  ✓ syscall monitoring stopped"
}

# Capture network namespace information
capture_netns_info() {
    local phase="$1"
    local container_name="$2"
    
    echo -e "${BLUE}Capturing network namespace info for phase: $phase${NC}"
    
    # Host network namespace info
    ip netns list > "$ADVANCED_DEBUG_DIR/netns_list_${phase}.txt" 2>/dev/null || true
    
    # Container network namespace info
    if [ -n "$container_name" ] && docker ps -q -f name="$container_name" >/dev/null 2>&1; then
        docker exec "$container_name" ip addr show > "$ADVANCED_DEBUG_DIR/container_netns_${phase}.txt" 2>/dev/null || true
        docker exec "$container_name" ip route show > "$ADVANCED_DEBUG_DIR/container_routes_${phase}.txt" 2>/dev/null || true
    fi
    
    echo "  ✓ Network namespace info captured"
    return 0
}

# Monitor connection state transitions
monitor_conntrack_transitions() {
    local phase="$1"
    
    echo -e "${BLUE}Monitoring conntrack state transitions for phase: $phase${NC}"
    
    if command -v conntrack >/dev/null 2>&1; then
        # Monitor conntrack events
        conntrack -E > "$ADVANCED_DEBUG_DIR/conntrack_events_${phase}.log" 2>&1 &
        local conntrack_pid=$!
        echo "$conntrack_pid" > "$ADVANCED_DEBUG_DIR/conntrack_events_${phase}.pid"
        
        echo "  ✓ Conntrack event monitoring started"
    fi
}

# Stop conntrack monitoring
stop_conntrack_monitoring() {
    local phase="$1"
    
    if [ -f "$ADVANCED_DEBUG_DIR/conntrack_events_${phase}.pid" ]; then
        local conntrack_pid=$(cat "$ADVANCED_DEBUG_DIR/conntrack_events_${phase}.pid")
        if [ -n "$conntrack_pid" ] && kill -0 "$conntrack_pid" 2>/dev/null; then
            kill "$conntrack_pid" 2>/dev/null || true
            sleep 1
        fi
        rm -f "$ADVANCED_DEBUG_DIR/conntrack_events_${phase}.pid"
        echo -e "${BLUE}Conntrack monitoring stopped for phase: $phase${NC}"
    fi
}

# Cleanup function
cleanup_advanced_debug() {
    echo -e "\n${YELLOW}Cleaning up advanced debugging...${NC}"
    
    # Stop all monitoring processes
    for phase in pre during post; do
        stop_ebpf_monitoring "$phase" 2>/dev/null || true
        stop_kernel_message_monitoring "$phase" 2>/dev/null || true
        stop_syscall_monitoring "$phase" 2>/dev/null || true
        stop_conntrack_monitoring "$phase" 2>/dev/null || true
    done
    
    # Disable ftrace
    local ftrace_dir="/sys/kernel/debug/tracing"
    if [ -d "$ftrace_dir" ]; then
        echo 0 > "$ftrace_dir/tracing_on" 2>/dev/null || true
        echo > "$ftrace_dir/set_ftrace_filter" 2>/dev/null || true
        echo nop > "$ftrace_dir/current_tracer" 2>/dev/null || true
    fi
    
    echo "  ✓ Advanced debugging cleanup completed"
}

# Set up cleanup trap
trap cleanup_advanced_debug EXIT INT TERM

# Start advanced monitoring
start_advanced_monitoring() {
    local phase="$1"
    local container_name="$2"
    
    echo -e "${BLUE}Starting advanced monitoring for phase: $phase${NC}"
    
    local monitoring_started=false
    
    # Start ftrace monitoring
    if collect_ftrace_data "$phase"; then
        echo "  ✓ ftrace monitoring active"
        monitoring_started=true
    else
        echo "  ⚠ ftrace monitoring failed"
    fi
    
    # Start eBPF monitoring
    if start_ebpf_monitoring "$phase"; then
        echo "  ✓ eBPF monitoring active"
        monitoring_started=true
    else
        echo "  ⚠ eBPF monitoring failed"
    fi
    
    # Start kernel message monitoring
    if monitor_kernel_messages "$phase"; then
        echo "  ✓ kernel message monitoring active"
        monitoring_started=true
    else
        echo "  ⚠ kernel message monitoring failed"
    fi
    
    # Start strace monitoring
    if monitor_syscalls "$phase" "$container_name"; then
        echo "  ✓ strace monitoring active"
        monitoring_started=true
    else
        echo "  ⚠ strace monitoring failed"
    fi
    
    # Monitor network namespace changes
    if capture_netns_info "$phase" "$container_name"; then
        echo "  ✓ network namespace monitoring active"
        monitoring_started=true
    else
        echo "  ⚠ network namespace monitoring failed"
    fi
    
    if [ "$monitoring_started" = true ]; then
        echo -e "${GREEN}  ✓ Advanced monitoring started (some components may have failed)${NC}"
        return 0
    else
        echo -e "${YELLOW}  ⚠ No advanced monitoring components started successfully${NC}"
        return 1
    fi
}

# Stop advanced monitoring
stop_advanced_monitoring() {
    local phase="$1"
    local container_name="$2"
    
    echo -e "${BLUE}Stopping advanced monitoring for phase: $phase${NC}"
    
    # Collect final ftrace data
    collect_ftrace_data "final_${phase}" >/dev/null 2>&1 || true
    
    # Stop eBPF monitoring
    stop_ebpf_monitoring "$phase" >/dev/null 2>&1 || true
    
    # Stop kernel message monitoring
    stop_kernel_message_monitoring "$phase" >/dev/null 2>&1 || true
    
    # Stop strace monitoring
    stop_syscall_monitoring "$phase" >/dev/null 2>&1 || true
    
    # Stop network namespace monitoring
    capture_netns_info "$phase" "$container_name" >/dev/null 2>&1 || true
    
    echo "  ✓ Advanced monitoring stopped"
}

# Command line interface
case "${1:-help}" in
    "setup")
        setup_ftrace
        setup_ebpf_monitoring
        echo -e "${GREEN}Advanced debugging tools configured${NC}"
        ;;
    "start")
        start_advanced_monitoring "${2:-default}" "${3:-}"
        ;;
    "stop")
        stop_advanced_monitoring "${2:-default}" "${3:-}"
        ;;
    "cleanup")
        cleanup_advanced_debug
        ;;
    "help"|*)
        echo "Usage: $0 {setup|start|stop|cleanup}"
        echo ""
        echo "Commands:"
        echo "  setup           - Configure ftrace and eBPF tools"
        echo "  start <phase> [container] - Start monitoring for specified phase"
        echo "  stop <phase> [container] - Stop monitoring for specified phase"
        echo "  cleanup         - Clean up all monitoring and restore system state"
        echo ""
        echo "This script must be run as root for kernel debugging capabilities."
        echo "Integration with test_udp_bug.sh is automatic when this script is present."
        ;;
esac 