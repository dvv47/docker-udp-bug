# Docker UDP Bug Reproduction Framework

## 🚨 CRITICAL DISCOVERY: Docker UDP Port Forwarding Corruption

This repository contains a reproduction framework for a critical Docker bug that corrupts UDP port forwarding when containers destroy UDP sockets before TCP sockets. The bug has been confirmed to affect **Docker Desktop in WSL2** environments.

## 🎯 Bug Summary

**Root Cause**: When a container application destroys UDP sockets before TCP sockets during cleanup, it corrupts Docker's internal UDP port forwarding mechanism for that specific container.

**Impact**: Complete UDP forwarding failure for the affected container that persists until container restart.

**Environment**: Confirmed in Docker Desktop running in WSL2 (Windows Subsystem for Linux 2)

**Test Method**: Python TCP/UDP server runs on host and sends continuous UDP traffic to container while maintaining TCP connection from container. This simulates real-world applications that use both protocols simultaneously.

## 🔍 Primary Evidence: UDP Socket Binding Disappearance

### Working State (PROPER tests)
```bash
$ ss -tulpn | grep ":54603"
udp   UNCONN 0      0                   *:54603            *:*
```

### Corrupted State (BUGGY tests)
```bash
$ ss -tulpn | grep ":54603"
# NO OUTPUT - UDP binding completely MISSING
```

### Timeline of Corruption
- **PRE-test BUGGY_1**: Docker UDP binding ✅ Present
- **DURING-test BUGGY_1**: Docker UDP binding ✅ Present  
- **POST-test BUGGY_1**: Docker UDP binding ❌ **MISSING!**
- **All BUGGY_2 phases**: Docker UDP binding ❌ Missing (persistent until restart)

**Critical Observation**: The exact moment of corruption occurs between `during_test_BUGGY_1` and `post_test_BUGGY_1`.

## 🧪 Running Tests

### Quick Start
```bash
# Prerequisites: Docker + Python 3
# The test automatically checks for dependencies

# Run main test (requires Docker and Python 3)
./test_udp_bug.sh

# Analyze results automatically  
./analyze_debug_data.sh
```

### Test Pattern
1. **PROPER_1 & PROPER_2**: TCP destroyed before UDP (✅ Works correctly)
2. **BUGGY_1**: UDP destroyed before TCP (⚠️ Corruption triggered but may still work)
3. **BUGGY_2**: Runs with inherited corruption (❌ Complete failure expected)

### Test Flow Architecture
```
Host                          Container
┌─────────────────────┐      ┌─────────────────────┐
│ Python TCP/UDP      │      │ minimal_udp_bug_    │
│ Server              │      │ repro.c             │
│                     │      │                     │
│ ┌─────────────────┐ │      │ ┌─────────────────┐ │
│ │ TCP Server      │◄├──────┤►│ TCP Client      │ │
│ │ Port 11002      │ │      │ │                 │ │
│ └─────────────────┘ │      │ └─────────────────┘ │
│                     │      │                     │
│ ┌─────────────────┐ │      │ ┌─────────────────┐ │
│ │ UDP Client      │─├──────┤►│ UDP Server      │ │
│ │ → Port 54603    │ │      │ │ Port 54603      │ │
│ └─────────────────┘ │      │ └─────────────────┘ │
└─────────────────────┘      └─────────────────────┘

Flow: Container connects TCP → Host sends UDP → Test corruption on cleanup
```

### Expected Results for Bug Confirmation
- **PROPER tests**: All UDP messages received successfully
- **BUGGY_1**: May work (corruption happens during execution)
- **BUGGY_2**: Complete failure - zero UDP messages received

## 📊 Debug Data Collection

The framework automatically collects comprehensive debug data:

### Basic Debugging (Default)
- **Socket states**: `ss -tulpn` output for all phases
- **Connection tracking**: UDP/TCP conntrack entries
- **Docker configuration**: Network inspect, container states
- **Process monitoring**: Container and host process states
- **Packet captures**: tcpdump for network traffic analysis

### Debug Data Structure
```
debug/
├── initial_*/                      # Initial system state
├── pre_test_PROPER_1_*/            # Before PROPER test 1
├── during_test_PROPER_1_*/         # During PROPER test 1
├── post_test_PROPER_1_*/           # After PROPER test 1
├── pre_test_BUGGY_1_*/             # Before BUGGY test 1
├── during_test_BUGGY_1_*/          # During BUGGY test 1
├── post_test_BUGGY_1_*/            # After BUGGY test 1
```

### Key Debug Files
- `debug/*/ss_all.txt` - **Socket state (PRIMARY EVIDENCE)**
- `debug/*/port_forwarding_analysis.txt` - **Automated UDP binding analysis**
- `debug/*/conntrack_udp.txt` - Connection tracking state
- `debug/*/container_inspect.json` - Container configuration
- `debug/*/tcpdump_*.pcap` - Network packet captures

## 🛠️ Recovery Methods

Once UDP forwarding is corrupted, recovery options:

```bash
# 1. Restart container (sufficient for recovery)
docker restart udp_bug_test
```

## 🚨 Bug Report Information

### Affected Versions
- **Docker Desktop**: Confirmed in WSL2 environment
- **Likely affects**: Any Docker version using userland proxy for UDP forwarding

### Reproduction Requirements
- Container with both UDP and TCP sockets
- Application that destroys UDP socket before TCP socket  
- Host-to-container UDP communication via port binding
- TCP connection from container to host (triggers the bug)
- **Python TCP/UDP server** (`tcp_udp_server.py`) running on host that:
  - Accepts TCP connections from container applications
  - Sends continuous UDP traffic to container while TCP connection is active
  - Only one active TCP client at a time (new connections replace previous ones)
  - Stops UDP traffic when TCP client disconnects

### Bug Classification
- **Severity**: High - Complete UDP forwarding failure for affected container
- **Scope**: Per-container port binding corruption
- **Persistence**: Requires container restart to fix
- **Impact**: Affects the specific container until restart

## 🔬 Technical Analysis

### Why This Bug Matters
1. **Breaks abstraction**: Application socket order shouldn't affect container port forwarding
2. **Silent failure**: No error messages, just missing functionality  
3. **Persistent corruption**: Survives application restarts within container
4. **Per-container impact**: Affects container's port binding state specifically

### Evidence Sources

#### Primary Evidence
1. **Socket state files**: `debug/*/ss_all.txt` - Most reliable corruption indicator
2. **Port forwarding analysis**: `debug/*/port_forwarding_analysis.txt` - Automated analysis

#### Secondary Evidence
1. **Packet captures**: `debug/*/tcpdump_*.pcap` - Shows missing external traffic
2. **Connection tracking**: `debug/*/conntrack_udp.txt` - Shows stale UDP entries
3. **Container state**: `debug/*/container_inspect.json` - Proves container keeps running

### Advanced Investigation (Root Required)
```bash
# Search for dropped packets in kernel traces
grep -i drop debug/advanced/ftrace_*.txt

# Look for netfilter hook calls
grep "nf_hook" debug/advanced/ftrace_*.txt

# Check eBPF socket monitoring
grep "Socket" debug/advanced/ebpf_*.log
```

## 🎯 Significance

This bug represents a **significant flaw in Docker's UDP port forwarding logic** where:
1. Application socket cleanup order affects container's port forwarding state
2. Docker's internal port forwarding for the container becomes corrupted
3. The corruption persists across application restarts within the container
4. Container restart is required to restore UDP forwarding

This should be reported to Docker maintainers as a networking regression affecting Docker Desktop and potentially other Docker installations using userland proxy mechanisms.

## 📁 Repository Structure

```
udp_bug_repro/
├── README.md                          # This comprehensive guide
├── test_udp_bug.sh                    # Main test framework  
├── tcp_udp_server.py                  # Python TCP/UDP server for host
├── analyze_debug_data.sh              # Debug data analysis
├── minimal_udp_bug_repro.c            # Test application source (container)
├── Makefile                           # Build configuration
├── log/                               # Test execution logs
└── debug/                             # Comprehensive debug data
    ├── pre_test_*/                    # Pre-test states
    ├── during_test_*/                 # During-test states
    ├── post_test_*/                   # Post-test states
    └── advanced/                      # Advanced kernel debugging (if root)
```

## 🐍 Python TCP/UDP Server

The framework includes a specialized Python server (`tcp_udp_server.py`) that runs on the host:

### Purpose
- **Simulates real-world dual-protocol applications** that use both TCP and UDP
- **Triggers the Docker UDP bug** by maintaining TCP connections while sending UDP traffic
- **Provides controlled test environment** for reproducing the corruption

### Behavior  
- **Listens for TCP connections** from Docker container applications
- **Sends continuous UDP messages** to container while TCP client is connected
- **One active client policy**: New TCP connections stop previous UDP streams  
- **Automatic cleanup**: Stops UDP traffic when TCP client disconnects
- **Comprehensive logging**: All TCP/UDP activities logged for debugging

### Usage
```bash
# Automatic usage via test script
./test_udp_bug.sh

# Manual usage for testing
python3 tcp_udp_server.py --udp-host <container_ip> --tcp-port 11002 --udp-port 54603
```

### Key Features
- **Thread-safe**: Properly manages concurrent TCP connections
- **Signal handling**: Graceful shutdown on SIGTERM/SIGINT
- **Error resilience**: Continues operation despite UDP/TCP errors
- **Resource management**: Automatic cleanup of finished threads

## 🤝 Contributing

To reproduce or investigate this bug:
1. Clone this repository
2. Run `./test_udp_bug.sh` 
3. Examine the generated debug data
4. Look for disappearing `udp *:54603` socket in `debug/*/ss_all.txt`
5. Analyze results with `./analyze_debug_data.sh`

**Key Investigation Focus**: The exact moment when Docker's UDP socket binding disappears between `during_test_BUGGY_1` and `post_test_BUGGY_1` states.
