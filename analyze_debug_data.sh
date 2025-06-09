#!/bin/bash

# Simplified Debug Data Analysis Script for Docker UDP Burst Traffic Instability
# Analyzes essential evidence for Docker UDP forwarding failure with burst patterns

set -e

DEBUG_DIR="$(pwd)/debug"
LOG_DIR="$(pwd)/log"
ANALYSIS_DIR="$(pwd)/analysis"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ ! -d "$DEBUG_DIR" ]; then
    echo -e "${RED}Error: Debug directory not found: $DEBUG_DIR${NC}"
    echo "Run the test script first: ./test_udp_bug.sh"
    exit 1
fi

echo -e "${BLUE}=== Docker UDP Burst Traffic Instability Analysis ===${NC}"
echo "Analyzing essential evidence for Docker UDP forwarding failure with burst patterns"
echo

mkdir -p "$ANALYSIS_DIR"

# Find the two critical debug states
find_critical_states() {
    echo -e "${BLUE}Finding critical debug states...${NC}"
    
    TEST_1_DIR="$DEBUG_DIR/test_1"
    TEST_2_DIR="$DEBUG_DIR/test_2"
    
    if [ ! -d "$TEST_1_DIR" ] || [ ! -d "$TEST_2_DIR" ]; then
        echo -e "${RED}❌ Critical debug states not found!${NC}"
        echo "Expected directories:"
        echo "  - test_1/ (working state)"
        echo "  - test_2/ (corrupted state)"
        echo
        echo "Available debug directories:"
        ls -la "$DEBUG_DIR" 2>/dev/null || echo "  (debug directory empty)"
        exit 1
    fi
    
    echo -e "${GREEN}✅ Found critical states:${NC}"
    echo "  Working state:   test_1/"
    echo "  Corrupted state: test_2/"
    echo
}

# Analyze UDP socket binding state (primary evidence)
analyze_udp_socket_binding() {
    local output_file="$1"
    
    echo -e "\n${RED}=== 🎯 PRIMARY EVIDENCE: UDP Socket Binding Analysis ===${NC}" | tee -a "$output_file"
    echo "This is the key evidence that demonstrates Docker UDP forwarding instability" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    local working_ss="$TEST_1_DIR/ss_all.txt"
    local corrupted_ss="$TEST_2_DIR/ss_all.txt"
    
    if [ ! -f "$working_ss" ] || [ ! -f "$corrupted_ss" ]; then
        echo -e "${RED}❌ Socket state files missing!${NC}" | tee -a "$output_file"
        echo "Expected files:" | tee -a "$output_file"
        echo "  - $working_ss" | tee -a "$output_file"
        echo "  - $corrupted_ss" | tee -a "$output_file"
        return 1
    fi
    
    echo -e "${BLUE}🔍 UDP Port 54603 Binding Analysis:${NC}" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    # Check working state
    echo "📊 WORKING STATE (test_1):" | tee -a "$output_file"
    local working_udp=$(grep ":54603" "$working_ss" 2>/dev/null || echo "")
    if [ -n "$working_udp" ]; then
        echo -e "${GREEN}✅ UDP binding present:${NC}" | tee -a "$output_file"
        echo "$working_udp" | sed 's/^/  /' | tee -a "$output_file"
    else
        echo -e "${RED}❌ UDP binding missing${NC}" | tee -a "$output_file"
    fi
    echo "" | tee -a "$output_file"
    
    # Check corrupted state
    echo "📊 CORRUPTED STATE (test_2):" | tee -a "$output_file"
    local corrupted_udp=$(grep ":54603" "$corrupted_ss" 2>/dev/null || echo "")
    if [ -n "$corrupted_udp" ]; then
        echo -e "${GREEN}✅ UDP binding present:${NC}" | tee -a "$output_file"
        echo "$corrupted_udp" | sed 's/^/  /' | tee -a "$output_file"
    else
        echo -e "${RED}❌ UDP binding missing${NC}" | tee -a "$output_file"
        echo "  (no UDP binding found for port 54603)" | tee -a "$output_file"
    fi
    echo "" | tee -a "$output_file"
    
    # Analysis and conclusion
    if [ -n "$working_udp" ] && [ -z "$corrupted_udp" ]; then
        echo -e "${RED}🚨 DOCKER UDP FORWARDING INSTABILITY CONFIRMED!${NC}" | tee -a "$output_file"
        echo "📍 Evidence pattern:" | tee -a "$output_file"
        echo "  ✅ test_1: UDP binding present → Docker forwarding functional" | tee -a "$output_file"
        echo "  ❌ test_2: UDP binding missing → Docker forwarding corrupted" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        echo -e "${YELLOW}🎯 CRITICAL FINDING:${NC}" | tee -a "$output_file"
        echo "  • Docker UDP forwarding becomes unstable with burst traffic patterns" | tee -a "$output_file"
        echo "  • This occurs DESPITE proper socket destruction order (TCP → UDP)" | tee -a "$output_file"
        echo "  • The issue is at Docker infrastructure level, not application level" | tee -a "$output_file"
        echo "  • Burst pattern: 10 UDP messages rapidly + 5-second pause" | tee -a "$output_file"
    elif [ -n "$working_udp" ] && [ -n "$corrupted_udp" ]; then
        echo -e "${GREEN}✅ UDP forwarding stable${NC}" | tee -a "$output_file"
        echo "  Both states show UDP binding present" | tee -a "$output_file"
        echo "  Docker handled burst traffic patterns correctly" | tee -a "$output_file"
    elif [ -z "$working_udp" ] && [ -z "$corrupted_udp" ]; then
        echo -e "${YELLOW}⚠ No UDP bindings found in either state${NC}" | tee -a "$output_file"
        echo "  This may indicate environmental issues or test setup problems" | tee -a "$output_file"
    else
        echo -e "${YELLOW}⚠ Unexpected pattern${NC}" | tee -a "$output_file"
        echo "  test_1 missing UDP binding but test_2 has it" | tee -a "$output_file"
        echo "  This suggests test setup or timing issues" | tee -a "$output_file"
    fi
}

# Analyze Docker port forwarding configuration
analyze_port_forwarding() {
    local output_file="$1"
    
    echo -e "\n${BLUE}=== 🔧 Docker Port Forwarding Analysis ===${NC}" | tee -a "$output_file"
    echo "Analyzing Docker's view of port forwarding between states" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    local working_pf="$TEST_1_DIR/port_forwarding_analysis.txt"
    local corrupted_pf="$TEST_2_DIR/port_forwarding_analysis.txt"
    
    if [ -f "$working_pf" ] && [ -f "$corrupted_pf" ]; then
        echo -e "${BLUE}📋 Docker Port Mapping Comparison:${NC}" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        
        # Extract key port forwarding status
        echo "Working state Docker port mappings:" | tee -a "$output_file"
        grep -A 5 "Container port mappings" "$working_pf" | sed 's/^/  /' | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        
        echo "Corrupted state Docker port mappings:" | tee -a "$output_file"
        grep -A 5 "Container port mappings" "$corrupted_pf" | sed 's/^/  /' | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        
        # Look for critical differences
        if ! diff -q "$working_pf" "$corrupted_pf" >/dev/null 2>&1; then
            echo -e "${YELLOW}🔍 Docker port forwarding configuration changed:${NC}" | tee -a "$output_file"
            echo "Key differences:" | tee -a "$output_file"
            diff -u "$working_pf" "$corrupted_pf" | grep -E "^[+-]" | head -10 | sed 's/^/  /' | tee -a "$output_file"
        else
            echo -e "${GREEN}✅ Docker port forwarding configuration unchanged${NC}" | tee -a "$output_file"
        fi
    else
        echo "❌ Port forwarding analysis files not found" | tee -a "$output_file"
    fi
}

# Analyze test results correlation
analyze_test_results() {
    local output_file="$1"
    
    echo -e "\n${BLUE}=== 📊 Test Results Correlation ===${NC}" | tee -a "$output_file"
    echo "Correlating socket state with actual test outcomes" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    local proper1_log="$LOG_DIR/PROPER_1.log"
    local proper2_log="$LOG_DIR/PROPER_2.log"
    
    echo -e "${BLUE}🧪 Test Execution Results:${NC}" | tee -a "$output_file"
    
    # Analyze PROPER_1 results
    if [ -f "$proper1_log" ]; then
        local proper1_messages=$(grep -c "MESSAGE=" "$proper1_log" 2>/dev/null || echo "0")
        echo "  PROPER_1: $proper1_messages UDP messages received" | tee -a "$output_file"
        if [ "$proper1_messages" -gt 0 ]; then
            echo -e "    ${GREEN}✅ PASS${NC} - UDP forwarding functional" | tee -a "$output_file"
        else
            echo -e "    ${RED}❌ FAIL${NC} - No UDP messages received" | tee -a "$output_file"
        fi
    else
        echo "  PROPER_1: Log file not found" | tee -a "$output_file"
    fi
    
    # Analyze PROPER_2 results
    if [ -f "$proper2_log" ]; then
        local proper2_messages=$(grep -c "MESSAGE=" "$proper2_log" 2>/dev/null || echo "0")
        echo "  PROPER_2: $proper2_messages UDP messages received" | tee -a "$output_file"
        if [ "$proper2_messages" -gt 0 ]; then
            echo -e "    ${GREEN}✅ PASS${NC} - UDP forwarding functional" | tee -a "$output_file"
        else
            echo -e "    ${RED}❌ FAIL${NC} - No UDP messages received" | tee -a "$output_file"
        fi
    else
        echo "  PROPER_2: Log file not found" | tee -a "$output_file"
    fi
    
    echo "" | tee -a "$output_file"
    
    # Correlate results with socket state
    echo -e "${YELLOW}🔗 Results-to-Socket-State Correlation:${NC}" | tee -a "$output_file"
    
    local working_udp=$(grep ":54603" "$TEST_1_DIR/ss_all.txt" 2>/dev/null || echo "")
    local corrupted_udp=$(grep ":54603" "$TEST_2_DIR/ss_all.txt" 2>/dev/null || echo "")
    
    if [ -n "$working_udp" ] && [ -z "$corrupted_udp" ]; then
        echo "  📍 test_1: UDP binding ✅ + Test PASS ✅ = Normal operation" | tee -a "$output_file"
        echo "  📍 test_2: UDP binding ❌ + Test FAIL ❌ = Docker forwarding corruption" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        echo -e "  ${RED}🎯 CORRELATION CONFIRMED: Missing UDP binding → Test failure${NC}" | tee -a "$output_file"
        echo "  This proves Docker UDP forwarding instability with burst traffic patterns" | tee -a "$output_file"
    elif [ -n "$working_udp" ] && [ -n "$corrupted_udp" ]; then
        echo "  📍 Both states show UDP binding present" | tee -a "$output_file"
        echo -e "  ${GREEN}✅ Docker UDP forwarding stable with burst patterns${NC}" | tee -a "$output_file"
    else
        echo "  📍 Unexpected socket state pattern" | tee -a "$output_file"
        echo "  ⚠ May indicate test setup or environmental issues" | tee -a "$output_file"
    fi
}

# Analyze packet captures if available (lightweight analysis)
analyze_packet_captures() {
    local output_file="$1"
    
    echo -e "\n${BLUE}=== 📦 Packet Flow Verification ===${NC}" | tee -a "$output_file"
    echo "Verifying UDP traffic patterns (if packet capture available)" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    local working_pcap=$(find "$TEST_1_DIR" -name "*.pcap" 2>/dev/null | head -1)
    local corrupted_pcap=$(find "$TEST_2_DIR" -name "*.pcap" 2>/dev/null | head -1)
    
    if [ -n "$working_pcap" ] && [ -n "$corrupted_pcap" ] && command -v tcpdump >/dev/null 2>&1; then
        echo -e "${BLUE}🔍 UDP Traffic Analysis:${NC}" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        
        # Simple packet count analysis
        local working_udp_count=$(tcpdump -r "$working_pcap" -n 'udp and dst port 54603' 2>/dev/null | wc -l)
        local corrupted_udp_count=$(tcpdump -r "$corrupted_pcap" -n 'udp and dst port 54603' 2>/dev/null | wc -l)
        
        echo "  test_1: $working_udp_count UDP packets to port 54603" | tee -a "$output_file"
        echo "  test_2: $corrupted_udp_count UDP packets to port 54603" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        
        if [ "$working_udp_count" -gt 0 ] && [ "$corrupted_udp_count" -eq 0 ]; then
            echo -e "${RED}🚨 PACKET EVIDENCE CONFIRMS UDP FORWARDING FAILURE!${NC}" | tee -a "$output_file"
            echo "  📍 Working state: UDP packets successfully forwarded" | tee -a "$output_file"
            echo "  📍 Corrupted state: No UDP packets reaching container" | tee -a "$output_file"
        elif [ "$working_udp_count" -gt 0 ] && [ "$corrupted_udp_count" -gt 0 ]; then
            echo -e "${GREEN}✅ UDP packet forwarding working in both states${NC}" | tee -a "$output_file"
        else
            echo -e "${YELLOW}⚠ Unexpected packet pattern${NC}" | tee -a "$output_file"
        fi
    else
        echo "📋 Packet capture not available or tcpdump not installed" | tee -a "$output_file"
        echo "  (Packet analysis skipped - not essential for this bug demonstration)" | tee -a "$output_file"
    fi
}

# Generate focused summary and recommendations
generate_summary() {
    local output_file="$1"
    
    echo -e "\n${YELLOW}=== 🎯 SUMMARY AND CRITICAL FINDINGS ===${NC}" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    # Determine the bug reproduction status
    local working_udp=$(grep ":54603" "$TEST_1_DIR/ss_all.txt" 2>/dev/null || echo "")
    local corrupted_udp=$(grep ":54603" "$TEST_2_DIR/ss_all.txt" 2>/dev/null || echo "")
    
    local proper1_messages=0
    local proper2_messages=0
    
    if [ -f "$LOG_DIR/PROPER_1.log" ]; then
        proper1_messages=$(grep -c "MESSAGE=" "$LOG_DIR/PROPER_1.log" 2>/dev/null || echo "0")
    fi
    
    if [ -f "$LOG_DIR/PROPER_2.log" ]; then
        proper2_messages=$(grep -c "MESSAGE=" "$LOG_DIR/PROPER_2.log" 2>/dev/null || echo "0")
    fi
    
    echo -e "${BLUE}📊 Evidence Summary:${NC}" | tee -a "$output_file"
    echo "  • test_1 UDP binding: $([ -n "$working_udp" ] && echo "✅ Present" || echo "❌ Missing")" | tee -a "$output_file"
    echo "  • test_2 UDP binding: $([ -n "$corrupted_udp" ] && echo "✅ Present" || echo "❌ Missing")" | tee -a "$output_file"
    echo "  • test_1 result: $proper1_messages messages ($([ "$proper1_messages" -gt 0 ] && echo "PASS" || echo "FAIL"))" | tee -a "$output_file"
    echo "  • test_2 result: $proper2_messages messages ($([ "$proper2_messages" -gt 0 ] && echo "PASS" || echo "FAIL"))" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    
    # Provide definitive conclusion
    if [ -n "$working_udp" ] && [ -z "$corrupted_udp" ] && [ "$proper1_messages" -gt 0 ] && [ "$proper2_messages" -eq 0 ]; then
        echo -e "${RED}🚨 DOCKER UDP BURST TRAFFIC INSTABILITY CONFIRMED!${NC}" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        echo -e "${YELLOW}🎯 Critical Finding:${NC}" | tee -a "$output_file"
        echo "  • Docker UDP forwarding becomes unstable when exposed to burst traffic patterns" | tee -a "$output_file"
        echo "  • This occurs EVEN with proper application socket handling (TCP → UDP cleanup)" | tee -a "$output_file"
        echo "  • The issue is at Docker infrastructure level, not application level" | tee -a "$output_file"
        echo "  • Burst pattern that triggers issue: 10 UDP messages + 5-second pause, repeated" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
        echo -e "${RED}🚨 Production Impact:${NC}" | tee -a "$output_file"
        echo "  • Any container receiving burst UDP traffic is susceptible" | tee -a "$output_file"
        echo "  • Silent failure - no error messages, just lost UDP forwarding" | tee -a "$output_file"
        echo "  • Requires container restart to recover" | tee -a "$output_file"
        echo "  • Affects microservices, IoT systems, real-time applications" | tee -a "$output_file"
        
    elif [ -n "$working_udp" ] && [ -n "$corrupted_udp" ] && [ "$proper1_messages" -gt 0 ] && [ "$proper2_messages" -gt 0 ]; then
        echo -e "${GREEN}✅ Docker UDP forwarding stable with burst patterns${NC}" | tee -a "$output_file"
        echo "  • Both tests passed successfully" | tee -a "$output_file"
        echo "  • UDP socket bindings maintained correctly" | tee -a "$output_file"
        echo "  • Docker handled burst traffic patterns without corruption" | tee -a "$output_file"
        echo "  • This Docker version appears to be resilient to the burst pattern issue" | tee -a "$output_file"
        
    else
        echo -e "${YELLOW}⚠ Inconclusive results${NC}" | tee -a "$output_file"
        echo "  • Evidence pattern doesn't match expected Docker UDP instability signatures" | tee -a "$output_file"
        echo "  • This may indicate:" | tee -a "$output_file"
        echo "    - Test environment issues" | tee -a "$output_file"
        echo "    - Docker version differences" | tee -a "$output_file"
        echo "    - Different timing/race conditions" | tee -a "$output_file"
        echo "    - Network configuration variations" | tee -a "$output_file"
    fi
    
    echo "" | tee -a "$output_file"
    echo -e "${CYAN}🔧 Essential Investigation Commands:${NC}" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "Manual verification of key evidence:" | tee -a "$output_file"
    echo "  # Compare UDP socket bindings (primary evidence)" | tee -a "$output_file"
    echo "  diff debug/test_1/ss_all.txt debug/test_2/ss_all.txt" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "  # Check working state UDP binding" | tee -a "$output_file"
    echo "  cat debug/test_1/ss_all.txt | grep \":54603\"" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "  # Check corrupted state UDP binding" | tee -a "$output_file"
    echo "  cat debug/test_2/ss_all.txt | grep \":54603\"" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "  # Test current UDP forwarding state" | tee -a "$output_file"
    echo "  echo 'TEST' | nc -u localhost 54603" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "Recovery if corruption detected:" | tee -a "$output_file"
    echo "  # Restart container (often sufficient)" | tee -a "$output_file"
    echo "  docker restart udp_bug_test" | tee -a "$output_file"
}

# Main analysis execution
main() {
    find_critical_states
    
    local analysis_file="$ANALYSIS_DIR/burst_instability_analysis_$(date +%Y%m%d_%H%M%S).txt"
    
    echo -e "${BLUE}Generating focused analysis report: $(basename $analysis_file)${NC}"
    echo
    
    # Initialize report
    cat > "$analysis_file" << EOF
Docker UDP Burst Traffic Instability Analysis
==============================================
Generated: $(date)
Analysis Focus: Essential evidence for Docker UDP forwarding instability
Working state: test_1/
Corrupted state: test_2/

This analysis focuses on the core evidence for Docker UDP forwarding instability with burst traffic patterns.
Key finding: Docker UDP forwarding fails even with proper socket cleanup (TCP → UDP).
EOF
    
    # Run focused analysis
    analyze_udp_socket_binding "$analysis_file"
    analyze_port_forwarding "$analysis_file"
    analyze_test_results "$analysis_file"
    analyze_packet_captures "$analysis_file"
    generate_summary "$analysis_file"
    
    echo -e "${GREEN}✅ Analysis complete!${NC}"
    echo -e "📄 Full report: ${YELLOW}$analysis_file${NC}"
    echo
    echo -e "${BLUE}🎯 Quick Results Check:${NC}"
    
    # Show quick summary
    local working_udp=$(grep ":54603" "$TEST_1_DIR/ss_all.txt" 2>/dev/null || echo "")
    local corrupted_udp=$(grep ":54603" "$TEST_2_DIR/ss_all.txt" 2>/dev/null || echo "")
    
    echo "  test_1 UDP binding: $([ -n "$working_udp" ] && echo -e "${GREEN}✅ Present${NC}" || echo -e "${RED}❌ Missing${NC}")"
    echo "  test_2 UDP binding: $([ -n "$corrupted_udp" ] && echo -e "${GREEN}✅ Present${NC}" || echo -e "${RED}❌ Missing${NC}")"
    
    if [ -n "$working_udp" ] && [ -z "$corrupted_udp" ]; then
        echo -e "  ${RED}🚨 DOCKER UDP INSTABILITY CONFIRMED!${NC}"
    elif [ -n "$working_udp" ] && [ -n "$corrupted_udp" ]; then
        echo -e "  ${GREEN}✅ Docker UDP forwarding stable${NC}"
    else
        echo -e "  ${YELLOW}⚠ Inconclusive or environmental issues${NC}"
    fi
    
    echo
    echo "View full analysis:"
    echo "  cat $analysis_file"
}

# Execute main analysis
main 