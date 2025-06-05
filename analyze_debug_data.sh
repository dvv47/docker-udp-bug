#!/bin/bash

# Debug Data Analysis Script for UDP Bug Reproduction
# Analyzes collected debug data to identify patterns and root causes

set -e

DEBUG_DIR="$(pwd)/debug"
LOG_DIR="$(pwd)/log"
ANALYSIS_DIR="$(pwd)/analysis"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ ! -d "$DEBUG_DIR" ]; then
    echo -e "${RED}Error: Debug directory not found: $DEBUG_DIR${NC}"
    echo "Run the test script first: ./test_udp_bug.sh"
    exit 1
fi

echo -e "${BLUE}=== Analyzing UDP Bug Debug Data ===${NC}"

mkdir -p "$ANALYSIS_DIR"

# Function to find the most recent debug data for a specific phase
find_debug_data() {
    local pattern="$1"
    find "$DEBUG_DIR" -type d -name "*${pattern}*" | sort | tail -1
}

# Function to compare files between two debug directories
compare_debug_files() {
    local dir1="$1"
    local dir2="$2"
    local output_file="$3"
    local description="$4"
    
    echo -e "\n${YELLOW}=== $description ===${NC}" | tee -a "$output_file"
    
    if [ ! -d "$dir1" ] || [ ! -d "$dir2" ]; then
        echo "One or both directories not found:" | tee -a "$output_file"
        echo "  Dir1: $dir1" | tee -a "$output_file"
        echo "  Dir2: $dir2" | tee -a "$output_file"
        return 1
    fi
    
    # Compare connection tracking
    if [ -f "$dir1/conntrack_udp.txt" ] && [ -f "$dir2/conntrack_udp.txt" ]; then
        echo -e "\n${BLUE}UDP Connection Tracking Differences:${NC}" | tee -a "$output_file"
        diff -u "$dir1/conntrack_udp.txt" "$dir2/conntrack_udp.txt" | tee -a "$output_file" || true
    fi
    
    if [ -f "$dir1/conntrack_tcp.txt" ] && [ -f "$dir2/conntrack_tcp.txt" ]; then
        echo -e "\n${BLUE}TCP Connection Tracking Differences:${NC}" | tee -a "$output_file"
        diff -u "$dir1/conntrack_tcp.txt" "$dir2/conntrack_tcp.txt" | tee -a "$output_file" || true
    fi
    
    # Compare iptables NAT rules
    if [ -f "$dir1/iptables_nat.txt" ] && [ -f "$dir2/iptables_nat.txt" ]; then
        echo -e "\n${BLUE}iptables NAT Rules Differences:${NC}" | tee -a "$output_file"
        diff -u "$dir1/iptables_nat.txt" "$dir2/iptables_nat.txt" | tee -a "$output_file" || true
    fi
    
    # Compare bridge forwarding database
    if [ -f "$dir1/bridge_fdb.txt" ] && [ -f "$dir2/bridge_fdb.txt" ]; then
        echo -e "\n${BLUE}Bridge FDB Differences:${NC}" | tee -a "$output_file"
        diff -u "$dir1/bridge_fdb.txt" "$dir2/bridge_fdb.txt" | tee -a "$output_file" || true
    fi
    
    # Compare network statistics
    if [ -f "$dir1/proc_snmp.txt" ] && [ -f "$dir2/proc_snmp.txt" ]; then
        echo -e "\n${BLUE}SNMP Statistics Differences:${NC}" | tee -a "$output_file"
        # Extract UDP statistics specifically
        echo "UDP stats from first state:" | tee -a "$output_file"
        grep "^Udp:" "$dir1/proc_snmp.txt" | tee -a "$output_file" || true
        echo "UDP stats from second state:" | tee -a "$output_file"
        grep "^Udp:" "$dir2/proc_snmp.txt" | tee -a "$output_file" || true
    fi
    
    # Compare socket states
    if [ -f "$dir1/ss_udp.txt" ] && [ -f "$dir2/ss_udp.txt" ]; then
        echo -e "\n${BLUE}UDP Socket State Differences:${NC}" | tee -a "$output_file"
        diff -u "$dir1/ss_udp.txt" "$dir2/ss_udp.txt" | tee -a "$output_file" || true
    fi
    
    echo "" | tee -a "$output_file"
}

# Focused analysis of corruption indicators
analyze_corruption_indicators() {
    local dir1="$1"
    local dir2="$2"
    local output_file="$3"
    local description="$4"
    
    echo -e "\n${RED}🔍 CORRUPTION INDICATORS: $description${NC}" | tee -a "$output_file"
    
    if [ ! -d "$dir1" ] || [ ! -d "$dir2" ]; then
        echo "❌ Cannot analyze - directories missing" | tee -a "$output_file"
        return 1
    fi
    
    local corruption_found=false
    
    # Check for stale UDP conntrack entries
    if [ -f "$dir1/conntrack_udp.txt" ] && [ -f "$dir2/conntrack_udp.txt" ]; then
        local count1=$(wc -l < "$dir1/conntrack_udp.txt" | tr -d ' ')
        local count2=$(wc -l < "$dir2/conntrack_udp.txt" | tr -d ' ')
        
        echo "UDP conntrack entries: $count1 → $count2" | tee -a "$output_file"
        
        if [ "$count2" -gt "$count1" ]; then
            echo "🚨 NEW UDP conntrack entries appeared (potential stale entries):" | tee -a "$output_file"
            diff -u "$dir1/conntrack_udp.txt" "$dir2/conntrack_udp.txt" | grep "^+" | grep -v "^+++" | head -5 | tee -a "$output_file" || true
            corruption_found=true
        elif [ "$count1" -gt "$count2" ]; then
            echo "✅ UDP conntrack entries cleaned up properly" | tee -a "$output_file"
        fi
        
        # Look for entries related to our test ports
        local port_entries1=$(grep -c "54603\|11002" "$dir1/conntrack_udp.txt" 2>/dev/null || echo "0")
        local port_entries2=$(grep -c "54603\|11002" "$dir2/conntrack_udp.txt" 2>/dev/null || echo "0")
        
        # Ensure we have single numbers (remove any extra whitespace/newlines)
        port_entries1=$(echo "$port_entries1" | head -1 | tr -d ' \n')
        port_entries2=$(echo "$port_entries2" | head -1 | tr -d ' \n')
        
        if [ -n "$port_entries1" ] && [ -n "$port_entries2" ] && [ "$port_entries2" -gt "$port_entries1" ]; then
            echo "🚨 New test port entries in conntrack: $port_entries1 → $port_entries2" | tee -a "$output_file"
            grep "54603\|11002" "$dir2/conntrack_udp.txt" 2>/dev/null | head -3 | tee -a "$output_file" || true
            corruption_found=true
        fi
    fi
    
    # Check for orphaned NAT rules
    if [ -f "$dir1/iptables_nat.txt" ] && [ -f "$dir2/iptables_nat.txt" ]; then
        local nat_rules1=$(wc -l < "$dir1/iptables_nat.txt" | tr -d ' ')
        local nat_rules2=$(wc -l < "$dir2/iptables_nat.txt" | tr -d ' ')
        
        echo "NAT rules count: $nat_rules1 → $nat_rules2" | tee -a "$output_file"
        
        if [ "$nat_rules2" -gt "$nat_rules1" ]; then
            echo "🚨 New NAT rules appeared (potential orphaned rules):" | tee -a "$output_file"
            diff -u "$dir1/iptables_nat.txt" "$dir2/iptables_nat.txt" | grep "^+" | grep -v "^+++" | head -3 | tee -a "$output_file" || true
            corruption_found=true
        fi
    fi
    
    # Check bridge FDB for stale entries
    if [ -f "$dir1/bridge_fdb.txt" ] && [ -f "$dir2/bridge_fdb.txt" ]; then
        local fdb_entries1=$(wc -l < "$dir1/bridge_fdb.txt" | tr -d ' ')
        local fdb_entries2=$(wc -l < "$dir2/bridge_fdb.txt" | tr -d ' ')
        
        echo "Bridge FDB entries: $fdb_entries1 → $fdb_entries2" | tee -a "$output_file"
        
        if [ "$fdb_entries2" -gt "$fdb_entries1" ]; then
            echo "🚨 New bridge FDB entries (potential stale MAC mappings):" | tee -a "$output_file"
            diff -u "$dir1/bridge_fdb.txt" "$dir2/bridge_fdb.txt" | grep "^+" | grep -v "^+++" | head -3 | tee -a "$output_file" || true
            corruption_found=true
        fi
    fi
    
    # Check for dropped packets in statistics
    if [ -f "$dir1/proc_snmp.txt" ] && [ -f "$dir2/proc_snmp.txt" ]; then
        # Extract UDP RcvbufErrors and SndbufErrors
        local udp1=$(grep "^Udp:" "$dir1/proc_snmp.txt" | tail -1)
        local udp2=$(grep "^Udp:" "$dir2/proc_snmp.txt" | tail -1)
        
        if [ "$udp1" != "$udp2" ]; then
            echo "🔍 UDP statistics changed:" | tee -a "$output_file"
            echo "Before: $udp1" | tee -a "$output_file"
            echo "After:  $udp2" | tee -a "$output_file"
            
            # Look for increases in error counts (fields like RcvbufErrors, etc.)
            # This is a simplified check - could be enhanced with field parsing
            echo "📊 Check for error count increases above" | tee -a "$output_file"
        fi
    fi
    
    if [ "$corruption_found" = true ]; then
        echo -e "${RED}🚨 CORRUPTION DETECTED: Evidence of state corruption found${NC}" | tee -a "$output_file"
    else
        echo -e "${GREEN}✅ No obvious corruption indicators detected${NC}" | tee -a "$output_file"
    fi
    
    echo "" | tee -a "$output_file"
}

# Analyze packet captures
analyze_packet_captures() {
    local output_file="$1"
    
    echo -e "\n${YELLOW}=== Packet Capture Analysis ===${NC}" | tee -a "$output_file"
    
    # Find all packet capture files
    local pcap_files=$(find "$DEBUG_DIR" -name "*.pcap" | sort)
    
    if [ -z "$pcap_files" ]; then
        echo "No packet capture files found" | tee -a "$output_file"
        return 0
    fi
    
    for pcap_file in $pcap_files; do
        if [ -f "$pcap_file" ] && [ -s "$pcap_file" ]; then
            echo -e "\n${BLUE}Analyzing: $(basename "$pcap_file")${NC}" | tee -a "$output_file"
            echo "File: $pcap_file" | tee -a "$output_file"
            
            # Basic packet statistics
            if command -v tcpdump >/dev/null 2>&1; then
                echo "Packet count:" | tee -a "$output_file"
                tcpdump -r "$pcap_file" 2>/dev/null | wc -l | tee -a "$output_file"
                
                echo "UDP packets:" | tee -a "$output_file"
                tcpdump -r "$pcap_file" udp 2>/dev/null | wc -l | tee -a "$output_file"
                
                echo "TCP packets:" | tee -a "$output_file"
                tcpdump -r "$pcap_file" tcp 2>/dev/null | wc -l | tee -a "$output_file"
                
                # ENHANCED: Analyze UDP flow patterns (the key bug indicator)
                echo -e "\n${RED}🔍 UDP FLOW ANALYSIS (Key Bug Indicator):${NC}" | tee -a "$output_file"
                
                # Look for host-to-container UDP traffic (192.168.1.47 -> port 54603)
                local host_to_container=$(tcpdump -r "$pcap_file" -n 'udp and dst port 54603 and not src host 127.0.0.1' 2>/dev/null | wc -l)
                echo "Host-to-container UDP packets: $host_to_container" | tee -a "$output_file"
                
                if [ "$host_to_container" -gt 0 ]; then
                    echo -e "${GREEN}✅ Host-to-container UDP forwarding: WORKING${NC}" | tee -a "$output_file"
                    echo "Sample host-to-container packets:" | tee -a "$output_file"
                    tcpdump -r "$pcap_file" -n 'udp and dst port 54603 and not src host 127.0.0.1' 2>/dev/null | head -3 | sed 's/^/  /' | tee -a "$output_file"
                else
                    echo -e "${RED}❌ Host-to-container UDP forwarding: BROKEN${NC}" | tee -a "$output_file"
                    echo "🚨 This indicates Docker bridge UDP forwarding failure!" | tee -a "$output_file"
                fi
                
                # Look for loopback traffic patterns
                local loopback_out=$(tcpdump -r "$pcap_file" -n 'udp and src host 127.0.0.1 and dst port 54603' 2>/dev/null | wc -l)
                local loopback_in=$(tcpdump -r "$pcap_file" -n 'udp and dst host 127.0.0.1 and src port 54603' 2>/dev/null | wc -l)
                
                echo "Loopback Out packets (127.0.0.1 -> 54603): $loopback_out" | tee -a "$output_file"
                echo "Loopback In packets (54603 -> 127.0.0.1): $loopback_in" | tee -a "$output_file"
                
                if [ "$loopback_out" -gt 0 ] && [ "$loopback_in" -gt 0 ]; then
                    echo -e "${GREEN}✅ Loopback UDP flow: BIDIRECTIONAL${NC}" | tee -a "$output_file"
                elif [ "$loopback_out" -gt 0 ] && [ "$loopback_in" -eq 0 ]; then
                    echo -e "${YELLOW}⚠ Loopback UDP flow: UNIDIRECTIONAL (only outgoing)${NC}" | tee -a "$output_file"
                    echo "🔍 This may indicate partial networking corruption" | tee -a "$output_file"
                fi
                
                # Analyze packet sizes for corruption indicators
                echo -e "\n${BLUE}📏 Packet Size Analysis:${NC}" | tee -a "$output_file"
                echo "UDP packet lengths in this capture:" | tee -a "$output_file"
                tcpdump -r "$pcap_file" -n 'udp and dst port 54603' 2>/dev/null | grep -o 'length [0-9]*' | sort | uniq -c | sed 's/^/  /' | tee -a "$output_file" || true
                
                # Show sample packets for pattern analysis
                echo -e "\n${BLUE}Sample packets:${NC}" | tee -a "$output_file"
                tcpdump -r "$pcap_file" -c 10 -n 'udp and port 54603' 2>/dev/null | sed 's/^/  /' | tee -a "$output_file" || true
            fi
        fi
    done
    
    # Summary analysis across all captures
    echo -e "\n${YELLOW}🎯 PACKET FLOW SUMMARY ANALYSIS:${NC}" | tee -a "$output_file"
    
    # Check if we have both PROPER and BUGGY captures for comparison
    local proper_captures=$(find "$DEBUG_DIR" -name "*PROPER*" -name "*.pcap" | head -1)
    local buggy_captures=$(find "$DEBUG_DIR" -name "*BUGGY*" -name "*.pcap" | head -1)
    
    if [ -n "$proper_captures" ] && [ -n "$buggy_captures" ]; then
        echo "Comparing PROPER vs BUGGY packet flows:" | tee -a "$output_file"
        
        if command -v tcpdump >/dev/null 2>&1; then
            local proper_host_packets=$(tcpdump -r "$proper_captures" -n 'udp and dst port 54603 and not src host 127.0.0.1' 2>/dev/null | wc -l)
            local buggy_host_packets=$(tcpdump -r "$buggy_captures" -n 'udp and dst port 54603 and not src host 127.0.0.1' 2>/dev/null | wc -l)
            
            echo "  PROPER test host-to-container packets: $proper_host_packets" | tee -a "$output_file"
            echo "  BUGGY test host-to-container packets: $buggy_host_packets" | tee -a "$output_file"
            
            if [ "$proper_host_packets" -gt 0 ] && [ "$buggy_host_packets" -eq 0 ]; then
                echo -e "\n${RED}🎯 BUG CONFIRMED BY PACKET ANALYSIS!${NC}" | tee -a "$output_file"
                echo "  📍 Host-to-container UDP packets present in PROPER test" | tee -a "$output_file"
                echo "  📍 Host-to-container UDP packets MISSING in BUGGY test" | tee -a "$output_file"
                echo "  🚨 This proves Docker bridge UDP forwarding corruption!" | tee -a "$output_file"
            fi
        fi
    fi
}

# Analyze connection tracking state evolution
analyze_conntrack_evolution() {
    local output_file="$1"
    
    echo -e "\n${YELLOW}=== Connection Tracking Evolution Analysis ===${NC}" | tee -a "$output_file"
    
    # Find all conntrack files in chronological order
    local conntrack_dirs=$(find "$DEBUG_DIR" -type d | sort)
    
    for dir in $conntrack_dirs; do
        if [ -f "$dir/conntrack_udp.txt" ]; then
            echo -e "\n${BLUE}State: $(basename "$dir")${NC}" | tee -a "$output_file"
            echo "UDP conntrack entries:" | tee -a "$output_file"
            if [ -s "$dir/conntrack_udp.txt" ]; then
                wc -l < "$dir/conntrack_udp.txt" | tee -a "$output_file"
                # Show entries related to our test ports
                grep -E "(54603|11002)" "$dir/conntrack_udp.txt" 2>/dev/null | head -5 | tee -a "$output_file" || true
            else
                echo "0 (empty file)" | tee -a "$output_file"
            fi
        fi
    done
}

# Analyze Docker bridge forwarding database corruption
analyze_bridge_fdb_corruption() {
    local output_file="$1"
    
    echo -e "\n${RED}=== Docker Bridge FDB Corruption Analysis ===${NC}" | tee -a "$output_file"
    echo "Analyzing bridge forwarding database changes that cause UDP packet loss..." | tee -a "$output_file"
    
    # Find bridge FDB files from different phases
    local pre_fdb=$(find "$DEBUG_DIR" -name "bridge_fdb.txt" -path "*pre*" | head -1)
    local post_fdb=$(find "$DEBUG_DIR" -name "bridge_fdb.txt" -path "*post*" | head -1)
    local proper_fdb=$(find "$DEBUG_DIR" -name "bridge_fdb.txt" -path "*PROPER*" | head -1)
    local buggy_fdb=$(find "$DEBUG_DIR" -name "bridge_fdb.txt" -path "*BUGGY*" | head -1)
    
    if [ -f "$pre_fdb" ] && [ -f "$post_fdb" ]; then
        echo -e "\n${BLUE}Bridge FDB Changes (Pre vs Post):${NC}" | tee -a "$output_file"
        echo "Comparing: $pre_fdb vs $post_fdb" | tee -a "$output_file"
        
        if ! diff -q "$pre_fdb" "$post_fdb" >/dev/null 2>&1; then
            echo "🔍 Bridge FDB CHANGED!" | tee -a "$output_file"
            echo "Differences:" | tee -a "$output_file"
            diff "$pre_fdb" "$post_fdb" | head -20 | sed 's/^/  /' | tee -a "$output_file" || true
        else
            echo "✅ Bridge FDB unchanged" | tee -a "$output_file"
        fi
    fi
    
    if [ -f "$proper_fdb" ] && [ -f "$buggy_fdb" ]; then
        echo -e "\n${BLUE}Bridge FDB Corruption (PROPER vs BUGGY):${NC}" | tee -a "$output_file"
        echo "Comparing: $proper_fdb vs $buggy_fdb" | tee -a "$output_file"
        
        if ! diff -q "$proper_fdb" "$buggy_fdb" >/dev/null 2>&1; then
            echo "🚨 Bridge FDB CORRUPTED between PROPER and BUGGY tests!" | tee -a "$output_file"
            echo "Critical differences:" | tee -a "$output_file"
            diff "$proper_fdb" "$buggy_fdb" | head -20 | sed 's/^/  /' | tee -a "$output_file" || true
            
            # Look for specific corruption patterns
            echo -e "\n${RED}Looking for UDP forwarding corruption patterns:${NC}" | tee -a "$output_file"
            
            # Check for missing entries in buggy state
            if command -v comm >/dev/null 2>&1; then
                local missing_entries=$(comm -23 "$proper_fdb" "$buggy_fdb" | wc -l | tr -d ' ')
                local extra_entries=$(comm -13 "$proper_fdb" "$buggy_fdb" | wc -l | tr -d ' ')
                
                echo "Entries missing in BUGGY state: $missing_entries" | tee -a "$output_file"
                echo "Extra entries in BUGGY state: $extra_entries" | tee -a "$output_file"
                
                if [ "$missing_entries" -gt 0 ]; then
                    echo "Missing FDB entries (may cause packet drops):" | tee -a "$output_file"
                    comm -23 "$proper_fdb" "$buggy_fdb" | head -5 | sed 's/^/  /' | tee -a "$output_file"
                fi
            fi
        else
            echo "⚠ Bridge FDB appears identical (corruption may be elsewhere)" | tee -a "$output_file"
        fi
    fi
    
    # Analyze Docker network configuration corruption
    echo -e "\n${BLUE}Docker Network Configuration Analysis:${NC}" | tee -a "$output_file"
    
    local proper_docker=$(find "$DEBUG_DIR" -name "docker_bridge_inspect.json" -path "*PROPER*" | head -1)
    local buggy_docker=$(find "$DEBUG_DIR" -name "docker_bridge_inspect.json" -path "*BUGGY*" | head -1)
    
    if [ -f "$proper_docker" ] && [ -f "$buggy_docker" ]; then
        if ! diff -q "$proper_docker" "$buggy_docker" >/dev/null 2>&1; then
            echo "🔍 Docker bridge configuration CHANGED!" | tee -a "$output_file"
            echo "Configuration differences:" | tee -a "$output_file"
            diff "$proper_docker" "$buggy_docker" | head -15 | sed 's/^/  /' | tee -a "$output_file" || true
        else
            echo "✅ Docker bridge configuration unchanged" | tee -a "$output_file"
        fi
    fi
    
    # Check for bridge interface state changes
    echo -e "\n${BLUE}Bridge Interface State Analysis:${NC}" | tee -a "$output_file"
    
    local proper_links=$(find "$DEBUG_DIR" -name "bridge_links.txt" -path "*PROPER*" | head -1)
    local buggy_links=$(find "$DEBUG_DIR" -name "bridge_links.txt" -path "*BUGGY*" | head -1)
    
    if [ -f "$proper_links" ] && [ -f "$buggy_links" ]; then
        if ! diff -q "$proper_links" "$buggy_links" >/dev/null 2>&1; then
            echo "🔍 Bridge link state CHANGED!" | tee -a "$output_file"
            echo "Link state differences:" | tee -a "$output_file"
            diff "$proper_links" "$buggy_links" | head -10 | sed 's/^/  /' | tee -a "$output_file" || true
        else
            echo "✅ Bridge link state unchanged" | tee -a "$output_file"
        fi
    fi
}

# Identify critical differences between PROPER and BUGGY tests
identify_critical_differences() {
    local output_file="$1"
    
    echo -e "\n${YELLOW}=== Critical Differences Analysis ===${NC}" | tee -a "$output_file"
    
    # Find directories for comparison
    local proper1_pre=$(find_debug_data "pre_test_PROPER_1")
    local proper1_post=$(find_debug_data "post_test_PROPER_1")
    local proper2_pre=$(find_debug_data "pre_test_PROPER_2")
    local proper2_post=$(find_debug_data "post_test_PROPER_2")
    
    local buggy1_pre=$(find_debug_data "pre_test_BUGGY_1")
    local buggy1_post=$(find_debug_data "post_test_BUGGY_1")
    local buggy2_pre=$(find_debug_data "pre_test_BUGGY_2")
    local buggy2_post=$(find_debug_data "post_test_BUGGY_2")
    
    echo "Found debug directories:" | tee -a "$output_file"
    echo "  PROPER_1 pre:  $proper1_pre" | tee -a "$output_file"
    echo "  PROPER_1 post: $proper1_post" | tee -a "$output_file"
    echo "  PROPER_2 pre:  $proper2_pre" | tee -a "$output_file"
    echo "  PROPER_2 post: $proper2_post" | tee -a "$output_file"
    echo "  BUGGY_1 pre:   $buggy1_pre" | tee -a "$output_file"
    echo "  BUGGY_1 post:  $buggy1_post" | tee -a "$output_file"
    echo "  BUGGY_2 pre:   $buggy2_pre" | tee -a "$output_file"
    echo "  BUGGY_2 post:  $buggy2_post" | tee -a "$output_file"
    
    # 1. Compare PROPER tests (should be consistent)
    echo -e "\n${BLUE}🔍 Baseline Comparison: PROPER tests should be consistent${NC}" | tee -a "$output_file"
    
    if [ -d "$proper1_pre" ] && [ -d "$proper2_pre" ]; then
        compare_debug_files "$proper1_pre" "$proper2_pre" "$output_file" "PROPER_1 vs PROPER_2 (Pre-test - should be similar)"
    fi
    
    if [ -d "$proper1_post" ] && [ -d "$proper2_post" ]; then
        compare_debug_files "$proper1_post" "$proper2_post" "$output_file" "PROPER_1 vs PROPER_2 (Post-test - should be similar)"
    fi
    
    # 2. KEY ANALYSIS: Pre vs Post BUGGY_1 (where corruption happens)
    echo -e "\n${RED}🎯 CRITICAL: BUGGY_1 Pre vs Post (Where corruption is triggered)${NC}" | tee -a "$output_file"
    echo "This comparison shows what changes during BUGGY_1 that corrupts the system" | tee -a "$output_file"
    
    if [ -d "$buggy1_pre" ] && [ -d "$buggy1_post" ]; then
        compare_debug_files "$buggy1_pre" "$buggy1_post" "$output_file" "🚨 BUGGY_1: Pre vs Post (Corruption trigger point)"
        analyze_corruption_indicators "$buggy1_pre" "$buggy1_post" "$output_file" "BUGGY_1 execution (corruption trigger)"
    else
        echo "❌ Missing BUGGY_1 pre/post data for analysis" | tee -a "$output_file"
    fi
    
    # 3. KEY ANALYSIS: Pre vs Post BUGGY_2 (corruption visible)
    echo -e "\n${RED}🔍 BUGGY_2 Pre vs Post (Corruption effects visible)${NC}" | tee -a "$output_file"
    echo "This comparison shows how the corrupted state affects the second test" | tee -a "$output_file"
    
    if [ -d "$buggy2_pre" ] && [ -d "$buggy2_post" ]; then
        compare_debug_files "$buggy2_pre" "$buggy2_post" "$output_file" "🔍 BUGGY_2: Pre vs Post (Corrupted state effects)"
        analyze_corruption_indicators "$buggy2_pre" "$buggy2_post" "$output_file" "BUGGY_2 execution (corruption effects)"
    else
        echo "❌ Missing BUGGY_2 pre/post data for analysis" | tee -a "$output_file"
    fi
    
    # 4. Compare BUGGY_1 pre vs BUGGY_2 pre (inherited corruption)
    echo -e "\n${YELLOW}🔗 State Inheritance: BUGGY_1 post vs BUGGY_2 pre${NC}" | tee -a "$output_file"
    echo "This shows what corrupted state BUGGY_2 inherits from BUGGY_1" | tee -a "$output_file"
    
    if [ -d "$buggy1_post" ] && [ -d "$buggy2_pre" ]; then
        compare_debug_files "$buggy1_post" "$buggy2_pre" "$output_file" "🔗 BUGGY_1 (post) vs BUGGY_2 (pre) - State inheritance"
    fi
    
    # 5. Compare working vs corrupted initial states
    echo -e "\n${BLUE}🆚 Working vs Corrupted: PROPER vs BUGGY_2 initial states${NC}" | tee -a "$output_file"
    echo "This shows the difference between clean and corrupted system states" | tee -a "$output_file"
    
    if [ -d "$proper1_pre" ] && [ -d "$buggy2_pre" ]; then
        compare_debug_files "$proper1_pre" "$buggy2_pre" "$output_file" "🆚 PROPER_1 (clean) vs BUGGY_2 (corrupted) - Initial states"
    fi
    
    # 6. Timeline analysis
    echo -e "\n${CYAN}📊 Timeline Analysis${NC}" | tee -a "$output_file"
    echo "Corruption timeline:" | tee -a "$output_file"
    echo "  1. PROPER_1: Clean state → Works normally → Clean state" | tee -a "$output_file"
    echo "  2. PROPER_2: Clean state → Works normally → Clean state" | tee -a "$output_file"
    echo "  3. BUGGY_1:  Clean state → 🚨 CORRUPTION TRIGGERED → Corrupted state" | tee -a "$output_file"
    echo "  4. BUGGY_2:  Corrupted state → Fails due to corruption → Still corrupted" | tee -a "$output_file"
}

# Generate summary report
generate_summary() {
    local output_file="$1"
    
    echo -e "\n${YELLOW}=== Summary and Recommendations ===${NC}" | tee -a "$output_file"
    
    # Check if bug was reproduced
    local buggy1_messages=0
    local buggy2_messages=0
    local buggy1_exists=false
    local buggy2_exists=false
    
    if [ -f "$LOG_DIR/BUGGY_1.log" ]; then
        buggy1_messages=$(grep -c "MESSAGE=" "$LOG_DIR/BUGGY_1.log" 2>/dev/null || echo "0")
        buggy1_exists=true
    fi
    
    if [ -f "$LOG_DIR/BUGGY_2.log" ]; then
        buggy2_messages=$(grep -c "MESSAGE=" "$LOG_DIR/BUGGY_2.log" 2>/dev/null || echo "0")
        buggy2_exists=true
    fi
    
    echo "Test Results Summary:" | tee -a "$output_file"
    echo "  BUGGY_1 log exists: $buggy1_exists, messages: $buggy1_messages" | tee -a "$output_file"
    echo "  BUGGY_2 log exists: $buggy2_exists, messages: $buggy2_messages" | tee -a "$output_file"
    
    # Detect bug reproduction patterns
    if [ "$buggy1_exists" = true ] && [ "$buggy1_messages" -gt "0" ] && [ "$buggy2_exists" = false ]; then
        echo -e "\n${RED}🎯 BUG REPRODUCED SUCCESSFULLY! (CLASSIC PATTERN)${NC}" | tee -a "$output_file"
        echo "  ✅ BUGGY_1 succeeded with $buggy1_messages messages (corruption triggered during this test)" | tee -a "$output_file"
        echo "  ❌ BUGGY_2 COMPLETE FAILURE - no log file created (zero messages received)" | tee -a "$output_file"
        echo "  🚨 This is the classic UDP bug pattern: first run works, second run completely fails" | tee -a "$output_file"
        echo "  📍 Corruption trigger point: Between BUGGY_1 pre and post states" | tee -a "$output_file"
        echo "  📍 Corruption visible: Complete UDP forwarding failure in BUGGY_2" | tee -a "$output_file"
    elif [ "$buggy1_exists" = true ] && [ "$buggy2_exists" = true ] && [ "$buggy1_messages" -gt "0" ] && [ "$buggy2_messages" -eq "0" ]; then
        echo -e "\n${RED}🎯 BUG REPRODUCED SUCCESSFULLY! (PARTIAL PATTERN)${NC}" | tee -a "$output_file"
        echo "  ✅ BUGGY_1 succeeded with $buggy1_messages messages (corruption happens during this test)" | tee -a "$output_file"
        echo "  ❌ BUGGY_2 failed with 0 messages (due to corrupted state from BUGGY_1)" | tee -a "$output_file"
        echo "  📍 Corruption trigger point: Between BUGGY_1 pre and post states" | tee -a "$output_file"
        echo "  📍 Corruption visible: During entire BUGGY_2 execution" | tee -a "$output_file"
    elif [ "$buggy1_messages" -eq "0" ] && [ "$buggy2_messages" -eq "0" ]; then
        echo -e "\n${YELLOW}⚠ Both BUGGY runs failed${NC}" | tee -a "$output_file"
        echo "  This might indicate:" | tee -a "$output_file"
        echo "  - Severe corruption from earlier run" | tee -a "$output_file"
        echo "  - Different issue preventing first test from working" | tee -a "$output_file"
        echo "  - System already in corrupted state" | tee -a "$output_file"
        echo "  - TCP server not running (check if start_tcp_server was commented out)" | tee -a "$output_file"
    else
        echo -e "\n${GREEN}✅ Bug not reproduced in this run${NC}" | tee -a "$output_file"
        echo "  Both BUGGY runs succeeded - bug conditions not met" | tee -a "$output_file"
        echo "  This could indicate:" | tee -a "$output_file"
        echo "  - Docker version not susceptible to this bug" | tee -a "$output_file"
        echo "  - Kernel has protective measures" | tee -a "$output_file"
        echo "  - Timing/race condition not triggered" | tee -a "$output_file"
    fi
    
    echo -e "\n${CYAN}🔬 Key Investigation Points:${NC}" | tee -a "$output_file"
    echo "1. 🚨 CRITICAL: Compare BUGGY_1 pre vs post states" | tee -a "$output_file"
    echo "   - This shows exactly what gets corrupted during socket cleanup" | tee -a "$output_file"
    echo "   - Look for stale conntrack entries, changed iptables rules, bridge FDB changes" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "2. 🔍 State inheritance: Compare BUGGY_1 post vs BUGGY_2 pre" | tee -a "$output_file"
    echo "   - This shows what corrupted state BUGGY_2 inherits" | tee -a "$output_file"
    echo "   - Should be nearly identical if corruption persists" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "3. 💥 Failure analysis: Compare BUGGY_2 pre vs post" | tee -a "$output_file"
    echo "   - Shows how corrupted state prevents normal operation" | tee -a "$output_file"
    echo "   - Look for dropped packets, failed connections" | tee -a "$output_file"
    
    echo -e "\n${BLUE}📋 Manual Investigation Commands:${NC}" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "🚨 CORRUPTION TRIGGER ANALYSIS:" | tee -a "$output_file"
    echo "  # What changed during BUGGY_1 that caused corruption?" | tee -a "$output_file"
    echo "  diff -u debug/pre_test_BUGGY_1_*/conntrack_udp.txt debug/post_test_BUGGY_1_*/conntrack_udp.txt" | tee -a "$output_file"
    echo "  diff -u debug/pre_test_BUGGY_1_*/iptables_nat.txt debug/post_test_BUGGY_1_*/iptables_nat.txt" | tee -a "$output_file"
    echo "  diff -u debug/pre_test_BUGGY_1_*/bridge_fdb.txt debug/post_test_BUGGY_1_*/bridge_fdb.txt" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "🔗 STATE INHERITANCE ANALYSIS:" | tee -a "$output_file"
    echo "  # What corrupted state does BUGGY_2 inherit?" | tee -a "$output_file"
    echo "  diff -u debug/post_test_BUGGY_1_*/conntrack_udp.txt debug/pre_test_BUGGY_2_*/conntrack_udp.txt" | tee -a "$output_file"
    echo "" | tee -a "$output_file"
    echo "🆚 CLEAN vs CORRUPTED COMPARISON:" | tee -a "$output_file"
    echo "  # Difference between working and corrupted states" | tee -a "$output_file"
    echo "  diff -u debug/pre_test_PROPER_1_*/conntrack_udp.txt debug/pre_test_BUGGY_2_*/conntrack_udp.txt" | tee -a "$output_file"
    
    echo -e "\n2. 📦 Packet Analysis:" | tee -a "$output_file"
    find "$DEBUG_DIR" -name "*.pcap" | head -3 | sed 's/^/   wireshark /' | tee -a "$output_file"
    echo "   # Compare packet flows between successful and failed tests" | tee -a "$output_file"
    
    echo -e "\n3. 🔍 Real-time Monitoring Setup:" | tee -a "$output_file"
    echo "   # Monitor during next test run to catch corruption in real-time" | tee -a "$output_file"
    echo "   watch -n 1 'conntrack -L -p udp | grep 54603'" | tee -a "$output_file"
    echo "   sudo tcpdump -i any -n 'udp port 54603' &" | tee -a "$output_file"
    
    echo -e "\n4. 🛠️ Recovery/Workaround:" | tee -a "$output_file"
    echo "   # Clear corrupted connection tracking state" | tee -a "$output_file"
    echo "   sudo conntrack -D -p udp --dport 54603" | tee -a "$output_file"
    echo "   sudo conntrack -D -p udp" | tee -a "$output_file"
    echo "   docker network prune" | tee -a "$output_file"
    
    echo -e "\n${GREEN}🎯 Root Cause Investigation Focus:${NC}" | tee -a "$output_file"
    echo "The bug appears to be triggered when:" | tee -a "$output_file"
    echo "  1. Container creates both UDP and TCP sockets" | tee -a "$output_file"
    echo "  2. Container exits with UDP socket destroyed BEFORE TCP socket" | tee -a "$output_file"
    echo "  3. This corrupts Docker's bridge networking state" | tee -a "$output_file"
    echo "  4. Subsequent containers inherit the corrupted state" | tee -a "$output_file"
    echo "  5. UDP forwarding fails due to stale connection tracking entries" | tee -a "$output_file"
}

# Main analysis
ANALYSIS_FILE="$ANALYSIS_DIR/bug_analysis_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLUE}Generating analysis report: $ANALYSIS_FILE${NC}"

# Start analysis
echo "Docker UDP Bug Debug Data Analysis" > "$ANALYSIS_FILE"
echo "Generated: $(date)" >> "$ANALYSIS_FILE"
echo "Debug directory: $DEBUG_DIR" >> "$ANALYSIS_FILE"
echo "========================================" >> "$ANALYSIS_FILE"

# Run all analysis functions
identify_critical_differences "$ANALYSIS_FILE"
analyze_conntrack_evolution "$ANALYSIS_FILE"
analyze_packet_captures "$ANALYSIS_FILE"
analyze_bridge_fdb_corruption "$ANALYSIS_FILE"
generate_summary "$ANALYSIS_FILE"

echo -e "${GREEN}Analysis complete!${NC}"
echo -e "Report saved to: ${YELLOW}$ANALYSIS_FILE${NC}"
echo ""
echo "To view the full report:"
echo "  cat $ANALYSIS_FILE"
echo ""
echo "To view specific sections:"
echo "  grep -A 20 'Critical Differences' $ANALYSIS_FILE"
echo "  grep -A 10 'Summary and Recommendations' $ANALYSIS_FILE" 