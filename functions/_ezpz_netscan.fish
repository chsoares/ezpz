function _ezpz_netscan
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # Usage message
    set usage "
Usage: ezpz netscan [-F] <target>
  <target> can be a CIDR range (e.g., 10.10.10.0/24), a single IP, or a file with targets.

  -F    Fast scan. Performs host discovery and a fast port scan only. Skips full TCP and UDP scans.
"

    # ASCII art banner
    echo ''
    echo '              |  '(set_color magenta --bold)'   __|   __|    \     \ | '(set_color normal)
    echo '    \    -_)   _|'(set_color magenta --bold)' \__ \  (      _ \   .  | '(set_color normal)
    echo ' _| _| \___| \__|'(set_color magenta --bold)' ____/ \___| _/  _\ _|\_|  '(set_color normal)
    echo ''

    # Variables
    set fast_scan 0
    set target ""

    # Argument parsing
    argparse 'F/fast' 'h/help' -- $argv
    or return 1

    if set -q _flag_help
        echo $usage
        return 1
    end

    if set -q _flag_fast
        set fast_scan 1
    end

    # Check for exactly one positional argument
    if test (count $argv) -ne 1
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    set target $argv[1]

    # Prerequisites check
    for tool in fping nmap
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Temporary file and trap management
    set targets_tmp (mktemp)
    # Trap for cleanup
    trap "rm -f '$targets_tmp'" EXIT TERM INT

    # Validation patterns (fixed to avoid escaped slash)
    set cidr_pattern '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([1-9]|[1-2][0-9]|3[0-2])$'
    set ip_pattern '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'

    # Host Discovery
    if test -f "$target"
        # Target file
        if not test -r "$target"
            ezpz_error "Cannot read target file: $target"
            return 1
        end
        cp "$target" "$targets_tmp"
    else if echo "$target" | grep -qE "$cidr_pattern"
        # Host discovery with CIDR
        ezpz_header "Running fping on the $target network"
        ezpz_cmd "fping -agq \"$target\""
        fping -agq "$target" | tee "$targets_tmp"
        cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
        ezpz_cmd "Saving enumerated hosts to ./hosts.txt"
    else if echo "$target" | grep -qE "$ip_pattern"
        # Single IP
        echo "$target" > "$targets_tmp"
    else
        ezpz_error "Invalid target format: $target"
        echo $usage
        return 1
    end

    # Check if temporary file has content
    if not test -s "$targets_tmp"
        ezpz_warn "No live hosts found"
        return 0
    end

    # Port Scanning - Fast TCP Scan
    ezpz_header "Running FAST TCP SCAN on discovered hosts"
    ezpz_cmd "sudo nmap -T4 -Pn -F --min-rate 10000 <target_ip>"
    while read -l item
        ezpz_info "Scanning $item..."
        sudo /usr/bin/nmap -T4 -Pn -F --min-rate 10000 "$item" |
            sed -n '/PORT/,$p' |
            sed -n '/Nmap done/q;p' |
            grep --color=never -v '^[[:space:]]*$'
    end < "$targets_tmp"

    if test $fast_scan -eq 1
        ezpz_warn "Fast scan complete."
        return 0
    end

    # Full TCP Scan
    ezpz_header "Running FULL TCP SCAN on discovered hosts"
    ezpz_cmd "sudo nmap -T4 -Pn -sVC -p- --min-rate 10000 -vv <target_ip>"
    while read -l item
        ezpz_info "Scanning $item..."
        sudo /usr/bin/nmap -T4 -Pn -sVC -p- "$item" --min-rate 10000 -vv 2>/dev/null |
            sed -n '/PORT/,$p' |
            sed -n '/Script Post-scanning/q;p' |
            grep --color=never -v '^[[:space:]]*$' #|
            #sed 's/^/'(set_color blue)'|/;s/$/'(set_color normal)'/'
    end < "$targets_tmp"

    # UDP Scan
    ezpz_header "Running UDP SCAN on discovered hosts"
    ezpz_cmd "sudo nmap -T4 -sU --open --min-rate 10000 <target_ip>"
    while read -l item
        ezpz_info "Scanning $item..."
        sudo /usr/bin/nmap -T4 -sU --open --min-rate 10000 "$item" |
            sed -n '/PORT/,$p' |
            sed -n '/Nmap done/q;p' |
            grep --color=never -v '^[[:space:]]*$'
    end < "$targets_tmp"

    # Finalization
    ezpz_success "Done."
end 