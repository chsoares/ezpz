function ezpz_adscan
    source $EZPZ_HOME/functions/ezpz_colors.fish

    # Usage message
    set usage "
Usage: ezpz adscan <target>
  <target> can be a CIDR range (e.g., 10.10.10.0/24), a single IP, or a file with targets.
  This function attempts to write to /etc/hosts and may require sudo.
"
    # ASCII art banner
    echo ''
    echo '             |'(set_color magenta --bold)'   __|   __|    \     \ | '(set_color normal)
    echo '   _` |   _` |'(set_color magenta --bold)' \__ \  (      _ \   .  | '(set_color normal)
    echo ' \__,_| \__,_|'(set_color magenta --bold)' ____/ \___| _/  _\ _|\_| '(set_color normal)
    echo ''

    # Variables
    set input ""

    # Argument parsing
    argparse 'h/help' -- $argv
    or return 1

    if set -q _flag_help
        echo $usage
        return 0
    end

    # Check for exactly one positional argument
    if test (count $argv) -ne 1
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    set input $argv[1]

    # Prerequisites check
    for tool in fping nxc responder
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Temporary files and trap management
    set targets_tmp (mktemp)
    set nxc_tmp (mktemp)
    set nxc_clean (mktemp)

    # Trap for final cleanup
    trap "rm -f '$targets_tmp' '$nxc_tmp' '$nxc_clean'" EXIT TERM
    # Trap for Ctrl+C (skip to next command, don't delete temp)
    trap "echo ''" INT

    # Validation patterns
    set cidr_pattern '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])/([1-9]|[1-2][0-9]|3[0-2])$'
    set ip_pattern '^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'

    # Host Discovery
    if test -f "$input"
        # Targets file
        if not test -r "$input"
            ezpz_error "Cannot read target file: $input"
            return 1
        end
        cp "$input" "$targets_tmp"
    else if echo "$input" | grep -qE "$cidr_pattern"
        # Host discovery with CIDR
        ezpz_header "Running fping on the $input network"
        ezpz_cmd_display "fping -agq \"$input\""
        fping -agq "$input" | tee "$targets_tmp"
        cat "$targets_tmp" >> hosts.txt && sort -u -o hosts.txt hosts.txt
        ezpz_cmd_display "Saving enumerated hosts to ./hosts.txt"
    else if echo "$input" | grep -qE "$ip_pattern"
        # Single IP
        echo "$input" > "$targets_tmp"
    else
        ezpz_error "Invalid target format: $input"
        echo $usage
        return 1
    end

    # Check if temporary file has content
    if not test -s "$targets_tmp"
        ezpz_warning "No live hosts found"
        return 0
    end

    # NetExec Scanning
    ezpz_header "Running NetExec on discovered hosts"
    ezpz_cmd_display "nxc smb <target_ip>"

    while read -l host_item
        ezpz_info_star "Scanning $host_item..."
        nxc smb "$host_item" | tr -s " " | tee -a "$nxc_tmp"
    end < "$targets_tmp"

    if test $status -ne 0; or not test -s "$nxc_tmp"
        ezpz_error "NetExec failed or returned no results."
        return 1
    end

    # Clean ANSI color codes from nxc output
    sed 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$nxc_tmp" > "$nxc_clean"
    set hosts_count (cat "$nxc_clean" | head -n -1 | wc -l)

    # Ask to add hosts to /etc/hosts
    read -P (set_color cyan --bold)"[?] Add discovered hosts to /etc/hosts? [y/N] "(set_color normal) confirm
    if test "$confirm" = "y" -o "$confirm" = "Y"
        while read -l line
            test -z "$line"; and continue
            string match -q "SMB*" "$line"; or continue

            set ip (string match -r '([0-9]{1,3}\.){3}[0-9]{1,3}' "$line")
            set hostname (string match -r 'name:([^)]+)' "$line" | string sub -s 2)
            set domain_name (string match -r 'domain:([^)]+)' "$line" | string sub -s 2)
            set is_dc (string match -ri "DC" "$line" > /dev/null; and echo 1; or echo 0)

            if test -n "$domain_name"
                if test $is_dc -eq 1 -o $hosts_count -eq 1
                    set new_entry "$ip    DC $hostname $hostname.$domain_name $domain_name"
                    set -gx domain $domain_name
                else
                    set new_entry "$ip    $hostname $hostname.$domain_name"
                end
            else
                set new_entry "$ip    $hostname"
            end

            if not grep -q -F "$ip" /etc/hosts
                echo "$new_entry" | sudo tee -a /etc/hosts > /dev/null
            end
        end < "$nxc_clean"

        ezpz_cmd_display "New hosts added to /etc/hosts successfully."
        if set -q domain
            ezpz_info_star "\$domain is set to $domain"
        end
    end

    # Ask to start Responder
    if test -s "$nxc_tmp"
        read -P (set_color cyan --bold)"[?] Windows hosts detected. Start Responder to capture hashes? [y/N] "(set_color normal) confirm_responder
        if test "$confirm_responder" = "y" -o "$confirm_responder" = "Y"
            ezpz_header "Starting Responder..."
            ezpz_cmd_display "sudo responder -dwv -I tun0"
            sudo responder -dwv -I tun0
        end
    end

    # Finalization
    trap - INT
    ezpz_warning "Done."
end 