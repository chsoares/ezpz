function _ezpz_adscan
    source $EZPZ_HOME/functions/_ezpz_colors.fish

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
        return 1
    end

    # Check for exactly one positional argument
    if test (count $argv) -ne 1
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    set input $argv[1]

    # Prerequisites check
    for tool in fping nxc
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Generate hosts file name from target
    set target_clean (echo "$input" | sed 's/[\/:]/_/g')
    set hostsfile "$target_clean"_etchosts.txt
    set krb5file "$target_clean"_krb5conf.txt

    # Trap for cleanup
    trap "rm -f '$targets_tmp'" EXIT TERM INT

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
    else if not echo "$input" | grep -qE "$cidr_pattern|$ip_pattern"
        ezpz_error "Invalid target format: $input"
        echo $usage
        return 1
    end


    # NetExec Scanning with hosts and krb5 file generation
    ezpz_header "Running NetExec on target network"
    set output (mktemp)
    nxc smb "$input" --generate-hosts-file "$hostsfile" > $output
    if test $status -ne 0
        ezpz_error "NetExec failed."
        return 1
    end

    cat $output | grep --color=never -oE '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).*' \
                | string replace -a "Null Auth:True" (set_color red --bold)"Null Auth:True"(set_color normal)
                | string replace -a "signing:False" (set_color cyan)"signing:False"(set_color normal)
                | string replace -a "SMBv1:True" (set_color cyan)"SMBv1:True"(set_color normal)

    # Remove duplicates from hosts file
    if test -f "$hostsfile"
        sort -u "$hostsfile" -o "$hostsfile"
    end

    # Display generated hosts file
    if test -f "$hostsfile"
        ezpz_info "Hosts file generated at $hostsfile"
        cat "$hostsfile"
        
        ezpz_question "Add hosts information to /etc/hosts? [append/overwrite/no]"
        read -l choice
        or set choice "append"
        set choice (string trim $choice)
        
        switch "$choice"
            case "append" "" "a"
                # Append mode (default) - merge hosts for existing IPs
                while read -l line
                    test -n "$line"; or continue
                    
                    set -l ip (echo "$line" | awk '{print $1}')
                    set -l new_hosts (echo "$line" | cut -d' ' -f2-)
                    
                    # Check if IP already exists in /etc/hosts
                    set -l existing_line (grep "^$ip\s" /etc/hosts)
                    
                    if test -n "$existing_line"
                        # IP exists, merge hostnames avoiding duplicates
                        set -l existing_hosts (echo "$existing_line" | cut -d' ' -f2-)
                        
                        # Combine and deduplicate hosts (exclude IP addresses)
                        set -l all_hosts
                        for host in (string split ' ' "$new_hosts")
                            if test -n "$host"; and not echo "$host" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
                                set -a all_hosts "$host"
                            end
                        end
                        for host in (string split ' ' "$existing_hosts")
                            if test -n "$host"; and not contains "$host" $all_hosts; and not echo "$host" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
                                set -a all_hosts "$host"
                            end
                        end
                        
                        set -l merged_entry "$ip    "(string join ' ' $all_hosts)
                        
                        # Replace the existing line
                        sudo sed -i "s|^$ip\s.*|$merged_entry|" /etc/hosts
                        ezpz_info "Updated /etc/hosts: $merged_entry"
                    else
                        # IP doesn't exist, add new entry
                        echo "$line" | sudo tee -a /etc/hosts >/dev/null
                        ezpz_info "Added to /etc/hosts: $line"
                    end
                end < "$hostsfile"
                
            case "overwrite" "o" "ow"
                # Overwrite mode - create new /etc/hosts with localhost + generated content
                set temp_hosts (mktemp)
                echo "127.0.0.1    localhost" > "$temp_hosts"
                cat "$hostsfile" >> "$temp_hosts"
                sudo tee /etc/hosts < "$temp_hosts" >/dev/null
                rm -f "$temp_hosts"
                ezpz_info "Overwritten /etc/hosts with localhost + generated hosts"
                
            case "no"
                ezpz_info "Hosts file not added to /etc/hosts"
                
            case "*"
                ezpz_error "Invalid choice. Use 'append', 'overwrite', or 'no'"
        end
    else
        ezpz_warn "No hosts file was generated"
    end

    # KRB5 Configuration
    ezpz_header "Trying to generate KRB5 config file"
    nxc smb "$input" --generate-krb5-file "$krb5file" > /dev/null

    if test -f "$krb5file"
        cat $krb5file | awk /./
        ezpz_info "KRB5.conf generated at $krb5file and exported to \$KRB5_CONFIG"
        set -gx KRB5_CONFIG "$krb5file"
    end

    # Responder Suggestion
    if test -f "$hostsfile"
        ezpz_title "Consider using Responder to capture hashes from Windows hosts!"
        #ezpz_cmd "sudo responder -dwv -I tun0"
    end

    # Finalization
    ezpz_success "Done."
end 