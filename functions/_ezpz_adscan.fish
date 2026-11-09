function _ezpz_adscan
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # Usage message
    set usage "
Usage: ezpz adscan <target>
  <target> can be a CIDR range (e.g., 10.10.10.0/24), a single IP, or a file with targets.
  This function attempts to write to /etc/hosts and may require sudo.
"
    ezpz_banner adscan

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
    for tool in nxc
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Generate hosts file name from target
    set target_clean (echo "$input" | sed 's/[\/:]/_/g')
    set hostsfile "$target_clean"_etchosts.txt

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
    ezpz_cmd "nxc smb $input"
    set output (mktemp)
    ezpz_spin nxc smb "$input" --generate-hosts-file "$hostsfile" > $output
    if test $status -ne 0
        ezpz_error "NetExec failed."
        return 1
    end

    cat $output | grep --color=never -oE '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).*' \
                | string replace -a "Null Auth:True" (set_color red --bold)"Null Auth:True"(set_color normal) \
                | string replace -a "signing:False" (set_color cyan)"signing:False"(set_color normal) \
                | string replace -a "SMBv1:True" (set_color cyan)"SMBv1:True"(set_color normal) \
                | string replace -a "NTLM:False" (set_color red --bold)"NTLM:False"(set_color normal)

    # Keep the domain controllers found in the SMB scan: the KRB5 config is
    # generated per domain, so we need every DC before $output is reused below.
    set -l dc_records (grep --text -F '(DC:True)' $output)

    ezpz_cmd "nxc ldap $input"
    ezpz_spin timeout 30 nxc ldap $input > $output
    cat $output | grep --color=never -oE '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).*' \
                | string replace -a "signing:None" (set_color red --bold)"signing:None"(set_color normal) \
                | string replace -a "channel binding:No TLS cert" (set_color cyan)"channel binding:No TLS cert"(set_color normal) \
                | string replace -a "channel binding:Never" (set_color cyan)"channel binding:Never"(set_color normal)

    ezpz_cmd "nxc winrm $input"
    ezpz_spin nxc winrm $input | grep --color=never -oE '(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]).*'

    # Remove duplicates from hosts file
    if test -f "$hostsfile"
        sort -u "$hostsfile" -o "$hostsfile"
    end

    # Display generated hosts file
    if test -f "$hostsfile"
        ezpz_info "Hosts file generated at $hostsfile"
        cat "$hostsfile"
        
        ezpz_question "Add hosts information to /etc/hosts? [append/overwrite/no]"
        set choice (ezpz_choose_one append overwrite no)
        
        switch "$choice"
            case "append"
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
                
            case "overwrite"
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
    # Generate one config per domain advertised by a DC on the scanned range.
    ezpz_header "Generating KRB5 config files"
    set -l krb5_files
    set -l krb5_domains

    for record in $dc_records
        set -l domain (string match -r '\(domain:([^)]+)\)' -- $record)[2]
        set -l dc_name (string match -r '\(name:([^)]+)\)' -- $record)[2]
        test -n "$domain"; or continue
        test -n "$dc_name"; or continue
        contains -- $domain $krb5_domains; and continue

        set -a krb5_domains $domain
        set -l krb5file "$domain"_krb5conf.txt
        set -a krb5_files $krb5file

        set -l realm (string upper $domain)
        set -l kdc (string lower $dc_name).$domain

        printf '%s\n' \
            '[libdefaults]' \
            '    dns_lookup_kdc = false' \
            '    dns_lookup_realm = false' \
            "    default_realm = $realm" \
            '' \
            '[realms]' \
            "    $realm = {" \
            "        kdc = $kdc" \
            "        admin_server = $kdc" \
            "        default_domain = $domain" \
            '    }' \
            '' \
            '[domain_realm]' \
            "    .$domain = $realm" \
            "    $domain = $realm" > $krb5file
    end

    switch (count $krb5_files)
        case 0
            ezpz_warn "No domain controller found. No KRB5 config generated."
        case 1
            cat $krb5_files[1]
            ezpz_info "KRB5.conf generated at $krb5_files[1] and exported to \$KRB5_CONFIG"
            set -gx KRB5_CONFIG $krb5_files[1]
        case '*'
            ezpz_info "Multiple domains found. Generated one KRB5 config per domain:"
            for krb5file in $krb5_files
                printf '  %s\n' "$PWD/$krb5file"
            end
            ezpz_warn "KRB5_CONFIG not exported. Choose a domain and run:"
            printf '  export KRB5_CONFIG=%s\n' "$PWD/$krb5_files[1]"
            if set -q KRB5_CONFIG
                ezpz_warn "KRB5_CONFIG is still set to a previous value: $KRB5_CONFIG"
            end
    end

    # Finalization
    ezpz_success "Done."
end 