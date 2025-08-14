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

    ezpz_success "Done."
end