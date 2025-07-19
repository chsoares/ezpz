function _ezpz_enumnull
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '                           '(set_color yellow --bold)'  __ \   |  |   |     |     '(set_color normal)
    echo '     -_)    \   |  |   ` \ '(set_color yellow --bold)'  |   |  |  |   |     |     '(set_color normal)
    echo '   \___| _| _| \_,_| _|_|_|'(set_color yellow --bold)' ____/  \__/  ____| ____| '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: ezpz enumnull -t <target>
  Performs initial reconnaissance on a target without credentials (null session).

  -t, --target    Target IP or hostname (Required)

Examples:
  ezpz enumnull -t 10.10.10.10
  ezpz enumnull -t dc01.corp.local
"

    # Check required tools
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Parse arguments
    argparse 't/target=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    # Check required arguments
    if not set -q _flag_target
        ezpz_error "Missing required argument: -t/--target"
        echo $usage
        return 1
    end

    set target $_flag_target

    # Create temporary files
    set users_tmp (mktemp)
    set users_temp (mktemp)
    trap 'rm -f "$users_tmp" "$users_temp"' EXIT TERM
    trap "echo ''" INT

    ezpz_title "Starting null session enumeration on $target..."

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

    # User Enumeration
    ezpz_header "Enumerating users"
    ezpz_cmd "nxc smb $target -u '' -p '' --users"
    timeout 60 nxc smb $target -u '' -p '' --users 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5,9- | tail -n +2 | awk '{if (NF>1) {printf "%s [", $1; for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":""); print "]"} else print $1}' | tee $users_temp
    
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -s $users_temp
        # Extract just usernames and save to file
        cat $users_temp | awk '{print $1}' > $users_tmp
        cp $users_tmp $users_file
        ezpz_info "Saving enumerated users to $users_file"
    else
        ezpz_warn "No users found with --users. Trying RID brute force..."
        
        # Fallback to RID brute force
        ezpz_header "Enumerating users with RID Bruteforcing (fallback)"
        ezpz_cmd "nxc smb $target -u '' -p '' --rid-brute 10000"
        timeout 60 nxc smb $target -u '' -p '' --rid-brute 10000 2>/dev/null | grep 'SidTypeUser' | cut -d ':' -f2 | cut -d '\\' -f2 | cut -d ' ' -f1 | tee $users_tmp
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping."
        else if test -s $users_tmp
            cp $users_tmp $users_file
            ezpz_info "Saving enumerated users to $users_file"
        else
            ezpz_warn "No users found during RID Bruteforcing with null session."
        end
    end

    # Groups
    ezpz_header "Enumerating groups"
    ezpz_cmd "nxc smb $target -u '' -p '' --groups"
    timeout 60 nxc smb $target -u '' -p '' --groups 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Password Policy
    ezpz_header "Enumerating password policy"
    ezpz_cmd "nxc smb $target -u '' -p '' --pass-pol"
    timeout 60 nxc smb $target -u '' -p '' --pass-pol 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Shares Enumeration
    ezpz_header "Enumerating shares"
    ezpz_cmd "nxc smb $target -u '' -p '' --shares"
    timeout 60 nxc smb $target -u '' -p '' --shares 2>/dev/null | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    trap - INT
    ezpz_success "Done."
end