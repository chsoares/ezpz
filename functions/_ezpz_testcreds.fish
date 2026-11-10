# RDP/MSSQL logins without Pwn3d only prove the password is valid; they do not
# give administrative access. Keep those protocols focused on actionable hits.
function __ezpz_testcreds_filter --argument-names protocol
    if contains -- $protocol rdp mssql
        grep --text --color=never -a 'Pwn3d!'
    else
        cat
    end
end

function _ezpz_testcreds
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    

    ezpz_banner testcreds
    
    # Usage message
    set usage "
Usage: ezpz testcreds -t <target> [[-f <file>] | [-u <user>] [-p <password> | -H <hash>] [-k]] [-x <protocols>]
  Tests credentials against multiple protocols on a target.

  -t, --target    Target IP or hostname (required)
  -f, --file      File containing credentials in user:pass/hash format
  -u, --user      Username for authentication
  -p, --password  Password for authentication
  -H, --hash      NTLM hash for pass-the-hash authentication
  -d, --domain    Domain for authentication
  -k, --kerb      Use Kerberos authentication
  -x, --protocols Specific protocols to test (comma-separated)
                  Default: smb,winrm,mssql,rdp,ssh,ftp
"

    # Parse arguments
    argparse 't/target=' 'f/file=' 'u/user=' 'p/password=' 'H/hash=' 'd/domain=' 'k/kerb' 'x/protocols=' 'h/help' -- $argv
    or begin
        ezpz_error "Failed to parse arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 1
    end

    # Validate required target
    if not set -q _flag_target
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    # Check for nxc
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Set default protocols if not specified
    set -l protocols
    if set -q _flag_protocols
        set protocols (string split , $_flag_protocols)
    else
        set protocols smb winrm mssql rdp ssh ftp
    end

    # Resolve the DC FQDN for Kerberos SPNs and warn about a CIFS-only ccache.
    set -l target $_flag_target
    set -l dc_fqdn (ezpz_dc_fqdn $target)
    test -n "$dc_fqdn"; or set dc_fqdn $target
    set -l nxc_target $target
    if set -q _flag_kerb; and test -n "$dc_fqdn"
        set nxc_target $dc_fqdn
        ezpz_kerberos_check smb; or return 1
    end

    # Store credential sets
    set -l cred_sets

    # Process credentials
    if set -q _flag_file
        if not test -f $_flag_file
            ezpz_error "File '$_flag_file' not found."
            return 1
        end
        
        # Read credentials from file
        set -l cred_count 0
        while read -l line
            set line (string trim -- $line)
            test -z "$line" && continue
            
            set -l user_from_file (string split -m1 : $line)[1]
            set -l pass_or_hash_from_file (string split -m1 : $line)[2]

            # Split DOMAIN\user or user@domain into bare user + domain. Kerberos
            # needs -u bare -d domain to match the ccache principal.
            set -l user_domain ""
            if string match -q '*\\*' -- $user_from_file
                set user_domain (string split '\\' $user_from_file)[1]
                set user_from_file (string split '\\' $user_from_file)[2]
            else if string match -q '*@*' -- $user_from_file
                set user_domain (string split '@' $user_from_file)[2]
                set user_from_file (string split '@' $user_from_file)[1]
            else if set -q _flag_domain
                set user_domain $_flag_domain
            end
            
            set cred_count (math $cred_count + 1)
            
            # Build credential arguments like enumdomain does
            set -l nxc_auth $nxc_target -u $user_from_file
            if test -n "$user_domain"
                set -a nxc_auth -d "$user_domain"
            end
            
            # Detect if it's a hash (32 hex chars) or password
            if string match -qr '^[a-fA-F0-9]{32}$' -- $pass_or_hash_from_file
                set -a nxc_auth -H $pass_or_hash_from_file
            else
                set -a nxc_auth -p $pass_or_hash_from_file
            end
            
            if set -q _flag_kerb
                set -a nxc_auth -k
                if set -q KRB5CCNAME
                    set -a nxc_auth --use-kcache
                end
            end
            
            # Store this credential set
            set -a cred_sets "$user_from_file"
            set -g "cred_$cred_count" $nxc_auth
        end < $_flag_file
    else
        # Use command line credentials - bare user + -d domain
        set -l cli_user $_flag_user
        set -l cli_domain ""
        if string match -q '*\\*' -- $cli_user
            set cli_domain (string split '\\' $cli_user)[1]
            set cli_user (string split '\\' $cli_user)[2]
        else if string match -q '*@*' -- $cli_user
            set cli_domain (string split '@' $cli_user)[2]
            set cli_user (string split '@' $cli_user)[1]
        else if set -q _flag_domain
            set cli_domain $_flag_domain
        end

        set -l nxc_auth $nxc_target -u $cli_user
        if test -n "$cli_domain"
            set -a nxc_auth -d "$cli_domain"
        end
        
        if set -q _flag_password
            set -a nxc_auth -p $_flag_password
        else if set -q _flag_hash
            set -a nxc_auth -H $_flag_hash
        end
        
        if set -q _flag_kerb
            set -a nxc_auth -k
            if set -q KRB5CCNAME
                set -a nxc_auth --use-kcache
            end
        end
        
        set cred_sets "$cli_user"
        set -g cred_1 $nxc_auth
    end

    # Test each set of credentials
    set -l cred_num 1
    for current_user in $cred_sets
        set -l cred_args_var "cred_$cred_num"
        set -l cred_args $$cred_args_var

        ezpz_header "Testing $current_user's credentials on $_flag_target with NetExec (timeout: 60s)"
        ezpz_cmd "nxc <PROTOCOL> $cred_args"

        for protocol in $protocols
            ezpz_info "Trying "(string upper $protocol)"..."

            if set -q _flag_kerb; and not ezpz_kerberos_has_tgt; and contains $protocol winrm mssql rdp ldap
                ezpz_warn "Skipping "(string upper $protocol)": Kerberos needs a TGT (ccache only has service tickets)."
                continue
            end
            
            # Test normal auth - same pattern as enumdomain
            # Drop generic failures (bad password, timeouts) but keep [-] lines
            # that carry useful account state (disabled, locked, expired, ...).
            ezpz_spin timeout 60s nxc $protocol $cred_args 2>&1 | \
            grep --text --color=never -v -E '\[-\].*(STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED)' | \
            grep --text --color=never -E '\+|DISABLED|ERROR|EXPIRED|LOCKED|MUST_CHANGE|NOT_GRANTED|RESTRICTION|INVALID_LOGON_HOURS' | \
            string replace -a "Pwn3d!" (set_color red --bold)"Pwn3d!"(set_color normal) | \
            string replace -r '\s+' ' ' | \
            __ezpz_testcreds_filter $protocol

            # Test local auth for supported protocols. nxc rejects --local-auth
            # together with -d/-k, so only run it for local credential sets.
            if not contains $protocol ssh ftp; and not contains -- -d $cred_args; and not contains -- -k $cred_args
                ezpz_spin timeout 60s nxc $protocol $cred_args --local-auth 2>&1 | \
                grep --text --color=never -v -E '\[-\].*(STATUS_LOGON_FAILURE|STATUS_ACCESS_DENIED)' | \
                grep --text --color=never -E '\+|DISABLED|ERROR|EXPIRED|LOCKED|MUST_CHANGE|NOT_GRANTED|RESTRICTION|INVALID_LOGON_HOURS' | \
                awk '{print $0 " '(set_color blue)'(local auth)'(set_color normal)'"}' | \
                string replace -a "Pwn3d!" (set_color red --bold)"Pwn3d!"(set_color normal) | \
                string replace -r '\s+' ' ' | \
                __ezpz_testcreds_filter $protocol
            end
        end
        
        # Clean up the credential variable
        set -e "cred_$cred_num"
        set cred_num (math $cred_num + 1)
    end

    ezpz_success "Done."
end