function _ezpz_testcreds
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    

    # ASCII art banner
    echo ''
    echo '  |               |  '(set_color magenta --bold)'   __|  _ \  __|  _ \    __| '(set_color normal)
    echo '   _|   -_) (_-<   _|'(set_color magenta --bold)'  (       /  _|   |  | \__ \ '(set_color normal)
    echo ' \__| \___| ___/ \__|'(set_color magenta --bold)' \___| _|_\ ___| ___/  ____/ '(set_color normal)
    echo ''
    
    # Usage message
    set usage "
Usage: ezpz testcreds -t <target> [[-f <file>] | [-u <user>] [-p <password> | -H <hash>] [-k]] [-x <protocols>]
  Tests credentials against multiple protocols on a target.

  -t, --target    Target IP or hostname (required)
  -f, --file      File containing credentials in user:pass/hash format
  -u, --user      Username for authentication
  -p, --password  Password for authentication
  -H, --hash      NTLM hash for pass-the-hash authentication
  -k, --kerb      Use Kerberos authentication
  -x, --protocols Specific protocols to test (comma-separated)
                  Default: smb,winrm,mssql,rdp,ssh,ftp
"

    # Parse arguments
    argparse 't/target=' 'f/file=' 'u/user=' 'p/password=' 'H/hash=' 'k/kerb' 'x/protocols=' 'h/help' -- $argv
    or begin
        ezpz_error "Failed to parse arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
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
            
            set -l user_from_file (string split : $line)[1]
            set -l pass_or_hash_from_file (string split : $line)[2]
            
            set cred_count (math $cred_count + 1)
            
            # Build credential arguments like enumdomain does
            set -l nxc_auth $_flag_target -u $user_from_file
            
            # Detect if it's a hash (32 hex chars) or password
            if string match -qr '^[a-fA-F0-9]{32}$' -- $pass_or_hash_from_file
                set -a nxc_auth -H $pass_or_hash_from_file
            else
                set -a nxc_auth -p $pass_or_hash_from_file
            end
            
            if set -q _flag_kerb
                set -a nxc_auth -k
            end
            
            # Store this credential set
            set -a cred_sets "$user_from_file"
            set -g "cred_$cred_count" $nxc_auth
        end < $_flag_file
    else
        # Use command line credentials - build like enumdomain
        set -l nxc_auth $_flag_target -u $_flag_user
        
        if set -q _flag_password
            set -a nxc_auth -p $_flag_password
        else if set -q _flag_hash
            set -a nxc_auth -H $_flag_hash
        end
        
        if set -q _flag_kerb
            set -a nxc_auth -k
        end
        
        set cred_sets "$_flag_user"
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
            
            # Test normal auth - same pattern as enumdomain
            timeout 60s nxc $protocol $cred_args | \
            grep --text --color=never + | \
            string replace -a "Pwn3d!" (set_color red --bold)"Pwn3d!"(set_color normal) | \
            string replace -r '\s+' ' '

            # Test local auth for supported protocols
            if not contains $protocol ssh ftp
                timeout 60s nxc $protocol $cred_args --local-auth | \
                grep --text --color=never + | \
                awk '{print $0 " '(set_color blue)'(local auth)'(set_color normal)'"}' | \
                string replace -a "Pwn3d!" (set_color red --bold)"Pwn3d!"(set_color normal) | \
                string replace -r '\s+' ' '
            end
        end
        
        # Clean up the credential variable
        set -e "cred_$cred_num"
        set cred_num (math $cred_num + 1)
    end

    ezpz_success "Done."
end