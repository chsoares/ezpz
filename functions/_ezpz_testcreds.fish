function _ezpz_testcreds
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    # Function to highlight "Pwn3d!"
    function highlight_pwned
        string replace -r "(Pwn3d\!)" (set_color red --bold)"\$1"(set_color normal) $argv
    end

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

    # Temporary file for credentials
    set -l auth_tmp (mktemp)
    trap "rm -f '$auth_tmp'" EXIT

    # Process credentials
    if set -q _flag_file
        if not test -f $_flag_file
            ezpz_error "File '$_flag_file' not found."
            return 1
        end
        
        # Read credentials from file
        while read -l line
            set -l line (string trim $line)
            test -z "$line" && continue
            
            set -l user_from_file (string split : $line)[1]
            set -l pass_or_hash_from_file (string split : $line)[2]
            
            # Detect if it's a hash (32 hex chars) or password
            if string match -qr '^[a-fA-F0-9]{32}$' -- $pass_or_hash_from_file
                echo "-t \"$_flag_target\" -u \"$user_from_file\" -H \"$pass_or_hash_from_file\"" $_flag_kerb >> $auth_tmp
            else
                echo "-t \"$_flag_target\" -u \"$user_from_file\" -p \"$pass_or_hash_from_file\"" $_flag_kerb >> $auth_tmp
            end
        end < $_flag_file
    else
        # Use command line credentials
        set -l cred_line "-t \"$_flag_target\""
        if set -q _flag_user
            set cred_line $cred_line "-u \"$_flag_user\""
        end
        if set -q _flag_password
            set cred_line $cred_line "-p \"$_flag_password\""
        else if set -q _flag_hash
            set cred_line $cred_line "-H \"$_flag_hash\""
        end
        if set -q _flag_kerb
            set cred_line $cred_line "-k"
        end
        echo $cred_line > $auth_tmp
    end

    # Test each set of credentials
    while read -l line
        set -l line (string trim $line)
        test -z "$line" && continue

        # Extract user and target for display
        set -l current_user ""
        set -l current_target ""
        
        set -l args (string split " " $line)
        for i in (seq 1 (count $args))
            switch $args[$i]
                case "-t" "--target"
                    set current_target (string trim -c '"' $args[(math $i + 1)])
                case "-u" "--user"
                    set current_user (string trim -c '"' $args[(math $i + 1)])
            end
        end

        ezpz_header "Testing $current_user's credentials on $current_target with NetExec (timeout: 60s)"
        ezpz_cmd_display "nxc <PROTOCOL> $line"

        for protocol in $protocols
            ezpz_info_star "Trying "(string upper $protocol)"..."
            
            # Test normal auth
            timeout 60s nxc $protocol $args 2>/dev/null | \
            grep --text --color=never + | \
            highlight_pwned | \
            string replace -r '\s+' ' '

            # Test local auth for supported protocols
            if not contains $protocol ssh ftp
                timeout 60s nxc $protocol $args --local-auth 2>/dev/null | \
                grep --text --color=never + | \
                string replace -a "(local auth)" (set_color blue)"(local auth)"(set_color normal) | \
                highlight_pwned | \
                string replace -r '\s+' ' '
            end
        end
    end < $auth_tmp

    ezpz_warning "Done."
end 