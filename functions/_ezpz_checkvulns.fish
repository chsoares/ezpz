function _ezpz_checkvulns
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '       |                |   '(set_color magenta --bold)'            |            '(set_color normal)
    echo '   _|    \    -_)   _|  | / '(set_color magenta --bold)'\ \ / |  |  |    \  (_-< '(set_color normal)
    echo ' \__| _| _| \___| \__| _\_\ '(set_color magenta --bold)' \_/ \_,_| _| _| _| ___/ '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: checkvulns -t <target> -u <user> [-p <password> | -H <hash>] [-k] [-d domain]
  <target> can be a single host or a file with one host per line.

  -t, --target    Target IP, hostname, or file containing targets.
  -u, --user      Username for authentication.
  -p, --password  Password for authentication.
  -H, --hash      NTLM hash for pass-the-hash authentication.
  -k, --kerb      Use Kerberos authentication (requires a valid TGT).
  -d, --domain    Domain for authentication (optional).
"
    # Check if nxc is installed
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Parse arguments
    argparse 't/target=' 'u/user=' 'p/password=' 'H/hash=' 'k/kerb' 'd/domain=' 'h/help' -- $argv
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

    # Build authentication arguments
    set auth_args
    
    # Only add authentication if user is provided
    if set -q _flag_user
        set -a auth_args -u
        if set -q _flag_domain
            set -a auth_args "$_flag_domain\\$_flag_user"
        else
            set -a auth_args "$_flag_user"
        end

        if set -q _flag_password
            set -a auth_args -p "$_flag_password"
        else if set -q _flag_hash
            set -a auth_args -H "$_flag_hash"
        end

        if set -q _flag_kerb
            set -a auth_args -k
            if set -q KRB5CCNAME
                set -a auth_args --use-kcache
            end
        end
    end

    # Time synchronization for Kerberos
    if set -q _flag_kerb -a set -q _flag_target
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo ntpdate -u $_flag_target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Set timeout for vulnerability checks
    set -x timeout_secs 60

    function _check_single_target
        set target $argv[1]
        set auth_string $argv[2..-1]
        

        ezpz_title "Checking for vulnerabilities on $target"

        # Test SMB connection first
        set smb_test_output (timeout $timeout_secs nxc smb $target $auth_string 2>/dev/null)
        
        # Check if connection failed based on different scenarios
        set should_skip 0
        
        # If no credentials provided, only skip if output is completely empty
        if test (count $auth_string) -eq 0
            if test -z "$smb_test_output"
                set should_skip 1
                ezpz_warn "SMB connection failed for $target (no response). Skipping."
            end
        else
            # If credentials provided, check for authentication failures
            if echo "$smb_test_output" | grep -q "\[-\]"
                set should_skip 1
                ezpz_warn "SMB authentication failed for $target. Skipping."
            else if test -z "$smb_test_output"
                set should_skip 1
                ezpz_warn "SMB connection failed for $target (no response). Skipping."
            end
        end
        
        if test $should_skip -eq 1
            return
        end

        # EternalBlue (MS17-010)
        ezpz_header "EternalBlue (MS17-010)"
        ezpz_cmd "nxc smb $target $auth_string -M ms17-010"
        timeout $timeout_secs nxc smb $target $auth_string -M ms17-010 | grep -a 'MS17-010' | tr -s " " | cut -d " " -f 3-
        if test $status -eq 124
            ezpz_warn "Timeout reached while testing MS17-010 on $target"
        end

        # PrintNightmare (CVE-2021-34527)
        ezpz_header "PrintNightmare (CVE-2021-34527)"
        ezpz_cmd "nxc smb $target $auth_string -M printnightmare"
        timeout $timeout_secs nxc smb $target $auth_string -M printnightmare | grep -a 'PRINT' | tr -s " " | cut -d " " -f 5-
        if test $status -eq 124
            ezpz_warn "Timeout reached while testing PrintNightmare on $target"
        end

        # NoPac (CVE-2021-42278)
        ezpz_header "NoPac (CVE-2021-42278)"
        if test (count $auth_string) -eq 0
            echo "NoPac requires valid credentials to test. Skipping."
        else
            ezpz_cmd "nxc smb $target $auth_string -M nopac"
            timeout $timeout_secs nxc smb $target $auth_string -M nopac | grep -a 'NOPAC' | tr -s " " | cut -d " " -f 5- | tr -s '\n'
            if test $status -eq 124
                ezpz_warn "Timeout reached while testing NoPac on $target"
            end
        end

        # Coerce Attacks (PetitPotam, etc.)
        ezpz_header "Coerce Attacks (PetitPotam, etc.)"
        ezpz_cmd "nxc smb $target $auth_string -M coerce_plus"
        timeout $timeout_secs nxc smb $target $auth_string -M coerce_plus | grep -a 'COERCE' | tr -s " " | cut -d " " -f 5- | tr -s '\n'
        if test $status -eq 124
            ezpz_warn "Timeout reached while testing Coerce on $target"
        end

        # Zerologon (CVE-2020-1472)
        ezpz_header "Zerologon (CVE-2020-1472)"
        ezpz_cmd "nxc smb $target $auth_string -M zerologon"
        timeout $timeout_secs nxc smb $target $auth_string -M zerologon | grep -a 'ZEROLOGON' | tr -s " " | cut -d " " -f 5- | sed 's/[-]//g' | grep -v "DCERPCException"
        if test $status -eq 124
            ezpz_warn "Timeout reached while testing Zerologon on $target"
        end
    end

    # Process target(s)
    if test -f "$_flag_target"
        while read -l target
            _check_single_target $target $auth_args
        end < $_flag_target
    else
        _check_single_target $_flag_target $auth_args
    end

    ezpz_success "Done."
end 