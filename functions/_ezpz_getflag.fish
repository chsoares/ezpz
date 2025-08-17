function _ezpz_getflag
    source $EZPZ_HOME/functions/_ezpz_colors.fish
    
    set -l options 't/target=' 'u/username=' 'p/password=' 'H/hash=' 'd/domain=' 'k/kerberos' 'x/protocol=' 'h/help'
    
    if not argparse $options -- $argv
        return 1
    end
    
    set -l usage "
getflag - Read flags from compromised hosts

Usage: ezpz getflag -t <target> [options]

Options:
  -t, --target <ip>         Target host (Required)
  -u, --username <user>     Username for authentication
  -p, --password <pass>     Password for authentication
  -H, --hash <hash>         NTLM hash for pass-the-hash
  -d, --domain <domain>     Domain for authentication
  -k, --kerberos            Use Kerberos authentication
  -x, --protocol <proto>    Protocol to use (smb/winrm/ssh, default: winrm)
  -h, --help                Show this help message

Examples:
  ezpz getflag -t 192.168.1.10 -u administrator -H hash
  ezpz getflag -t 192.168.1.20 -u root -p password -x ssh
  ezpz getflag -t 192.168.1.30 -u domain\\user -p pass -x smb -d domain.local
"
    
    if set -q _flag_help
        echo $usage
        return 1
    end
    
    if not set -q _flag_target
        ezpz_error "Target IP required (-t)"
        echo $usage
        return 1
    end
    
    set -l target $_flag_target
    set -l protocol winrm
    
    if set -q _flag_protocol
        set protocol $_flag_protocol
    end
    
    if not contains $protocol smb winrm ssh
        ezpz_error "Invalid protocol: $protocol. Use smb, winrm, or ssh"
        echo $usage
        return 1
    end
    
    set -l auth_args
    
    if set -q _flag_username
        set -a auth_args -u $_flag_username
    else
        ezpz_error "Username required (-u)"
        echo $usage
        return 1
    end
    
    if set -q _flag_password
        set -a auth_args -p $_flag_password
    else if set -q _flag_hash
        set -a auth_args -H $_flag_hash
    else if set -q _flag_kerberos
        set -a auth_args -k
        if set -q KRB5CCNAME
            set -a auth_args --use-kcache
            ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
        end
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo ntpdate -u $target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    else
        ezpz_error "Authentication method required (-p, -H, or -k)"
        echo $usage
        return 1
    end

    if set -q _flag_domain
        set -a auth_args -d $_flag_domain
    end
    
    set -l user $_flag_username
    if string match -q "*\\*" $user
        set user (string split '\\' $user)[2]
    end
    
    ezpz_header "Getting $user's flag from $target using $protocol"
    
    set -l command
    switch $protocol
        case winrm smb
            set command "type c:\\users\\$user\\desktop\\*.txt"
        case ssh
            set command "cat ~/*.txt"
    end
    
    ezpz_cmd "nxc $protocol $target $auth_args -x '$command'"
    
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "NetExec (nxc) not found in PATH"
        return 1
    end
    
    nxc $protocol $target $auth_args -x $command 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
end