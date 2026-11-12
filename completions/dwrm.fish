# Fish completions for dwrm - WinRM enumeration tool
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __dwrm_get_ips
    __ezpz_completion_targets
end

# Helper function to get usernames from creds.txt
function __dwrm_get_users
    if test -f creds.txt
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match '*:*' | cut -d: -f1 | sort -u
    end
end

# Helper function to get password/hash for a specific user from creds.txt
function __dwrm_get_creds_for_user
    set -l user $argv[1]
    if test -f creds.txt; and test -n "$user"
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match "$user:*" | cut -d: -f2-
    end
end

# Helper function to get the current -u flag value from command line
function __dwrm_get_current_user
    set -l tokens (commandline -opc)
    set -l user_flag_next false
    
    for token in $tokens
        if test "$user_flag_next" = true
            echo $token
            return
        end
        if test "$token" = "-u"; or test "$token" = "--user"
            set user_flag_next true
        end
    end
end

# Helper function to get domains/hostnames from *_etchosts.txt files
function __dwrm_get_domains
    __ezpz_completion_domains
end

# Target IP completion - first positional argument
complete -c dwrm -f -n 'not __fish_seen_subcommand_from (dwrm --help 2>/dev/null | grep -o "\-[a-zA-Z]")' -a '(__dwrm_get_ips)'

# Username completion from creds.txt
complete -c dwrm -f -s u -l user -r -a '(__ezpz_creds_completion_users)' -d 'Username for authentication'

# Password completion based on selected user
complete -c dwrm -f -s p -l password -r -a '(__ezpz_creds_completion_passwords)' -d 'Password for authentication'

# Hash completion based on selected user (NTLM hash)
complete -c dwrm -f -s H -l hash -r -a '(__ezpz_creds_completion_hashes)' -d 'NTLM hash for pass-the-hash'

# Domain Controller FQDN completion from *_etchosts.txt files
complete -c dwrm -f --keep-order -l dc -r -a '(__dwrm_get_domains)' -d 'Domain Controller FQDN'

# Help option
complete -c dwrm -f -s h -l help -d 'Show help message'
