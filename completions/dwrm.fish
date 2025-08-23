# Fish completions for dwrm - WinRM enumeration tool
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __dwrm_get_ips
    # Use find to avoid wildcard expansion errors
    set -l ip_files (find . -maxdepth 1 -name "*_ips.txt" -type f 2>/dev/null)
    
    for file in $ip_files
        if test -f "$file"
            cat "$file" 2>/dev/null | string match -r '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        end
    end
    # No output if no files exist - completion will be empty
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
    # Use find to avoid wildcard expansion errors
    set -l hosts_files (find . -maxdepth 1 -name "*_etchosts.txt" -type f 2>/dev/null)
    
    for file in $hosts_files
        if test -f "$file"
            # Extract all hostnames from etchosts format (IP hostname1 hostname2 ...)
            # Skip comments and empty lines, remove first column (IP), print all remaining hostnames
            cat "$file" 2>/dev/null | string match -v '^#*' | string match -v '^[[:space:]]*$' | awk '{for(i=2;i<=NF;i++) print $i}' | string match -v '' | sort -u
        end
    end
    # No output if no files exist - completion will be empty
end

# Target IP completion - first positional argument
complete -c dwrm -f -n 'not __fish_seen_subcommand_from (dwrm --help 2>/dev/null | grep -o "\-[a-zA-Z]")' -a '(__dwrm_get_ips)' -d 'Target IP address'

# Username completion from creds.txt
complete -c dwrm -f -s u -l user -r -a '(__dwrm_get_users)' -d 'Username for authentication'

# Password completion based on selected user
complete -c dwrm -f -s p -l password -r -a '(__dwrm_get_creds_for_user (__dwrm_get_current_user))' -d 'Password for authentication'

# Hash completion based on selected user (NTLM hash)
complete -c dwrm -f -s H -l hash -r -a '(__dwrm_get_creds_for_user (__dwrm_get_current_user))' -d 'NTLM hash for pass-the-hash'

# Domain Controller FQDN completion from *_etchosts.txt files
complete -c dwrm -f -l dc -r -a '(__dwrm_get_domains)' -d 'Domain Controller FQDN'

# Help option
complete -c dwrm -f -s h -l help -d 'Show help message'