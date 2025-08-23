# Fish completions for certipy - Active Directory Certificate Services enumeration tool
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __certipy_get_ips
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
function __certipy_get_users
    if test -f creds.txt
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match '*:*' | cut -d: -f1 | sort -u
    end
end

# Helper function to get password/hash for a specific user from creds.txt
function __certipy_get_creds_for_user
    set -l user $argv[1]
    if test -f creds.txt; and test -n "$user"
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match "$user:*" | cut -d: -f2-
    end
end

# Helper function to get the current -u flag value from command line (without @domain part)
function __certipy_get_current_user
    set -l tokens (commandline -opc)
    set -l user_flag_next false
    
    for token in $tokens
        if test "$user_flag_next" = true
            # Extract username part before @domain if present
            echo $token | cut -d@ -f1
            return
        end
        if test "$token" = "-u"; or test "$token" = "--username"
            set user_flag_next true
        end
    end
end

# Helper function to get domains/hostnames from *_etchosts.txt files
function __certipy_get_domains
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

# Helper function to create user@domain combinations
function __certipy_get_user_domain_combos
    set -l users (__certipy_get_users)
    set -l domains (__certipy_get_domains)
    
    for user in $users
        for domain in $domains
            echo "$user@$domain"
        end
    end
end

# Certipy commands
complete -c certipy -f -n '__fish_use_subcommand' -a 'find' -d 'Find certificate templates and CAs'
complete -c certipy -f -n '__fish_use_subcommand' -a 'req' -d 'Request certificates'
complete -c certipy -f -n '__fish_use_subcommand' -a 'auth' -d 'Authenticate with certificates'
complete -c certipy -f -n '__fish_use_subcommand' -a 'template' -d 'Manage certificate templates'
complete -c certipy -f -n '__fish_use_subcommand' -a 'ca' -d 'Manage certificate authorities'
complete -c certipy -f -n '__fish_use_subcommand' -a 'relay' -d 'NTLM relay to ADCS'
complete -c certipy -f -n '__fish_use_subcommand' -a 'shadow' -d 'Shadow credentials attack'

# Authentication options
# Username with domain completion (user@domain format)
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -s u -l username -r -a '(__certipy_get_user_domain_combos)' -d 'Username in user@domain format'

# Password completion based on selected user
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -s p -l password -r -a '(__certipy_get_creds_for_user (__certipy_get_current_user))' -d 'Password for authentication'

# Hash completion based on selected user (format: lm:ntlm)
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l hashes -r -a '(__certipy_get_creds_for_user (__certipy_get_current_user))' -d 'NTLM hashes in lm:ntlm format'

# Domain Controller IP completion
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l dc-ip -r -a '(__certipy_get_ips)' -d 'Domain Controller IP address'

# Target FQDN completion
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l target -r -a '(__certipy_get_domains)' -d 'Target FQDN'

# Common options
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l debug -d 'Enable debug output'
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l ldap-channel-binding -d 'Enable LDAP channel binding'
complete -c certipy -f -n '__fish_seen_subcommand_from find req auth template ca relay shadow' -l no-ldap-channel-binding -d 'Disable LDAP channel binding'

# Find command specific options
complete -c certipy -f -n '__fish_seen_subcommand_from find' -l vulnerable -d 'Only show vulnerable certificate templates'
complete -c certipy -f -n '__fish_seen_subcommand_from find' -l hide-admins -d 'Hide administrator accounts'
complete -c certipy -f -n '__fish_seen_subcommand_from find' -l old-bloodhound -d 'Use old BloodHound format'
complete -c certipy -f -n '__fish_seen_subcommand_from find' -l text -d 'Output results as text'
complete -c certipy -f -n '__fish_seen_subcommand_from find' -l stdout -d 'Output results to stdout'

# Req command specific options
complete -c certipy -f -n '__fish_seen_subcommand_from req' -l template -r -d 'Certificate template name'
complete -c certipy -f -n '__fish_seen_subcommand_from req' -l ca -r -d 'Certificate Authority name'
complete -c certipy -f -n '__fish_seen_subcommand_from req' -l upn -r -d 'User Principal Name for certificate'
complete -c certipy -f -n '__fish_seen_subcommand_from req' -l dns -r -d 'DNS name for certificate'
complete -c certipy -f -n '__fish_seen_subcommand_from req' -l key-size -r -d 'RSA key size (default: 2048)'

# Auth command specific options
complete -c certipy -f -n '__fish_seen_subcommand_from auth' -l pfx -r -d 'PFX certificate file'
complete -c certipy -f -n '__fish_seen_subcommand_from auth' -l pfx-password -r -d 'PFX certificate password'
complete -c certipy -f -n '__fish_seen_subcommand_from auth' -l kirbi -r -d 'Output Kirbi file'

# Help option
complete -c certipy -f -s h -l help -d 'Show help message'