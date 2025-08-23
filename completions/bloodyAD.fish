# Fish completions for bloodyAD - Active Directory privilege escalation framework
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __bloodyad_get_ips
    set -l ip_files (find . -maxdepth 1 -name "*_ips.txt" -type f 2>/dev/null)
    
    for file in $ip_files
        if test -f "$file"
            cat "$file" 2>/dev/null | string match -r '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        end
    end
end

# Helper function to get usernames from creds.txt
function __bloodyad_get_users
    if test -f creds.txt
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match '*:*' | cut -d: -f1 | sort -u
    end
end

# Helper function to get password/hash for a specific user from creds.txt
function __bloodyad_get_creds_for_user
    set -l user $argv[1]
    if test -f creds.txt; and test -n "$user"
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match "$user:*" | cut -d: -f2-
    end
end

# Helper function to get the current -u flag value from command line
function __bloodyad_get_current_user
    set -l tokens (commandline -opc)
    set -l user_flag_next false
    
    for token in $tokens
        if test "$user_flag_next" = true
            echo $token
            return
        end
        if test "$token" = "-u"; or test "$token" = "--username"
            set user_flag_next true
        end
    end
end

# Helper function to get domains/hostnames from *_etchosts.txt files
function __bloodyad_get_domains
    set -l hosts_files (find . -maxdepth 1 -name "*_etchosts.txt" -type f 2>/dev/null)
    
    for file in $hosts_files
        if test -f "$file"
            cat "$file" 2>/dev/null | string match -v '^#*' | string match -v '^[[:space:]]*$' | awk '{for(i=2;i<=NF;i++) print $i}' | string match -v '' | sort -u
        end
    end
end

# Helper function to get all IPs and FQDNs for target completion
function __bloodyad_get_targets
    __bloodyad_get_ips
    __bloodyad_get_domains
end

# Main commands
complete -c bloodyAD -f -n '__fish_use_subcommand' -a 'add' -d 'Add objects, rights, or properties to AD'
complete -c bloodyAD -f -n '__fish_use_subcommand' -a 'get' -d 'Retrieve information from AD'
complete -c bloodyAD -f -n '__fish_use_subcommand' -a 'remove' -d 'Remove objects, rights, or properties from AD'
complete -c bloodyAD -f -n '__fish_use_subcommand' -a 'set' -d 'Modify existing AD objects or properties'

# GET subcommands
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'children' -d 'List children for a given target object'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'dnsDump' -d 'Retrieve DNS records of the Active Directory'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'membership' -d 'Retrieve SID and SAM Account Names of all groups a target belongs to'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'object' -d 'Retrieve LDAP attributes for the target object'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'search' -d 'Search in LDAP database'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'trusts' -d 'Display trusts in an ascii tree'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from get' -a 'writable' -d 'Retrieve objects writable by client'

# ADD subcommands
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'computer' -d 'Adds new computer (args: name password)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'dcsync' -d 'Adds DCSync right on domain (args: trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'dnsRecord' -d 'Adds a new DNS record (args: name data)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'genericAll' -d 'Gives full control to trustee on target (args: target trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'groupMember' -d 'Adds a new member to group (args: target member)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'rbcd' -d 'Adds Resource Based Constraint Delegation (args: target trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'shadowCredentials' -d 'Adds Key Credentials to target (args: target)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'uac' -d 'Adds property flags altering object behavior (args: target flag)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from add' -a 'user' -d 'Adds a new user (args: name password)'

# REMOVE subcommands
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'dcsync' -d 'Removes DCSync right (args: trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'dnsRecord' -d 'Removes a DNS record (args: name data)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'genericAll' -d 'Removes full control of trustee on target (args: target trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'groupMember' -d 'Removes member from group (args: target member)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'object' -d 'Removes object (args: target)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'rbcd' -d 'Removes Resource Based Constraint Delegation (args: target trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'shadowCredentials' -d 'Removes Key Credentials (args: target)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from remove' -a 'uac' -d 'Removes property flags (args: target flag)'

# SET subcommands
complete -c bloodyAD -f -n '__fish_seen_subcommand_from set' -a 'object' -d 'Add/Replace/Delete target attribute (args: target attribute value)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from set' -a 'owner' -d 'Changes target ownership (args: target trustee)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from set' -a 'password' -d 'Change password of a user/computer (args: target password)'
complete -c bloodyAD -f -n '__fish_seen_subcommand_from set' -a 'restore' -d 'Restore deleted objects (args: target)'

# Authentication options - for all commands
# Username completion from creds.txt
complete -c bloodyAD -f -s u -l username -r -a '(__bloodyad_get_users)' -d 'Username for authentication'

# Password completion based on selected user
complete -c bloodyAD -f -s p -l password -r -a '(__bloodyad_get_creds_for_user (__bloodyad_get_current_user))' -d 'Password for authentication (or :hash for pass-the-hash)'

# Domain option with hostname completion from *_etchosts.txt files
complete -c bloodyAD -f -s d -l domain -r -a '(__bloodyad_get_domains)' -d 'Domain name'

# Host option with IP/FQDN completion
complete -c bloodyAD -f -l host -r -a '(__bloodyad_get_targets)' -d 'Target host IP or FQDN'

# Domain Controller IP option
complete -c bloodyAD -f -l dc-ip -r -a '(__bloodyad_get_ips)' -d 'Domain Controller IP address'

# Common options
complete -c bloodyAD -f -l kerberos -d 'Use Kerberos authentication'
complete -c bloodyAD -f -l no-pass -d 'Do not prompt for password'
complete -c bloodyAD -f -l cert -r -d 'Certificate file for authentication'
complete -c bloodyAD -f -l key -r -d 'Private key file for certificate auth'

# Help option
complete -c bloodyAD -f -s h -l help -d 'Show help message'