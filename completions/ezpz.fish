# Fish completions for ezpz pentesting toolkit
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __ezpz_get_ips
    # Use find to avoid wildcard expansion errors
    set -l ip_files (find . -maxdepth 1 -name "*_ips.txt" -type f 2>/dev/null)
    
    # First, list the filenames themselves (without ./ prefix)
    for file in $ip_files
        echo (basename "$file")
    end
    
    # Then list the IPs inside the files
    for file in $ip_files
        if test -f "$file"
            cat "$file" 2>/dev/null | string match -r '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
        end
    end
    # No output if no files exist - completion will be empty
end

# Helper function to get usernames from creds.txt
function __ezpz_get_users
    if test -f creds.txt
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match '*:*' | cut -d: -f1 | sort -u
    end
end

# Helper function to get password/hash for a specific user from creds.txt
function __ezpz_get_creds_for_user
    set -l user $argv[1]
    if test -f creds.txt; and test -n "$user"
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match "$user:*" | cut -d: -f2-
    end
end

# Helper function to get the current -u flag value from command line
function __ezpz_get_current_user
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
function __ezpz_get_domains
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

# Main ezpz commands
complete -c ezpz -f -n '__fish_use_subcommand' -a 'netscan' -d 'Network discovery and port scanning'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'webscan' -d 'Web enumeration with whatweb and ffuf'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'adscan' -d 'Active Directory enumeration'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'checkvulns' -d 'Vulnerability assessment'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'enumnull' -d 'Initial enumeration via NULL sessions'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'enumdomain' -d 'Domain enumeration'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'enumuser' -d 'User enumeration'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'enumshares' -d 'Share enumeration'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'enumsqli' -d 'SQL Server enumeration'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'testcreds' -d 'Test credentials against targets'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getloot' -d 'Extract information from Windows hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'secretsparse' -d 'Parse secretsdump.py output'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getflag' -d 'Read flags from compromised hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getshell' -d 'Get reverse shell from compromised hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'credspray' -d 'Password spraying using kerbrute'

# Target flag with IP completion from *_ips.txt files - requires argument
# All commands that take targets
complete -c ezpz -f -n '__fish_seen_subcommand_from netscan webscan adscan checkvulns enumnull enumdomain enumuser enumshares enumsqli testcreds getloot getflag getshell credspray' -s t -l target -r -a '(__ezpz_get_ips)' -d 'Target IP or hostname'

# Authentication options - for commands that support auth
# Username completion from creds.txt
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot' -s u -l user -r -a '(__ezpz_get_users)' -d 'Username'

# Password completion based on selected user
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot' -s p -l password -r -a '(__ezpz_get_creds_for_user (__ezpz_get_current_user))' -d 'Password for authentication'

# Hash completion based on selected user
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot' -s H -l hash -r -a '(__ezpz_get_creds_for_user (__ezpz_get_current_user))' -d 'NTLM hash for pass-the-hash'

# Domain option with hostname completion from *_etchosts.txt files
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot credspray' -s d -l domain -r -a '(__ezpz_get_domains)' -d 'Domain name'

# Kerberos authentication
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot' -s k -l kerb -d 'Use Kerberos authentication'

# Help option - for all commands
complete -c ezpz -f -n '__fish_seen_subcommand_from netscan webscan adscan checkvulns enumnull enumdomain enumuser enumshares enumsqli testcreds getloot secretsparse getflag getshell credspray' -s h -l help -d 'Show help message'

# Specific options for individual commands
# testcreds specific
complete -c ezpz -f -n '__fish_seen_subcommand_from testcreds' -s f -l file -r -d 'File containing credentials in user:pass/hash format'
complete -c ezpz -f -n '__fish_seen_subcommand_from testcreds' -s x -l protocols -r -a 'smb,winrm,mssql,rdp,ssh,ftp' -d 'Protocol'

# enumsqli specific
complete -c ezpz -f -n '__fish_seen_subcommand_from enumsqli' -s F -l fast -d 'Skip DBMS enumeration and interactive prompts'

# credspray specific
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s u -l usersfile -r -a '(find . -maxdepth 1 -name "*users.txt" -type f 2>/dev/null | sed "s|^\./||")' -d 'File with usernames (one per line)'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s p -l password -r -a '(find . -maxdepth 1 -name "*.txt" -type f 2>/dev/null | sed "s|^\./||")' -d 'Password to spray (string or file)'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s c -l credsfile -r -a '(find . -maxdepth 1 -name "*.txt" -type f 2>/dev/null | sed "s|^\./||")' -d 'File with user:pass credentials'
