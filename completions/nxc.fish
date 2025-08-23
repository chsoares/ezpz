# Fish completions for nxc (NetExec) - Windows/AD enumeration tool
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Helper function to get IPs from *_ips.txt files in current directory
function __nxc_get_ips
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
function __nxc_get_users
    if test -f creds.txt
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match '*:*' | cut -d: -f1 | sort -u
    end
end

# Helper function to get password/hash for a specific user from creds.txt
function __nxc_get_creds_for_user
    set -l user $argv[1]
    if test -f creds.txt; and test -n "$user"
        cat creds.txt 2>/dev/null | string match -v '^#*' | string match "$user:*" | cut -d: -f2-
    end
end

# Helper function to get the current -u flag value from command line
function __nxc_get_current_user
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
function __nxc_get_domains
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

# NetExec protocols
complete -c nxc -f -n '__fish_use_subcommand' -a 'smb' -d 'SMB protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'winrm' -d 'WinRM protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'mssql' -d 'MSSQL protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'rdp' -d 'RDP protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'ssh' -d 'SSH protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'ftp' -d 'FTP protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'ldap' -d 'LDAP protocol'
complete -c nxc -f -n '__fish_use_subcommand' -a 'vnc' -d 'VNC protocol'

# Target completion with IP completion from *_ips.txt files
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -a '(__nxc_get_ips)' -d 'Target IP or hostname'

# Authentication options
# Username completion from creds.txt
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s u -l username -r -a '(__nxc_get_users)' -d 'Username for authentication'

# Password completion based on selected user
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s p -l password -r -a '(__nxc_get_creds_for_user (__nxc_get_current_user))' -d 'Password for authentication'

# Hash completion based on selected user (NTLM hash)
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s H -l hash -r -a '(__nxc_get_creds_for_user (__nxc_get_current_user))' -d 'NTLM hash for pass-the-hash'

# Domain option with hostname completion from *_etchosts.txt files
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s d -l domain -r -a '(__nxc_get_domains)' -d 'Domain name'

# Kerberos authentication
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s k -l kerberos -d 'Use Kerberos authentication'

# Common NetExec options
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -l local-auth -d 'Authenticate locally to each target'
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -l continue-on-success -d 'Continue after successful authentication'
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -l verbose -d 'Enable verbose output'
complete -c nxc -f -n '__fish_seen_subcommand_from smb winrm mssql rdp ssh ftp ldap vnc' -s t -l threads -r -d 'Number of concurrent threads'

# SMB specific options
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l shares -d 'Enumerate shares'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l sessions -d 'Enumerate active sessions'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l users -d 'Enumerate users'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l groups -d 'Enumerate groups'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l loggedon-users -d 'Enumerate logged on users'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l disks -d 'Enumerate disks'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l pass-pol -d 'Get password policy'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -l rid-brute -d 'RID bruteforce'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -s x -l execute -r -d 'Execute command'
complete -c nxc -f -n '__fish_seen_subcommand_from smb' -s X -l ps-execute -r -d 'Execute PowerShell command'

# WinRM specific options
complete -c nxc -f -n '__fish_seen_subcommand_from winrm' -s x -l execute -r -d 'Execute command'
complete -c nxc -f -n '__fish_seen_subcommand_from winrm' -s X -l ps-execute -r -d 'Execute PowerShell command'

# MSSQL specific options
complete -c nxc -f -n '__fish_seen_subcommand_from mssql' -l query -r -d 'Execute SQL query'
complete -c nxc -f -n '__fish_seen_subcommand_from mssql' -s x -l execute -r -d 'Execute system command via xp_cmdshell'

# Help option
complete -c nxc -f -s h -l help -d 'Show help message'