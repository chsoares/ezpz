# Fish completions for ezpz pentesting toolkit
# Place this file in ~/.config/fish/completions/ or fish_complete_path directory

# Remove stale auth completions if this file is re-sourced in an existing shell.
complete -e -c ezpz -s u
complete -e -c ezpz -s p
complete -e -c ezpz -s H

# Helper function to get IPs from *_ips.txt files in current directory
function __ezpz_get_ips
    __ezpz_completion_targets --files
end

# Helper function to get IPs including tun0 interface (for listener options)
function __ezpz_get_listener_ips
    # Get tun0 IP if available
    set -l tun0_ip (ip addr show tun0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    if test -n "$tun0_ip"
        echo $tun0_ip
    end
    
    # Include only IPs from files, not filenames
    __ezpz_get_dns_ips
end

# Helper function to get only IPs from files (no filenames) for DNS servers
function __ezpz_get_dns_ips
    __ezpz_completion_targets
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
    __ezpz_completion_domains
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
complete -c ezpz -f -n '__fish_use_subcommand' -a 'certspray' -d 'Spray credentials against ADCS'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'path' -d 'Show one-hop AD attack paths from BloodHound'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getloot' -d 'Extract information from Windows hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'secretsparse' -d 'Parse secretsdump.py output'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getflag' -d 'Read flags from compromised hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'getshell' -d 'Get reverse shell from compromised hosts'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'credspray' -d 'Password spraying using kerbrute'
complete -c ezpz -f -n '__fish_use_subcommand' -a 'selfrelay' -d 'NTLM self-relay attack chain'

# Target flag with IP completion from *_ips.txt files - requires argument
# All commands that take targets
complete -c ezpz -f -n '__fish_seen_subcommand_from netscan webscan adscan checkvulns certspray enumnull enumdomain enumuser enumshares enumsqli testcreds getloot getflag getshell credspray selfrelay' -s t -l target -r -a '(__ezpz_get_ips)'

# Authentication options - for commands that support auth
# Username completion from creds.txt
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot selfrelay' -s u -l user -r -a '(__ezpz_creds_completion_users)' -d 'Username'

# Password completion based on selected user
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot selfrelay' -s p -l password -r -a '(__ezpz_creds_completion_passwords)' -d 'Password for authentication'

# Hash completion based on selected user
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot' -s H -l hash -r -a '(__ezpz_creds_completion_hashes)' -d 'NTLM hash for pass-the-hash'

# Domain option with hostname completion from *_etchosts.txt files
complete -c ezpz -f --keep-order -n '__fish_seen_subcommand_from checkvulns certspray path enumdomain testcreds enumuser enumshares enumsqli getloot credspray selfrelay' -s d -l domain -r -a '(__ezpz_get_domains)' -d 'Domain name'
complete -c ezpz -f --keep-order -n '__fish_seen_subcommand_from enumdomain' -l target-domain -r -a '(__ezpz_get_domains)' -d 'Target domain'

# Kerberos authentication
complete -c ezpz -f -n '__fish_seen_subcommand_from checkvulns enumdomain testcreds enumuser enumshares enumsqli getloot selfrelay' -s k -l kerb -d 'Use Kerberos authentication'

# Help option - for all commands
complete -c ezpz -f -n '__fish_seen_subcommand_from netscan webscan adscan checkvulns certspray path enumnull enumdomain enumuser enumshares enumsqli testcreds getloot secretsparse getflag getshell credspray selfrelay' -s h -l help -d 'Show help message'

# Specific options for individual commands
# testcreds specific
complete -c ezpz -f -n '__fish_seen_subcommand_from testcreds' -s f -l file -r -a '(__ezpz_completion_creds_files)' -d 'File containing credentials in user:pass/hash format'
complete -c ezpz -f -n '__fish_seen_subcommand_from testcreds' -s x -l protocols -r -a '(__ezpz_completion_protocols)'

# Users from the selected domain's *_users*.txt files for `path --to`.
function __ezpz_path_to_users
    set -l tokens (commandline -opc)
    set -l domain ""
    set -l want_domain 0
    for token in $tokens
        if test $want_domain -eq 1
            set domain $token
            break
        end
        if test "$token" = "-d"; or test "$token" = "--domain"
            set want_domain 1
        else if string match -q -- '--domain=*' $token
            set domain (string replace -- '--domain=' '' $token)
            break
        end
    end
    test -n "$domain"; or return

    set -l files
    for root in . "$boxpwd"
        test -d "$root"; or continue
        for file in (find "$root" -maxdepth 1 -name "$domain"_users\*.txt -type f 2>/dev/null)
            contains -- $file $files; or set -a files $file
        end
    end

    set -l users
    for file in $files
        while read -l line
            set line (string trim -- $line)
            test -z "$line"; and continue
            string match -q '#*' -- $line; and continue
            set -l user (string split -m1 ' ' -- $line)[1]
            set user (string replace -r -- '@.*$' '' $user)
            set user (string replace -r -- '^.*\\\\' '' $user)
            test -n "$user"; and set -a users $user
        end < "$file"
    end
    printf '%s\n' $users | sort -u
end

# path specific
complete -c ezpz -f -n '__fish_seen_subcommand_from path' -s f -l file -r -a '(find . -maxdepth 1 -name "*_bloodhound.zip" -type f 2>/dev/null | sed "s|^./||")' -d 'BloodHound zip'
complete -c ezpz -f -n '__fish_seen_subcommand_from path' -s u -l user -r -a '(__ezpz_path_to_users)' -d 'User from <domain>_users*.txt'
complete -c ezpz -f -n '__fish_seen_subcommand_from path' -l chain -d 'Search a multihop chain'
complete -c ezpz -f -n '__fish_seen_subcommand_from path' -l short -d 'Show only chain summaries (requires --chain)'
complete -c ezpz -f -n '__fish_seen_subcommand_from path' -l to -r -a '(__ezpz_path_to_users)'

# certspray specific
complete -c ezpz -f -n '__fish_seen_subcommand_from certspray' -s f -l file -r -a '(__ezpz_completion_creds_files)' -d 'Credentials file'

# enumsqli specific
complete -c ezpz -f -n '__fish_seen_subcommand_from enumsqli' -s F -l fast -d 'Skip DBMS enumeration and interactive prompts'

# credspray specific
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s u -l user -r -a '(__ezpz_completion_creds_files)' -d 'Username, username file, or user:pass file'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s p -l password -r -a '(__ezpz_completion_creds_files)' -d 'Password, password file, or user:pass file'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s f -l file -r -a '(__ezpz_completion_creds_files)' -d 'Hail mary: user:pass credential file'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -s F -l force -d 'Ignore the password-policy lockout guard'
complete -c ezpz -f -n '__fish_seen_subcommand_from credspray' -l unsafe -d 'Do not pass --safe to kerbrute'

# selfrelay specific
complete -c ezpz -f -n '__fish_seen_subcommand_from selfrelay' -s l -l listener -r -a '(__ezpz_get_listener_ips)' -d 'Listener IP'
complete -c ezpz -f -n '__fish_seen_subcommand_from selfrelay' -l dns -r -a '(__ezpz_get_dns_ips)' -d 'DNS Server IP'
complete -c ezpz -f -n '__fish_seen_subcommand_from selfrelay' -s m -l method -r -a 'PetitPotam Printerbug DFSCoerce ALL' -d 'Coercion method'
complete -c ezpz -f -n '__fish_seen_subcommand_from selfrelay' -s x -l cmd -r -d 'Custom command to execute'
complete -c ezpz -f -n '__fish_seen_subcommand_from selfrelay' -l modify -d 'Use modify action instead of add for DNS record'
