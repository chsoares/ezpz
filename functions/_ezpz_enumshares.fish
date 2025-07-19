function _ezpz_enumshares
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '                         '(set_color yellow --bold)'   __|  |  |    \    _ \  __|   __| '(set_color normal)
    echo '   -_)    \   |  |   ` \ '(set_color yellow --bold)' \__ \  __ |   _ \     /  _|  \__ \ '(set_color normal)
    echo ' \___| _| _| \_,_| _|_|_|'(set_color yellow --bold)' ____/ _| _| _/  _\ _|_\ ___| ____/ '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: ezpz enumshares -t <target> [-u <user>] [-p <password> | -H <hash>] [-d <domain>] [-k]
  Enumerates and spiders SMB shares.

  -t, --target    Target host or file with targets (Required)
  -u, --user      Username for authentication (optional, for null session if omitted)
  -p, --password  Password for authentication
  -H, --hash      NTLM hash for pass-the-hash authentication
  -d, --domain    Domain for authentication (optional)
  -k, --kerb      Use Kerberos authentication

Examples:
  ezpz enumshares -t 10.10.10.10 -u administrator -p password123
  ezpz enumshares -t hosts.txt -u CORP\\\\admin -H abc123... -d corp.local
  ezpz enumshares -t 10.10.10.10  # null session
"

    # Check required tools
    set required_tools nxc smbclient
    for tool in $required_tools
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Parse arguments
    argparse 'u/user=' 'p/password=' 'H/hash=' 't/target=' 'd/domain=' 'k/kerb' 'h/help' -- $argv
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

    # Set variables
    set target_host $_flag_target
    
    # Build nxc authentication arguments
    set nxc_auth
    if set -q _flag_user
        set user $_flag_user
        if set -q _flag_domain
            set -a nxc_auth -u "$_flag_domain\\$user"
        else
            set -a nxc_auth -u "$user"
        end
    else
        # Null session
        set -a nxc_auth -u '' -p ''
        set user ""
    end

    # Add authentication method
    if set -q _flag_password
        set -a nxc_auth -p "$_flag_password"
    else if set -q _flag_hash
        set -a nxc_auth -H "$_flag_hash"
    end

    if set -q _flag_kerb
        set -a nxc_auth -k
        
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            if set -q _flag_target
                sudo ntpdate -u $_flag_target >/dev/null 2>&1
            else
                ezpz_warn "No target specified for time sync. Kerberos may fail."
            end
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Add SMB timeout to avoid common errors
    set -a nxc_auth --smb-timeout 999

    # Create temporary files
    set hosts_tmp (mktemp)
    set shares_tmp (mktemp)
    set share_names_tmp (mktemp)
    set files_tmp (mktemp)
    trap 'rm -f "$hosts_tmp" "$shares_tmp" "$share_names_tmp" "$files_tmp"' EXIT TERM
    trap "echo ''" INT

    # Determine target hosts
    if test -f "$target_host"
        # Target is a file with hosts
        cp $target_host $hosts_tmp
    else
        # Target is a single host
        echo "$target_host" > $hosts_tmp
    end

    # Process each target
    while read -l target
        ezpz_header "Enumerating shares on $target"
        ezpz_cmd "nxc smb $target $nxc_auth --shares"
        
        timeout 60 nxc smb $target $nxc_auth --shares 2>/dev/null | grep -E "READ|WRITE" | tr -s " " | cut -d " " -f 5- > $shares_tmp
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping $target."
            continue
        end

        if not test -s $shares_tmp
            ezpz_warn "No readable/writable shares found on $target."
            continue
        end

        # Format shares as table using READ/WRITE as delimiter
        printf "%-20s %-15s %s\n" "SHARE NAME" "PERMISSIONS" "DESCRIPTION"
        printf "%-20s %-15s %s\n" "----------" "-----------" "-----------"
        cat $shares_tmp | awk '
        {
            line = $0
            if (match(line, /READ,WRITE/)) {
                share = substr(line, 1, RSTART-1)
                perm = "READ,WRITE"
                desc = substr(line, RSTART+10)
            } else if (match(line, /READ/)) {
                share = substr(line, 1, RSTART-1)
                perm = "READ"
                desc = substr(line, RSTART+5)
            } else if (match(line, /WRITE/)) {
                share = substr(line, 1, RSTART-1)
                perm = "WRITE"
                desc = substr(line, RSTART+6)
            }
            gsub(/^[ \t]+|[ \t]+$/, "", share)
            gsub(/^[ \t]+|[ \t]+$/, "", desc)
            printf "%-20s %-15s %s\n", share, perm, desc
        }'

        # Extract share names for spidering
        cat $shares_tmp | awk '
        {
            line = $0
            if (match(line, /READ,WRITE|READ|WRITE/)) {
                share = substr(line, 1, RSTART-1)
                gsub(/^[ \t]+|[ \t]+$/, "", share)
                print share
            }
        }' > $share_names_tmp

        # Process each share
        while read -l share
            test -z "$share"; and continue
            
            ezpz_question "Spider '$share' share for interesting files? [y/N]"
            read -l confirm
            if test "$confirm" = "y" -o "$confirm" = "Y"
                ezpz_header "Searching '$share' for config/script/text files"
                set regex_pattern "\.txt|\.xml|\.config|\.cnf|\.conf|\.ini|\.ps1"
                ezpz_cmd "nxc smb $target $nxc_auth --spider $share --regex '$regex_pattern'"
                
                timeout 60 nxc smb $target $nxc_auth --spider $share --regex $regex_pattern 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d " " -f 5- | cut -d '[' -f 1 | sed 's/[[:space:]]*$//' | tee $files_tmp
                
                if test $pipestatus[1] -eq 124
                    ezpz_warn "Operation timed out. Skipping spider for $share."
                    continue
                end

                if test -s $files_tmp
                    ezpz_question "Download these files? [y/N]"
                    read -l confirm_dl
                    if test "$confirm_dl" = "y" -o "$confirm_dl" = "Y"
                        set dir_path "./$target"_"$share"_loot
                        mkdir -p $dir_path
                        ezpz_header "Saving files to $dir_path"

                        # Extract user and password for smbclient
                        set smb_user $user
                        set smb_pass ""
                        set smb_domain ""
                        
                        if set -q _flag_password
                            set smb_pass $_flag_password
                        end
                        
                        if set -q _flag_domain
                            set smb_domain $_flag_domain
                        end

                        while read -l file_path_full
                            test -z "$file_path_full"; and continue
                            
                            set share_path "//$target/$share"
                            set file_path (echo "$file_path_full" | sed "s|/|\\\\|g")
                            set file_name (basename "$file_path_full")
                            
                            if test -n "$smb_domain" -a -n "$smb_pass"
                                ezpz_cmd "smbclient $share_path -U \"$smb_domain\\\\$smb_user%$smb_pass\" -c \"get \\\"$file_path\\\" \\\"$dir_path/$file_name\\\"\""
                                smbclient $share_path -U "$smb_domain\\$smb_user%$smb_pass" -c "get \"$file_path\" \"$dir_path/$file_name\"" >/dev/null 2>&1
                            else if test -n "$smb_pass"
                                ezpz_cmd "smbclient $share_path -U \"$smb_user%$smb_pass\" -c \"get \\\"$file_path\\\" \\\"$dir_path/$file_name\\\"\""
                                smbclient $share_path -U "$smb_user%$smb_pass" -c "get \"$file_path\" \"$dir_path/$file_name\"" >/dev/null 2>&1
                            else
                                ezpz_warn "No password provided for smbclient download. Skipping file downloads."
                                break
                            end
                        end < $files_tmp

                        if test -d $dir_path
                            ezpz_header "Searching for secrets in downloaded files..."
                            set secret_pattern "password|passwd|secret|key|token|cred|connstr"
                            ezpz_cmd "grep -iE -r \"$secret_pattern\" \"$dir_path\""
                            grep -iE -r --color=always $secret_pattern $dir_path 2>/dev/null
                        end
                    end
                else
                    ezpz_warn "No files found matching the pattern in share '$share'."
                end
            end
        end < $share_names_tmp
    end < $hosts_tmp

    trap - INT
    ezpz_success "Done."
end